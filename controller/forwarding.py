"""OpenFlow forwarding, counter monitoring, flood detection and timed mitigation."""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import arp, ether_types, ethernet, ipv4, packet, udp
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3

from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector
from controller.config import DEFAULT_CONFIG, load_config, validate_config  # noqa: F401 (re-exported)
from controller.lab import (  # noqa: F401 (re-exported for existing callers)
    CLIENT_IP, LAB_IP_TO_MAC, LAB_IPS, LAB_MAC_TO_IP, LAB_MAC_TO_PORT, VICTIM_IP, VICTIM_PORT,
    VICTIM_SWITCH_PORT,
)

COOKIE_BASE = 0xDD05000000000000
COOKIE_MASK = 0xFFFF000000000000
COOKIE_MISS = COOKIE_BASE | 1
COOKIE_CONTROL = COOKIE_BASE | 2
COOKIE_UDP = COOKIE_BASE | 3
COOKIE_PUNT = COOKIE_BASE | 4
COOKIE_DROP = COOKIE_BASE | 5
PRIORITY_PUNT = 5
PRIORITY_CONTROL = 20
PRIORITY_UDP = 100
PRIORITY_DROP = 200
FLOW_IDLE_TIMEOUT = 30


def forwarding_match_fields(eth_type, in_port, source_mac, destination_mac, ip_packet,
                            udp_packet=None, arp_packet=None):
    """Return (priority, cookie, match fields) for a known unicast packet."""
    common = {"in_port": in_port, "eth_src": source_mac, "eth_dst": destination_mac}
    if eth_type == ether_types.ETH_TYPE_ARP:
        if arp_packet is None:
            return None
        return PRIORITY_CONTROL, COOKIE_CONTROL, {
            **common,
            "eth_type": eth_type,
            "arp_op": arp_packet.opcode,
            "arp_spa": arp_packet.src_ip,
            "arp_sha": arp_packet.src_mac.lower(),
        }
    if eth_type == ether_types.ETH_TYPE_IP and ip_packet is not None:
        if ip_packet.proto == 17:  # UDP: count each source/destination separately.
            if udp_packet is None:
                return None
            protected_service = ip_packet.dst == VICTIM_IP and udp_packet.dst_port == VICTIM_PORT
            return (PRIORITY_UDP if protected_service else PRIORITY_CONTROL,
                    COOKIE_UDP if protected_service else COOKIE_CONTROL, {
                **common,
                "eth_type": eth_type,
                "ip_proto": 17,
                "ipv4_src": ip_packet.src,
                "ipv4_dst": ip_packet.dst,
                "udp_dst": udp_packet.dst_port,
            })
        if ip_packet.proto == 1:  # ICMP for connectivity checks.
            return PRIORITY_CONTROL, COOKIE_CONTROL, {
                **common,
                "eth_type": eth_type,
                "ip_proto": 1,
                "ipv4_src": ip_packet.src,
                "ipv4_dst": ip_packet.dst,
            }
    return None


def drop_match_fields(source):
    """Restrict mitigation to one UDP source and the lab victim's echo port."""
    if source not in LAB_IPS or source in (VICTIM_IP, "10.0.0.11"):
        raise ValueError("source is not an eligible lab attack host")
    return {"eth_type": ether_types.ETH_TYPE_IP, "ip_proto": 17,
            "ipv4_src": source, "ipv4_dst": VICTIM_IP, "udp_dst": VICTIM_PORT}


class ForwardingController(app_manager.OSKenApp):
    """Control the fixed five-host lab and log every alert/mitigation decision."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.trackers = {}
        self.detectors = {}
        self.drop_counters = {}
        self.active_blocks = {}
        self.pending_replies = {}
        self.pending_barriers = {}
        self.config = load_config(os.environ.get("FLOWGUARD_CONFIG", DEFAULT_CONFIG))
        self.mitigation_enabled = os.environ.get("FLOWGUARD_MITIGATION", "1") != "0"
        self.event_file = os.environ.get("FLOWGUARD_EVENTS")
        self.monitor_thread = hub.spawn(self._monitor)

    def _event(self, kind, **details):
        record = {"type": kind, "time_utc": datetime.now(timezone.utc).isoformat(),
                  "monotonic_s": time.monotonic(), **details}
        self.logger.info("FLOWGUARD %s", json.dumps(record, sort_keys=True))
        if self.event_file:
            with open(self.event_file, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")

    def _new_detector(self):
        protected_sources = set(self.config["protected_sources"]) | {VICTIM_IP, CLIENT_IP}
        return TwoWindowDetector(
            self.config["victim_pps"], self.config["source_pps"],
            self.config["min_sources"], self.config["consecutive_windows"],
            protected_sources,
        )

    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                ofp = datapath.ofproto
                parser = datapath.ofproto_parser
                request = parser.OFPFlowStatsRequest(
                    datapath, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
                    COOKIE_BASE, COOKIE_MASK,
                    parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=17,
                                    ipv4_dst=VICTIM_IP, udp_dst=VICTIM_PORT),
                )
                datapath.send_msg(request)
            hub.sleep(float(self.config["poll_interval_s"]))

    def _add_flow(self, datapath, priority, match, actions, cookie, idle_timeout=0, hard_timeout=0, flags=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(
            parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_ADD,
                priority=priority,
                match=match,
                instructions=instructions,
                cookie=cookie,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                flags=flags,
            )
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        self.mac_to_port[datapath.id] = {}
        self._clear_pending_state(datapath.id)
        self.datapaths[datapath.id] = datapath
        self.trackers[datapath.id] = CounterTracker()
        self.detectors[datapath.id] = self._new_detector()
        self.drop_counters[datapath.id] = {}
        self.active_blocks[datapath.id] = {}
        # A reconnect may leave old flows in OVS. Remove only this app's cookie range.
        datapath.send_msg(
            parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_DELETE,
                table_id=0,
                cookie=COOKIE_BASE,
                cookie_mask=COOKIE_MASK,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(),
            )
        )
        # The table miss drops unrelated frames in the switch. Only the fixed
        # lab hosts and protocols below can generate a packet-in event.
        self._add_flow(datapath, priority=0, match=parser.OFPMatch(), actions=[], cookie=COOKIE_MISS)
        controller_action = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        for mac, address in LAB_MAC_TO_IP.items():
            self._add_flow(
                datapath,
                priority=PRIORITY_PUNT,
                match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=LAB_MAC_TO_PORT[mac],
                                      eth_src=mac, arp_spa=address),
                actions=controller_action,
                cookie=COOKIE_PUNT,
            )
            for protocol in (1, 17):
                self._add_flow(
                    datapath,
                    priority=PRIORITY_PUNT,
                    match=parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        in_port=LAB_MAC_TO_PORT[mac],
                        eth_src=mac,
                        ipv4_src=address,
                        ip_proto=protocol,
                    ),
                    actions=controller_action,
                    cookie=COOKIE_PUNT,
                )
        self.logger.info("OpenFlow 1.3 switch connected: dpid=%s; forwarding state reset", datapath.id)
        self._event("switch_connected", dpid=datapath.id, mitigation_enabled=self.mitigation_enabled)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnected_handler(self, ev):
        self._clear_pending_state(ev.datapath.id)
        self.mac_to_port.pop(ev.datapath.id, None)
        self.datapaths.pop(ev.datapath.id, None)
        self.trackers.pop(ev.datapath.id, None)
        self.detectors.pop(ev.datapath.id, None)
        self.drop_counters.pop(ev.datapath.id, None)
        self.active_blocks.pop(ev.datapath.id, None)
        self.logger.info("Switch disconnected: dpid=%s", ev.datapath.id)

    def _clear_pending_state(self, datapath_id):
        """Discard multipart and barrier state when a switch reconnects or leaves."""
        for pending in (self.pending_replies, self.pending_barriers):
            for key in [key for key in pending if key[0] == datapath_id]:
                pending.pop(key, None)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_handler(self, ev):
        message = ev.msg
        datapath = message.datapath
        key = (datapath.id, message.xid)
        flows = self.pending_replies.setdefault(key, [])
        flows.extend(message.body)
        if message.flags & datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        self.pending_replies.pop(key, None)
        now = time.monotonic()
        counters = []
        dropped = {}
        for stat in flows:
            fields = dict(stat.match.items())
            source = fields.get("ipv4_src")
            if (not source or fields.get("ipv4_dst") != VICTIM_IP
                    or fields.get("udp_dst") != VICTIM_PORT):
                continue
            if stat.cookie == COOKIE_UDP:
                identity = f"{fields.get('in_port')}:{fields.get('eth_src')}:{fields.get('eth_dst')}"
                counters.append(FlowCounter(source, VICTIM_IP, identity, stat.packet_count, stat.byte_count))
            elif stat.cookie == COOKIE_DROP:
                dropped[source] = stat.packet_count
        tracker = self.trackers.get(datapath.id)
        detector = self.detectors.get(datapath.id)
        if tracker is None or detector is None:
            return
        rates = tracker.sample(now, counters)
        previous_drop = self.drop_counters[datapath.id]
        drop_deltas = {source: max(0, count - previous_drop.get(source, count)) for source, count in dropped.items()}
        self.drop_counters[datapath.id] = dropped
        self._event("sample", dpid=datapath.id, **rates, drop_packet_delta=drop_deltas,
                    drop_packet_total=dropped)
        if rates["elapsed_s"] is None or rates["elapsed_s"] <= 0:
            return
        alert = detector.observe(rates)
        if alert is not None:
            self._event("alert", dpid=datapath.id, victim=VICTIM_IP, **alert)
            if self.mitigation_enabled:
                self._mitigate(datapath, alert["sources"], now)
        elif detector.alert_active and self.mitigation_enabled:
            # Reconcile current offenders throughout an active episode so a
            # newly qualifying source or an expired block is handled promptly.
            self._mitigate(datapath, detector.qualifying_sources(rates), now)

    def _mitigate(self, datapath, sources, now):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        blocks = self.active_blocks[datapath.id]
        installed = []
        for source in sources:
            if (source not in LAB_IPS or source in (VICTIM_IP, CLIENT_IP)
                    or source in self.config.get("protected_sources", ())):
                continue
            if blocks.get(source, 0) > now:
                continue
            timeout = int(self.config["mitigation_hard_timeout_s"])
            match = parser.OFPMatch(**drop_match_fields(source))
            self._add_flow(datapath, PRIORITY_DROP, match, [], COOKIE_DROP,
                           hard_timeout=timeout, flags=ofp.OFPFF_SEND_FLOW_REM)
            blocks[source] = now + timeout
            installed.append(source)
            self._event("drop_requested", dpid=datapath.id, source=source, victim=VICTIM_IP,
                        port=VICTIM_PORT, hard_timeout_s=timeout)
        if installed:
            barrier = parser.OFPBarrierRequest(datapath)
            datapath.send_msg(barrier)
            self.pending_barriers[(datapath.id, barrier.xid)] = installed

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_handler(self, ev):
        sources = self.pending_barriers.pop((ev.msg.datapath.id, ev.msg.xid), None)
        if sources:
            self._event("drop_confirmed", dpid=ev.msg.datapath.id, sources=sources)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        message = ev.msg
        if message.cookie != COOKIE_DROP:
            return
        source = dict(message.match.items()).get("ipv4_src")
        self.active_blocks.get(message.datapath.id, {}).pop(source, None)
        self._event("drop_removed", dpid=message.datapath.id, source=source,
                    packets=message.packet_count, reason=message.reason)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        frame = packet.Packet(msg.data)
        eth = frame.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype not in (ether_types.ETH_TYPE_ARP, ether_types.ETH_TYPE_IP):
            return
        source_mac = eth.src.lower()
        destination_mac = eth.dst.lower()
        if source_mac not in LAB_MAC_TO_IP:
            return
        if in_port != LAB_MAC_TO_PORT[source_mac]:
            self.logger.warning("Ignoring host identity on unexpected port: %s from %s", source_mac, in_port)
            return

        ip_packet = frame.get_protocol(ipv4.ipv4)
        udp_packet = frame.get_protocol(udp.udp)
        arp_packet = frame.get_protocol(arp.arp)
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            if ip_packet is None or ip_packet.src != LAB_MAC_TO_IP[source_mac] or ip_packet.dst not in LAB_IPS:
                return
            # IPv4 destinations in this lab are unicast hosts. Reject Ethernet
            # group destinations and IP/MAC disagreement before any packet-out.
            if (int(destination_mac.split(":", 1)[0], 16) & 1
                    or destination_mac != LAB_IP_TO_MAC[ip_packet.dst]):
                return
            if ip_packet.proto == 17 and udp_packet is None:
                return
        else:
            if arp_packet is None:
                return
            if (arp_packet.hwtype != arp.ARP_HW_TYPE_ETHERNET
                    or arp_packet.proto != ether_types.ETH_TYPE_IP
                    or arp_packet.hlen != 6 or arp_packet.plen != 4
                    or arp_packet.opcode not in (arp.ARP_REQUEST, arp.ARP_REPLY)
                    or arp_packet.src_mac.lower() != source_mac
                    or arp_packet.src_ip != LAB_MAC_TO_IP[source_mac]
                    or arp_packet.dst_ip not in LAB_IPS):
                return
            if arp_packet.opcode == arp.ARP_REPLY:
                expected_target = LAB_IP_TO_MAC[arp_packet.dst_ip]
                if arp_packet.dst_mac.lower() != expected_target or destination_mac != expected_target:
                    return
            else:
                expected_target = LAB_IP_TO_MAC[arp_packet.dst_ip]
                if (arp_packet.dst_mac.lower() not in ("00:00:00:00:00:00", expected_target)
                        or destination_mac not in ("ff:ff:ff:ff:ff:ff", expected_target)):
                    return

        ports = self.mac_to_port.setdefault(datapath.id, {})
        old_port = ports.get(source_mac)
        if old_port is not None and old_port != in_port:
            self.logger.warning("Ignoring unexpected MAC move: %s from %s to %s", source_mac, old_port, in_port)
            return
        ports[source_mac] = in_port
        if destination_mac in LAB_MAC_TO_PORT:
            out_port = LAB_MAC_TO_PORT[destination_mac]
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            out_port = ofp.OFPP_FLOOD
        else:
            return
        if out_port == in_port:
            return
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            flow = forwarding_match_fields(eth.ethertype, in_port, source_mac, destination_mac,
                                           ip_packet, udp_packet, arp_packet)
            if flow is not None:
                priority, cookie, fields = flow
                self._add_flow(
                    datapath,
                    priority=priority,
                    match=parser.OFPMatch(**fields),
                    actions=actions,
                    cookie=cookie,
                    idle_timeout=FLOW_IDLE_TIMEOUT,
                )
                if cookie == COOKIE_UDP:
                    self.logger.info("UDP forward flow: %s -> %s out_port=%s", ip_packet.src, ip_packet.dst, out_port)

        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
            )
        )
