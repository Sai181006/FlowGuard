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

from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector  # noqa: F401
from controller.detectors import build_detector
from controller.config import (  # noqa: F401 (re-exported)
    DEFAULT_CONFIG, OPTIONAL_KEYS, effective_config, load_config, validate_config,
)
from controller.lab import (  # noqa: F401 (re-exported for existing callers)
    CLIENT_IP, LAB_IP_TO_MAC, LAB_IPS, LAB_MAC_TO_IP, LAB_MAC_TO_PORT, VICTIM_IP, VICTIM_PORT,
    VICTIM_SWITCH_PORT,
)
from controller.meters import (  # noqa: F401 (re-exported)
    METER_ID_BASE, meter_delete_all, meter_features_request, meter_id_for, meter_mod_add,
    meter_stats_request, parse_meter_features, ratelimit_instructions, ratelimit_match_fields,
    source_for_meter_id,
)
from controller.mitigation import OffenderHistory, choose_action

COOKIE_BASE = 0xDD05000000000000
COOKIE_MASK = 0xFFFF000000000000
COOKIE_MISS = COOKIE_BASE | 1
COOKIE_CONTROL = COOKIE_BASE | 2
COOKIE_UDP = COOKIE_BASE | 3
COOKIE_PUNT = COOKIE_BASE | 4
COOKIE_DROP = COOKIE_BASE | 5
COOKIE_RATELIMIT = COOKIE_BASE | 6
PRIORITY_PUNT = 5
PRIORITY_CONTROL = 20
PRIORITY_UDP = 100
PRIORITY_MITIGATION = 200  # drop and rate-limit rules share one priority
PRIORITY_DROP = PRIORITY_MITIGATION
FLOW_IDLE_TIMEOUT = 30
# Caveat: a back-off timeout longer than FLOW_IDLE_TIMEOUT lets the source's
# priority-100 forwarding flow idle out underneath the mitigation rule. When the
# rule expires, the next packet is punted and the forwarding flow reinstalled,
# so the counter tracker has no previous value for it and loses one window.


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
        self.offenders = {}
        self.meter_support = {}
        self.installed_meters = {}
        self.pending_ratelimit_xids = {}
        self.ratelimit_counters = {}
        self.meter_counters = {}
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

    def _effective_config(self):
        """The configuration with every optional section filled in.

        A legacy seven-key dictionary (older callers and tests) is completed
        with the defaults, which reproduce the original drop-only behaviour.
        """
        if all(key in self.config for key in OPTIONAL_KEYS):
            return self.config
        return effective_config(self.config)

    def _new_detector(self):
        protected_sources = set(self.config["protected_sources"]) | {VICTIM_IP, CLIENT_IP}
        return build_detector(self._effective_config(), protected_sources)

    def _offender_history(self, datapath_id):
        history = self.offenders.get(datapath_id)
        if history is None:
            history = self.offenders[datapath_id] = OffenderHistory.from_config(self._effective_config())
        return history

    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                ofp = datapath.ofproto
                parser = datapath.ofproto_parser
                # The request match is less specific than the forwarding, drop
                # and rate-limit flows, so all three are returned.
                request = parser.OFPFlowStatsRequest(
                    datapath, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
                    COOKIE_BASE, COOKIE_MASK,
                    parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=17,
                                    ipv4_dst=VICTIM_IP, udp_dst=VICTIM_PORT),
                )
                datapath.send_msg(request)
                if self.installed_meters.get(datapath.id):
                    datapath.send_msg(meter_stats_request(datapath))
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
        self.offenders[datapath.id] = OffenderHistory.from_config(self._effective_config())
        self.meter_support[datapath.id] = "unknown"
        self.installed_meters[datapath.id] = set()
        self.pending_ratelimit_xids[datapath.id] = {}
        self.ratelimit_counters[datapath.id] = {}
        self.meter_counters[datapath.id] = {}
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
        # Meters have no cookie; the lab switch carries only FlowGuard meters.
        # The features reply decides whether rate limiting is attempted at all.
        datapath.send_msg(meter_delete_all(datapath))
        datapath.send_msg(meter_features_request(datapath))
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
        for state in (self.offenders, self.meter_support, self.installed_meters,
                      self.ratelimit_counters, self.meter_counters):
            state.pop(ev.datapath.id, None)
        self.logger.info("Switch disconnected: dpid=%s", ev.datapath.id)

    def _clear_pending_state(self, datapath_id):
        """Discard multipart and barrier state when a switch reconnects or leaves."""
        for pending in (self.pending_replies, self.pending_barriers):
            for key in [key for key in pending if key[0] == datapath_id]:
                pending.pop(key, None)
        self.pending_ratelimit_xids.pop(datapath_id, None)

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
        limited = {}
        for stat in flows:
            fields = dict(stat.match.items())
            source = fields.get("ipv4_src")
            if (not source or fields.get("ipv4_dst") != VICTIM_IP
                    or fields.get("udp_dst") != VICTIM_PORT):
                continue
            # Only the forwarding flows feed the detector. While a drop or
            # rate-limit rule (priority 200) is installed it takes the
            # source's packets, so the source reads as 0 pps to the detector.
            if stat.cookie == COOKIE_UDP:
                identity = f"{fields.get('in_port')}:{fields.get('eth_src')}:{fields.get('eth_dst')}"
                counters.append(FlowCounter(source, VICTIM_IP, identity, stat.packet_count, stat.byte_count))
            elif stat.cookie == COOKIE_DROP:
                dropped[source] = stat.packet_count
            elif stat.cookie == COOKIE_RATELIMIT:
                limited[source] = limited.get(source, 0) + stat.packet_count
        tracker = self.trackers.get(datapath.id)
        detector = self.detectors.get(datapath.id)
        if tracker is None or detector is None:
            return
        rates = tracker.sample(now, counters)
        previous_drop = self.drop_counters[datapath.id]
        drop_deltas = {source: max(0, count - previous_drop.get(source, count)) for source, count in dropped.items()}
        self.drop_counters[datapath.id] = dropped
        previous_limited = self.ratelimit_counters.get(datapath.id, {})
        limited_deltas = {source: max(0, count - previous_limited.get(source, count))
                          for source, count in limited.items()}
        self.ratelimit_counters[datapath.id] = limited
        has_rates = rates["elapsed_s"] is not None and rates["elapsed_s"] > 0
        # Observe first so detector_state describes this window; the sample
        # event is still logged before any alert it causes.
        alert = detector.observe(rates) if has_rates else None
        self._event("sample", dpid=datapath.id, **rates, drop_packet_delta=drop_deltas,
                    drop_packet_total=dropped, detector_state=detector.state(),
                    ratelimit_packet_delta=limited_deltas, ratelimit_packet_total=limited)
        if not has_rates:
            return
        if alert is not None:
            details = {**alert, "detector": detector.name, "scores": alert.get("scores", {})}
            self._event("alert", dpid=datapath.id, victim=VICTIM_IP, **details)
            if self.mitigation_enabled:
                self._mitigate(datapath, alert["sources"], now)
        elif detector.alert_active and self.mitigation_enabled:
            # Reconcile current offenders throughout an active episode so a
            # newly qualifying source or an expired block is handled promptly.
            self._mitigate(datapath, detector.qualifying_sources(rates), now)

    def _mitigate(self, datapath, sources, now):
        """Install one timed rule per new offender and confirm the batch with a barrier.

        The action and timeout come from the offense history: plain drop,
        an OpenFlow meter (rate limit), or rate limit first and drop for a
        repeat offender (graduated), with optional exponential back-off.
        """
        policy = self._effective_config()["mitigation"]
        blocks = self.active_blocks[datapath.id]
        offenders = self._offender_history(datapath.id)
        support = self.meter_support.get(datapath.id, "unknown")
        batch = {"drop": [], "rate_limit": [], "failed": {}, "timeouts": {}, "offenses": {}, "xids": []}
        unsupported = []
        for source in sources:
            if (source not in LAB_IPS or source in (VICTIM_IP, CLIENT_IP)
                    or source in self.config.get("protected_sources", ())):
                continue
            if blocks.get(source, 0) > now:
                continue
            offense, timeout = offenders.next_offense(source, now)
            action = choose_action(policy["action"], offense, policy["graduated_drop_after"])
            if action == "rate_limit" and support != "unsupported":
                batch["xids"].extend(self._install_rate_limit(datapath, source, timeout, offense, policy))
                batch["rate_limit"].append(source)
            else:
                if action == "rate_limit":
                    unsupported.append(source)
                self._install_drop(datapath, source, timeout, offense)
                batch["drop"].append(source)
            blocks[source] = now + timeout
            batch["timeouts"][source] = timeout
            batch["offenses"][source] = offense
        if unsupported:
            self._event("ratelimit_failed", dpid=datapath.id, sources=unsupported, error_type=None,
                        error_code=None, fallback="drop", reason="meter_unsupported")
        if batch["drop"] or batch["rate_limit"]:
            self._send_barrier(datapath, batch)

    def _send_barrier(self, datapath, batch):
        barrier = datapath.ofproto_parser.OFPBarrierRequest(datapath)
        datapath.send_msg(barrier)
        self.pending_barriers[(datapath.id, barrier.xid)] = batch

    def _install_drop(self, datapath, source, timeout, offense):
        match = datapath.ofproto_parser.OFPMatch(**drop_match_fields(source))
        self._add_flow(datapath, PRIORITY_MITIGATION, match, [], COOKIE_DROP,
                       hard_timeout=timeout, flags=datapath.ofproto.OFPFF_SEND_FLOW_REM)
        self._event("drop_requested", dpid=datapath.id, source=source, victim=VICTIM_IP,
                    port=VICTIM_PORT, hard_timeout_s=timeout, offense_count=offense, action="drop")

    def _install_rate_limit(self, datapath, source, timeout, offense, policy):
        """Send the source's meter and its metered forwarding flow; return their xids."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        meter_id = meter_id_for(source)
        rate = int(policy["rate_limit_pps"])
        burst = int(policy["rate_limit_burst_packets"])
        installed = self.installed_meters.setdefault(datapath.id, set())
        # MODIFY an existing meter so a changed rate applies to the new rule.
        meter_mod = meter_mod_add(datapath, meter_id, rate, burst, modify=meter_id in installed)
        datapath.send_msg(meter_mod)
        if meter_id not in installed:
            self.meter_counters.setdefault(datapath.id, {}).pop(meter_id, None)
            installed.add(meter_id)
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofp.OFPFC_ADD,
            priority=PRIORITY_MITIGATION,
            match=parser.OFPMatch(**ratelimit_match_fields(source)),
            instructions=ratelimit_instructions(datapath, meter_id),
            cookie=COOKIE_RATELIMIT,
            hard_timeout=timeout,
            flags=ofp.OFPFF_SEND_FLOW_REM,
        )
        datapath.send_msg(flow_mod)
        # OS-Ken assigns the xid in send_msg; a switch error names that xid.
        xids = [message.xid for message in (meter_mod, flow_mod) if message.xid is not None]
        pending = self.pending_ratelimit_xids.setdefault(datapath.id, {})
        for xid in xids:
            pending[xid] = source
        self._event("ratelimit_requested", dpid=datapath.id, source=source, victim=VICTIM_IP,
                    port=VICTIM_PORT, meter_id=meter_id, rate_pps=rate, burst_packets=burst,
                    hard_timeout_s=timeout, offense_count=offense)
        return xids

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_handler(self, ev):
        """Record switch errors and mark failed rate-limit requests for fallback.

        A switch processes messages in order and reports an error before it
        answers a later barrier, so the barrier reply can act on the failure.
        """
        message = ev.msg
        datapath = message.datapath
        ofp = datapath.ofproto
        # "type" is the event kind in the log record, hence error_type/error_code.
        self._event("openflow_error", dpid=datapath.id, error_type=message.type,
                    error_code=message.code, xid=message.xid)
        pending = self.pending_ratelimit_xids.get(datapath.id, {})
        source = pending.get(message.xid) if message.xid is not None else None
        if source is None and message.type != ofp.OFPET_METER_MOD_FAILED:
            return
        if datapath.id in self.meter_support:
            self.meter_support[datapath.id] = "unsupported"
        # A meter error that cannot be tied to one request fails every
        # rate limit still waiting for its barrier on this switch.
        for (datapath_id, _), batch in self.pending_barriers.items():
            if datapath_id != datapath.id or not isinstance(batch, dict):
                continue
            for limited in batch.get("rate_limit", ()):
                if source is None or limited == source:
                    batch.setdefault("failed", {}).setdefault(limited, (message.type, message.code))

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_handler(self, ev):
        datapath = ev.msg.datapath
        batch = self.pending_barriers.pop((datapath.id, ev.msg.xid), None)
        if not batch:
            return
        if isinstance(batch, list):  # drop-only form
            batch = {"drop": batch, "rate_limit": []}
        if batch.get("drop"):
            self._event("drop_confirmed", dpid=datapath.id, sources=batch["drop"])
        pending = self.pending_ratelimit_xids.get(datapath.id, {})
        for xid in batch.get("xids", ()):
            pending.pop(xid, None)
        failed = batch.get("failed", {})
        confirmed = [source for source in batch.get("rate_limit", ()) if source not in failed]
        if confirmed:
            self._event("ratelimit_confirmed", dpid=datapath.id, sources=confirmed)
        if failed:
            self._fallback_to_drop(datapath, batch, failed)

    def _fallback_to_drop(self, datapath, batch, failed):
        """Replace rejected rate limits with drop rules of the same timeout."""
        errors = {}
        for source in batch["rate_limit"]:
            if source in failed:
                errors.setdefault(failed[source], []).append(source)
        for (error_type, error_code), sources in errors.items():
            self._event("ratelimit_failed", dpid=datapath.id, sources=sources, error_type=error_type,
                        error_code=error_code, fallback="drop", reason="openflow_error")
        installed = self.installed_meters.get(datapath.id, set())
        fallback = {"drop": [], "rate_limit": []}
        for source in batch["rate_limit"]:
            if source not in failed:
                continue
            installed.discard(meter_id_for(source))
            self._install_drop(datapath, source, batch["timeouts"][source], batch["offenses"][source])
            fallback["drop"].append(source)
        self._send_barrier(datapath, fallback)

    @set_ev_cls(ofp_event.EventOFPMeterFeaturesStatsReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def meter_features_handler(self, ev):
        datapath = ev.msg.datapath
        if datapath.id not in self.meter_support:
            return
        features = parse_meter_features(ev.msg.body, datapath.ofproto)
        if not features["supported"]:
            self.meter_support[datapath.id] = "unsupported"
        elif self.meter_support[datapath.id] == "unknown":
            # An earlier meter error keeps the switch marked unsupported.
            self.meter_support[datapath.id] = "supported"
        self._event("meter_features", dpid=datapath.id, **features)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_handler(self, ev):
        datapath = ev.msg.datapath
        previous = self.meter_counters.get(datapath.id)
        if previous is None:
            return
        for stat in ev.msg.body:
            source = source_for_meter_id(stat.meter_id)
            if source is None:
                continue
            band_total = stat.band_stats[0].packet_band_count if stat.band_stats else 0
            old_in, old_band = previous.get(stat.meter_id, (0, 0))
            # A smaller counter means the meter was re-created; count from zero.
            in_delta = stat.packet_in_count - old_in if stat.packet_in_count >= old_in else stat.packet_in_count
            band_delta = band_total - old_band if band_total >= old_band else band_total
            previous[stat.meter_id] = (stat.packet_in_count, band_total)
            if in_delta or band_delta or stat.flow_count:  # idle meters stay quiet
                self._event("meter_sample", dpid=datapath.id, meter_id=stat.meter_id, source=source,
                            packet_in_delta=in_delta, band_drop_delta=band_delta,
                            band_drop_total=band_total, flow_count=stat.flow_count)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        message = ev.msg
        if message.cookie not in (COOKIE_DROP, COOKIE_RATELIMIT):
            return
        source = dict(message.match.items()).get("ipv4_src")
        self.active_blocks.get(message.datapath.id, {}).pop(source, None)
        kind = "drop_removed" if message.cookie == COOKIE_DROP else "ratelimit_removed"
        self._event(kind, dpid=message.datapath.id, source=source,
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
