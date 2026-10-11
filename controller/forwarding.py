"""Learning-switch forwarding with attributable IPv4/UDP flow counters."""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import arp, ether_types, ethernet, ipv4, packet
from os_ken.ofproto import ofproto_v1_3


LAB_MAC_TO_IP = {
    "02:00:00:00:00:10": "10.0.0.10",
    "02:00:00:00:00:11": "10.0.0.11",
    "02:00:00:00:00:21": "10.0.0.21",
    "02:00:00:00:00:22": "10.0.0.22",
    "02:00:00:00:00:23": "10.0.0.23",
}
LAB_IPS = frozenset(LAB_MAC_TO_IP.values())
COOKIE_BASE = 0xDD05000000000000
COOKIE_MASK = 0xFFFF000000000000
COOKIE_MISS = COOKIE_BASE | 1
COOKIE_CONTROL = COOKIE_BASE | 2
COOKIE_UDP = COOKIE_BASE | 3
COOKIE_PUNT = COOKIE_BASE | 4
PRIORITY_PUNT = 5
PRIORITY_CONTROL = 20
PRIORITY_UDP = 100
FLOW_IDLE_TIMEOUT = 30


def forwarding_match_fields(eth_type, in_port, source_mac, destination_mac, ip_packet):
    """Return (priority, cookie, match fields) for a known unicast packet."""
    common = {"in_port": in_port, "eth_src": source_mac, "eth_dst": destination_mac}
    if eth_type == ether_types.ETH_TYPE_ARP:
        return PRIORITY_CONTROL, COOKIE_CONTROL, {**common, "eth_type": eth_type}
    if eth_type == ether_types.ETH_TYPE_IP and ip_packet is not None:
        if ip_packet.proto == 17:  # UDP: count each source/destination separately.
            return PRIORITY_UDP, COOKIE_UDP, {
                **common,
                "eth_type": eth_type,
                "ip_proto": 17,
                "ipv4_src": ip_packet.src,
                "ipv4_dst": ip_packet.dst,
            }
        if ip_packet.proto == 1:  # ICMP for connectivity checks.
            return PRIORITY_CONTROL, COOKIE_CONTROL, {
                **common,
                "eth_type": eth_type,
                "ip_proto": 1,
                "ipv4_src": ip_packet.src,
                "ipv4_dst": ip_packet.dst,
            }
    return None


class ForwardingController(app_manager.OSKenApp):
    """Control the one-switch lab; telemetry and mitigation arrive in M4/M5."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}

    def _add_flow(self, datapath, priority, match, actions, cookie, idle_timeout=0):
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
            )
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        self.mac_to_port[datapath.id] = {}
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
                match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, eth_src=mac, arp_spa=address),
                actions=controller_action,
                cookie=COOKIE_PUNT,
            )
            for protocol in (1, 17):
                self._add_flow(
                    datapath,
                    priority=PRIORITY_PUNT,
                    match=parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        eth_src=mac,
                        ipv4_src=address,
                        ip_proto=protocol,
                    ),
                    actions=controller_action,
                    cookie=COOKIE_PUNT,
                )
        self.logger.info("OpenFlow 1.3 switch connected: dpid=%s; forwarding state reset", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnected_handler(self, ev):
        self.mac_to_port.pop(ev.datapath.id, None)
        self.logger.info("Switch disconnected: dpid=%s", ev.datapath.id)

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

        ip_packet = frame.get_protocol(ipv4.ipv4)
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            if ip_packet is None or ip_packet.src != LAB_MAC_TO_IP[source_mac] or ip_packet.dst not in LAB_IPS:
                return
        elif frame.get_protocol(arp.arp) is None:
            return

        ports = self.mac_to_port.setdefault(datapath.id, {})
        old_port = ports.get(source_mac)
        if old_port is not None and old_port != in_port:
            self.logger.warning("Ignoring unexpected MAC move: %s from %s to %s", source_mac, old_port, in_port)
            return
        ports[source_mac] = in_port
        out_port = ports.get(destination_mac, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            flow = forwarding_match_fields(eth.ethertype, in_port, source_mac, destination_mac, ip_packet)
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
