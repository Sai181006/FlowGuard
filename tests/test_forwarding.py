"""Focused tests for match boundaries that protect later flow statistics."""

import json
import logging
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

from os_ken.lib.packet import arp, ether_types, ethernet, ipv4, packet, udp
from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

from controller.detection import CounterTracker, TwoWindowDetector
from controller.mitigation import OffenderHistory
from controller.forwarding import (
    CLIENT_IP, COOKIE_CONTROL, COOKIE_DROP, COOKIE_PUNT, COOKIE_RATELIMIT, COOKIE_UDP,
    DEFAULT_CONFIG, LAB_MAC_TO_IP, LAB_MAC_TO_PORT, LAB_IP_TO_MAC,
    PRIORITY_CONTROL, PRIORITY_DROP, PRIORITY_MITIGATION, PRIORITY_UDP,
    ForwardingController, drop_match_fields, forwarding_match_fields,
    load_config, validate_config,
)
from topology.lab_topology import DDoSTopo, HOSTS, HOST_PORTS


def make_frame(eth_src, eth_dst, eth_type, network, transport=None, payload=b"test"):
    frame = packet.Packet()
    frame.add_protocol(ethernet.ethernet(dst=eth_dst, src=eth_src, ethertype=eth_type))
    frame.add_protocol(network)
    if transport is not None:
        frame.add_protocol(transport)
    frame.add_protocol(payload)
    frame.serialize()
    return frame.data


def make_app():
    app = object.__new__(ForwardingController)
    app.mac_to_port = {1: {}}
    app.datapaths = {}
    app.trackers = {1: CounterTracker()}
    app.detectors = {1: TwoWindowDetector(100, 30, protected_sources=(CLIENT_IP,))}
    app.drop_counters = {1: {}}
    app.active_blocks = {1: {}}
    app.pending_replies = {}
    app.pending_barriers = {}
    app.config = load_config(DEFAULT_CONFIG)
    app.offenders = {1: OffenderHistory.from_config(app.config)}
    app.meter_support = {1: "unknown"}
    app.installed_meters = {1: set()}
    app.pending_ratelimit_xids = {1: {}}
    app.ratelimit_counters = {1: {}}
    app.meter_counters = {1: {}}
    app.mitigation_enabled = True
    app.logger = logging.getLogger("test-forwarding")
    app.events = []
    app._event = lambda kind, **details: app.events.append({"type": kind, **details})
    app._messages = []
    app.datapath = SimpleNamespace(id=1, ofproto=ofp, ofproto_parser=parser,
                                   send_msg=app._messages.append)
    return app


def deliver(app, frame_data, in_port):
    app.packet_in_handler(SimpleNamespace(msg=SimpleNamespace(
        datapath=app.datapath, match={"in_port": in_port}, data=frame_data,
        buffer_id=ofp.OFP_NO_BUFFER,
    )))


class SerializingDatapath:
    """Like OS-Ken's Datapath.send_msg: assign an xid, then encode the message."""

    def __init__(self, messages, dpid=1):
        self.id = dpid
        self.ofproto = ofp
        self.ofproto_parser = parser
        self.messages = messages
        self.xid = 0

    def send_msg(self, msg):
        assert isinstance(msg, parser.MsgBase)
        if msg.xid is None:
            self.xid += 1
            msg.set_xid(self.xid)
        msg.serialize()
        self.messages.append(msg)


def make_serializing_app(action="drop", backoff=False, **mitigation):
    app = make_app()
    app.config["mitigation"].update(mitigation, action=action)
    app.config["mitigation"]["backoff"]["enabled"] = backoff
    app.offenders = {1: OffenderHistory.from_config(app.config)}
    app.datapath = SerializingDatapath(app._messages)
    return app


def flow_stat(source, port, packets, udp_port=9000, cookie=COOKIE_UDP):
    return SimpleNamespace(
        match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=17,
                              ipv4_src=source, ipv4_dst="10.0.0.10",
                              udp_dst=udp_port, in_port=port,
                              eth_src=LAB_IP_TO_MAC[source],
                              eth_dst=LAB_IP_TO_MAC["10.0.0.10"]),
        cookie=cookie, packet_count=packets, byte_count=packets * 128,
    )


def poll(app, now, stats):
    with mock.patch("controller.forwarding.time.monotonic", return_value=now):
        app.flow_stats_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=app.datapath, xid=int(now * 100), flags=0, body=stats,
        )))


ATTACKERS = (("10.0.0.21", 3), ("10.0.0.22", 4))


def flood(app, times=(1, 2, 3), start=0):
    """200 pps from both attackers; the third poll raises the alert."""
    for index, now in enumerate(times):
        poll(app, now, [flow_stat(source, port, start + 200 * index) for source, port in ATTACKERS])


def flow_mods(app, cookie):
    return [msg for msg in app._messages if isinstance(msg, parser.OFPFlowMod) and msg.cookie == cookie]


def meter_mods(app):
    return [msg for msg in app._messages if isinstance(msg, parser.OFPMeterMod)]


def events(app, kind):
    return [event for event in app.events if event["type"] == kind]


def reply_to_barrier(app, barrier=None):
    if barrier is None:
        barrier = [msg for msg in app._messages if isinstance(msg, parser.OFPBarrierRequest)][-1]
    app.barrier_handler(SimpleNamespace(msg=SimpleNamespace(datapath=app.datapath, xid=barrier.xid)))


def switch_error(app, error_type, code, xid):
    app.error_handler(SimpleNamespace(msg=SimpleNamespace(
        datapath=app.datapath, type=error_type, code=code, xid=xid)))


class ForwardingMatchTests(unittest.TestCase):
    def test_allowed_hosts_match_topology(self):
        self.assertEqual(LAB_MAC_TO_IP, {mac: address.split("/")[0] for address, mac in HOSTS.values()})
        self.assertEqual(LAB_MAC_TO_PORT, {
            mac: HOST_PORTS[name] for name, (address, mac) in HOSTS.items()
        })
        topology = DDoSTopo()
        self.assertEqual(LAB_MAC_TO_PORT, {
            mac: topology.port("s1", name)[0] for name, (_, mac) in HOSTS.items()
        })

    def test_udp_match_is_attributable(self):
        ip_packet = SimpleNamespace(proto=17, src="10.0.0.11", dst="10.0.0.10")
        priority, cookie, match = forwarding_match_fields(
            ether_types.ETH_TYPE_IP, 2, "02:00:00:00:00:11", "02:00:00:00:00:10",
            ip_packet, SimpleNamespace(src_port=40000, dst_port=9000),
        )
        self.assertEqual((priority, cookie), (PRIORITY_UDP, COOKIE_UDP))
        self.assertEqual(match["ipv4_src"], "10.0.0.11")
        self.assertEqual(match["ipv4_dst"], "10.0.0.10")
        self.assertEqual(match["ip_proto"], 17)
        self.assertEqual(match["in_port"], 2)
        self.assertEqual(match["udp_dst"], 9000)

    def test_only_the_protected_udp_service_is_counted(self):
        ip_packet = SimpleNamespace(proto=17, src="10.0.0.21", dst="10.0.0.10")
        udp_packet = SimpleNamespace(src_port=40000, dst_port=9001)
        priority, cookie, match = forwarding_match_fields(
            ether_types.ETH_TYPE_IP, 3, "02:00:00:00:00:21", "02:00:00:00:00:10",
            ip_packet, udp_packet,
        )
        self.assertEqual((priority, cookie), (PRIORITY_CONTROL, COOKIE_CONTROL))
        self.assertEqual(match["udp_dst"], 9001)

    def test_arp_match_cannot_capture_udp(self):
        arp_packet = SimpleNamespace(opcode=arp.ARP_REPLY, src_ip="10.0.0.11",
                                     src_mac="02:00:00:00:00:11")
        priority, cookie, match = forwarding_match_fields(
            ether_types.ETH_TYPE_ARP, 2, "02:00:00:00:00:11", "02:00:00:00:00:10",
            None, arp_packet=arp_packet,
        )
        self.assertEqual((priority, cookie), (PRIORITY_CONTROL, COOKIE_CONTROL))
        self.assertEqual(match["eth_type"], ether_types.ETH_TYPE_ARP)
        self.assertNotIn("ipv4_src", match)
        self.assertEqual(match["arp_spa"], "10.0.0.11")
        self.assertEqual(match["arp_sha"], "02:00:00:00:00:11")
        self.assertEqual(match["arp_op"], arp.ARP_REPLY)

    def test_other_ip_does_not_get_broad_forwarding_flow(self):
        tcp_packet = SimpleNamespace(proto=6, src="10.0.0.11", dst="10.0.0.10")
        self.assertIsNone(
            forwarding_match_fields(
                ether_types.ETH_TYPE_IP, 2, "02:00:00:00:00:11", "02:00:00:00:00:10", tcp_packet
            )
        )


class PacketInSecurityTests(unittest.TestCase):
    def test_installed_punt_rules_bind_each_identity_to_its_fixed_port(self):
        app = make_app()
        app.switch_features_handler(SimpleNamespace(msg=SimpleNamespace(datapath=app.datapath)))
        punts = [msg for msg in app._messages
                 if isinstance(msg, parser.OFPFlowMod) and msg.cookie == COOKIE_PUNT]
        self.assertEqual(len(punts), len(LAB_MAC_TO_IP) * 3)
        for flow in punts:
            fields = dict(flow.match.items())
            source_mac = fields["eth_src"]
            self.assertEqual(fields["in_port"], LAB_MAC_TO_PORT[source_mac])

    def test_attacker_cannot_claim_client_identity_before_client_arrives(self):
        app = make_app()
        client_mac = LAB_IP_TO_MAC[CLIENT_IP]
        frame_data = make_frame(
            client_mac, LAB_IP_TO_MAC["10.0.0.10"], ether_types.ETH_TYPE_IP,
            ipv4.ipv4(src=CLIENT_IP, dst="10.0.0.10", proto=17),
            udp.udp(src_port=40000, dst_port=9000),
        )
        deliver(app, frame_data, 3)
        self.assertNotIn(client_mac, app.mac_to_port[1])
        self.assertFalse(any(isinstance(msg, parser.OFPPacketOut) for msg in app._messages))

        deliver(app, frame_data, LAB_MAC_TO_PORT[client_mac])
        packetouts = [msg for msg in app._messages if isinstance(msg, parser.OFPPacketOut)]
        udp_flows = [msg for msg in app._messages
                     if isinstance(msg, parser.OFPFlowMod) and msg.cookie == COOKIE_UDP]
        self.assertEqual(len(packetouts), 1)
        self.assertEqual(packetouts[0].actions[0].port, 1)
        self.assertEqual(len(udp_flows), 1)

    def test_valid_arp_forwarding_rule_retains_sender_identity(self):
        app = make_app()
        source_mac = "02:00:00:00:00:21"
        source_ip = "10.0.0.21"
        victim_mac = LAB_IP_TO_MAC["10.0.0.10"]
        valid = make_frame(
            source_mac, victim_mac, ether_types.ETH_TYPE_ARP,
            arp.arp(hwtype=arp.ARP_HW_TYPE_ETHERNET, proto=ether_types.ETH_TYPE_IP,
                    hlen=6, plen=4, opcode=arp.ARP_REPLY, src_mac=source_mac,
                    src_ip=source_ip, dst_mac=victim_mac, dst_ip="10.0.0.10"),
        )
        deliver(app, valid, 3)
        learned = [msg for msg in app._messages
                   if isinstance(msg, parser.OFPFlowMod) and msg.cookie == COOKIE_CONTROL]
        self.assertEqual(len(learned), 1)
        self.assertEqual(learned[0].match["in_port"], 3)
        self.assertEqual(learned[0].match["arp_spa"], source_ip)
        self.assertEqual(learned[0].match["arp_sha"], source_mac)

    def test_valid_arp_request_still_floods_in_the_lab(self):
        app = make_app()
        source_mac = "02:00:00:00:00:21"
        frame_data = make_frame(
            source_mac, "ff:ff:ff:ff:ff:ff", ether_types.ETH_TYPE_ARP,
            arp.arp(hwtype=arp.ARP_HW_TYPE_ETHERNET, proto=ether_types.ETH_TYPE_IP,
                    hlen=6, plen=4, opcode=arp.ARP_REQUEST, src_mac=source_mac,
                    src_ip="10.0.0.21", dst_mac="00:00:00:00:00:00", dst_ip="10.0.0.10"),
        )
        deliver(app, frame_data, 3)
        packetouts = [msg for msg in app._messages if isinstance(msg, parser.OFPPacketOut)]
        self.assertEqual(len(packetouts), 1)
        self.assertEqual(packetouts[0].actions[0].port, ofp.OFPP_FLOOD)

    def test_forged_arp_sender_ip_or_hardware_is_rejected(self):
        source_mac = "02:00:00:00:00:21"
        victim_mac = LAB_IP_TO_MAC["10.0.0.10"]
        for source_ip, arp_source_mac in (("10.0.0.22", source_mac),
                                          ("10.0.0.21", "02:00:00:00:00:22")):
            with self.subTest(source_ip=source_ip, arp_source_mac=arp_source_mac):
                app = make_app()
                frame_data = make_frame(
                    source_mac, victim_mac, ether_types.ETH_TYPE_ARP,
                    arp.arp(hwtype=arp.ARP_HW_TYPE_ETHERNET, proto=ether_types.ETH_TYPE_IP,
                            hlen=6, plen=4, opcode=arp.ARP_REPLY, src_mac=arp_source_mac,
                            src_ip=source_ip, dst_mac=victim_mac, dst_ip="10.0.0.10"),
                )
                deliver(app, frame_data, 3)
                self.assertFalse(any(isinstance(msg, parser.OFPPacketOut) for msg in app._messages))
                self.assertFalse(any(isinstance(msg, parser.OFPFlowMod) for msg in app._messages))

    def test_broadcast_and_multicast_l2_destinations_cannot_bypass_udp_counting(self):
        for destination_mac in ("ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"):
            with self.subTest(destination_mac=destination_mac):
                app = make_app()
                frame_data = make_frame(
                    "02:00:00:00:00:21", destination_mac, ether_types.ETH_TYPE_IP,
                    ipv4.ipv4(src="10.0.0.21", dst="10.0.0.10", proto=17),
                    udp.udp(src_port=40000, dst_port=9000),
                )
                deliver(app, frame_data, 3)
                self.assertFalse(any(isinstance(msg, parser.OFPPacketOut) for msg in app._messages))
                self.assertFalse(any(isinstance(msg, parser.OFPFlowMod) for msg in app._messages))

    def test_unicast_udp_to_protected_service_is_counted_and_other_ports_are_not(self):
        app = make_app()
        for destination_port, expected_cookie in ((9000, COOKIE_UDP), (9001, COOKIE_CONTROL)):
            frame_data = make_frame(
                "02:00:00:00:00:21", LAB_IP_TO_MAC["10.0.0.10"], ether_types.ETH_TYPE_IP,
                ipv4.ipv4(src="10.0.0.21", dst="10.0.0.10", proto=17),
                udp.udp(src_port=40000, dst_port=destination_port),
            )
            deliver(app, frame_data, 3)
            flows = [msg for msg in app._messages if isinstance(msg, parser.OFPFlowMod)
                     and msg.match.get("udp_dst") == destination_port]
            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0].cookie, expected_cookie)


class DetectorConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(Path(DEFAULT_CONFIG).read_text(encoding="utf-8"))

    def test_shipped_config_is_valid(self):
        self.assertEqual(validate_config(self.config), self.config)

    def test_client_and_victim_are_always_excluded_from_mitigation_sources(self):
        app = make_app()
        app.config["protected_sources"] = []
        detector = app._new_detector()
        self.assertIn(CLIENT_IP, detector.protected_sources)
        self.assertIn("10.0.0.10", detector.protected_sources)

    def test_invalid_timeout_and_nonfinite_threshold_are_rejected(self):
        for timeout in (0, -1, 65536, 86401):
            with self.subTest(timeout=timeout):
                config = dict(self.config, mitigation_hard_timeout_s=timeout)
                with self.assertRaises(ValueError):
                    validate_config(config)
        config = dict(self.config, source_pps=float("nan"))
        with self.assertRaises(ValueError):
            validate_config(config)
        config = dict(self.config, victim_pps=10 ** 1000)
        with self.assertRaises(ValueError):
            validate_config(config)

    def test_invalid_poll_interval_and_impossible_source_count_are_rejected(self):
        for interval in (0, 60.1):
            with self.subTest(interval=interval):
                with self.assertRaises(ValueError):
                    validate_config(dict(self.config, poll_interval_s=interval))
        with self.assertRaises(ValueError):
            validate_config(dict(self.config, min_sources=3,
                                  protected_sources=["10.0.0.11", "10.0.0.21"]))


class MitigationMatchTests(unittest.TestCase):
    def test_mitigation_match_is_source_destination_and_service_specific(self):
        fields = drop_match_fields("10.0.0.21")
        self.assertEqual(fields["ipv4_src"], "10.0.0.21")
        self.assertEqual(fields["ipv4_dst"], "10.0.0.10")
        self.assertEqual(fields["udp_dst"], 9000)
        self.assertEqual(fields["ip_proto"], 17)
        with self.assertRaises(ValueError):
            drop_match_fields("10.0.0.11")
        with self.assertRaises(ValueError):
            drop_match_fields("8.8.8.8")


class FlowStatsScopeTests(unittest.TestCase):
    def _stat(self, source, port, packets, udp_port=9000, cookie=COOKIE_UDP):
        return SimpleNamespace(
            match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=17,
                                  ipv4_src=source, ipv4_dst="10.0.0.10",
                                  udp_dst=udp_port, in_port=port,
                                  eth_src=LAB_IP_TO_MAC[source],
                                  eth_dst=LAB_IP_TO_MAC["10.0.0.10"]),
            cookie=cookie, packet_count=packets, byte_count=packets * 128,
        )

    def _sample(self, app, now, stats):
        with mock.patch("controller.forwarding.time.monotonic", return_value=now):
            app.flow_stats_handler(SimpleNamespace(msg=SimpleNamespace(
                datapath=app.datapath, xid=int(now * 100), flags=0, body=stats,
            )))

    def test_wrong_udp_port_never_enters_service_counters_or_mitigation(self):
        app = make_app()
        for now, packets in ((1, 0), (2, 200), (3, 400)):
            stats = [self._stat(source, port, packets, udp_port=9001)
                     for source, port in (("10.0.0.21", 3), ("10.0.0.22", 4))]
            self._sample(app, now, stats)
        self.assertFalse(any(event["type"] == "alert" for event in app.events))
        self.assertFalse(any(isinstance(msg, parser.OFPFlowMod) and msg.cookie == COOKIE_DROP
                             for msg in app._messages))

    def test_active_alert_rechecks_new_and_expired_offenders(self):
        app = make_app()
        initial_sources = (("10.0.0.21", 3), ("10.0.0.22", 4))
        for now, packets in ((1, 0), (2, 200), (3, 400)):
            self._sample(app, now, [self._stat(source, port, packets)
                                    for source, port in initial_sources])
        drops = [msg for msg in app._messages
                 if isinstance(msg, parser.OFPFlowMod) and msg.cookie == COOKIE_DROP]
        self.assertEqual({msg.match["ipv4_src"] for msg in drops},
                         {"10.0.0.21", "10.0.0.22"})
        self.assertEqual({msg.match["udp_dst"] for msg in drops}, {9000})

        with_new_source = initial_sources + (("10.0.0.23", 5),)
        self._sample(app, 4, [self._stat(source, port, 600 if source != "10.0.0.23" else 0)
                              for source, port in with_new_source])
        self._sample(app, 5, [self._stat(source, port, 800 if source != "10.0.0.23" else 200)
                              for source, port in with_new_source])
        drops = [msg for msg in app._messages
                 if isinstance(msg, parser.OFPFlowMod) and msg.cookie == COOKIE_DROP]
        self.assertIn("10.0.0.23", {msg.match["ipv4_src"] for msg in drops})

        app.active_blocks[1]["10.0.0.21"] = 0
        self._sample(app, 6, [self._stat(source, port, 1000 if source != "10.0.0.23" else 400)
                              for source, port in with_new_source])
        drops = [msg for msg in app._messages
                 if isinstance(msg, parser.OFPFlowMod) and msg.cookie == COOKIE_DROP]
        self.assertEqual(sum(msg.match["ipv4_src"] == "10.0.0.21" for msg in drops), 2)

    def test_disconnect_clears_pending_switch_state(self):
        app = make_app()
        app.pending_replies = {(1, 11): [], (2, 12): []}
        app.pending_barriers = {(1, 21): ["10.0.0.21"], (2, 22): ["10.0.0.22"]}
        app.switch_disconnected_handler(SimpleNamespace(datapath=app.datapath))
        self.assertEqual(app.pending_replies, {(2, 12): []})
        self.assertEqual(app.pending_barriers, {(2, 22): ["10.0.0.22"]})

    def test_disconnect_clears_meter_and_offender_state(self):
        app = make_serializing_app(action="rate_limit")
        flood(app)
        self.assertEqual(app.installed_meters[1], {1021, 1022})
        self.assertTrue(app.pending_ratelimit_xids[1])
        app.pending_ratelimit_xids[2] = {99: "10.0.0.23"}
        app.switch_disconnected_handler(SimpleNamespace(datapath=app.datapath))
        for state in (app.offenders, app.meter_support, app.installed_meters,
                      app.pending_ratelimit_xids, app.ratelimit_counters, app.meter_counters):
            self.assertNotIn(1, state)
        self.assertEqual(app.pending_ratelimit_xids, {2: {99: "10.0.0.23"}})
        self.assertFalse([key for key in app.pending_barriers if key[0] == 1])


class ShippedDropBehaviourTests(unittest.TestCase):
    def test_shipped_config_drops_with_fixed_ten_second_rules(self):
        app = make_serializing_app()
        self.assertEqual(app.config["mitigation"]["action"], "drop")
        for now in (100, 111, 122):
            app._mitigate(app.datapath, {"10.0.0.21": 200.0}, now)
        drops = flow_mods(app, COOKIE_DROP)
        self.assertEqual([msg.hard_timeout for msg in drops], [10, 10, 10])
        self.assertEqual({msg.priority for msg in drops}, {PRIORITY_DROP})
        self.assertEqual(PRIORITY_DROP, PRIORITY_MITIGATION)
        self.assertFalse(meter_mods(app))
        self.assertEqual([event["offense_count"] for event in events(app, "drop_requested")], [1, 2, 3])
        self.assertEqual({event["action"] for event in events(app, "drop_requested")}, {"drop"})

    def test_barrier_still_accepts_the_list_form(self):
        app = make_app()
        app.pending_barriers[(1, 7)] = ["10.0.0.21"]
        app.barrier_handler(SimpleNamespace(msg=SimpleNamespace(datapath=app.datapath, xid=7)))
        self.assertEqual(events(app, "drop_confirmed")[0]["sources"], ["10.0.0.21"])

    def test_legacy_seven_key_config_still_works(self):
        app = make_app()
        legacy = json.loads(Path(DEFAULT_CONFIG).read_text(encoding="utf-8"))
        for key in ("detector", "detectors", "mitigation"):
            legacy.pop(key, None)
        app.config = legacy
        app.offenders = {}
        self.assertEqual(app._new_detector().name, "threshold")
        app.datapath = SerializingDatapath(app._messages)
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 5)
        self.assertEqual([msg.hard_timeout for msg in flow_mods(app, COOKIE_DROP)], [10])


class RateLimitMitigationTests(unittest.TestCase):
    def test_rate_limit_installs_pps_meter_then_identity_bound_metered_flow(self):
        app = make_serializing_app(action="rate_limit")
        flood(app)
        meters = meter_mods(app)
        self.assertEqual([msg.meter_id for msg in meters], [1021, 1022])
        for meter in meters:
            self.assertEqual(meter.command, ofp.OFPMC_ADD)
            self.assertEqual(meter.flags, ofp.OFPMF_PKTPS | ofp.OFPMF_STATS | ofp.OFPMF_BURST)
            self.assertEqual(len(meter.bands), 1)
            self.assertIsInstance(meter.bands[0], parser.OFPMeterBandDrop)
            self.assertEqual((meter.bands[0].rate, meter.bands[0].burst_size), (20, 20))
        limits = flow_mods(app, COOKIE_RATELIMIT)
        self.assertEqual(COOKIE_RATELIMIT & 0xFF, 0x06)
        self.assertEqual(len(limits), 2)
        self.assertFalse(flow_mods(app, COOKIE_DROP))
        for flow, (source, port), meter in zip(limits, ATTACKERS, meters):
            self.assertLess(app._messages.index(meter), app._messages.index(flow))
            self.assertEqual(flow.priority, 200)
            self.assertEqual(flow.hard_timeout, 10)
            self.assertEqual(flow.flags, ofp.OFPFF_SEND_FLOW_REM)
            self.assertEqual(dict(flow.match.items()), {
                **drop_match_fields(source), "in_port": port, "eth_src": LAB_IP_TO_MAC[source],
                "eth_dst": LAB_IP_TO_MAC["10.0.0.10"]})
            meter_instruction, apply_instruction = flow.instructions
            self.assertIsInstance(meter_instruction, parser.OFPInstructionMeter)
            self.assertEqual(meter_instruction.meter_id, meter.meter_id)
            self.assertEqual(apply_instruction.type, ofp.OFPIT_APPLY_ACTIONS)
            self.assertEqual([action.port for action in apply_instruction.actions], [1])
            decoded = parser.OFPFlowMod.parser(app.datapath, flow.version, flow.msg_type, flow.msg_len,
                                               flow.xid, bytes(flow.buf))
            self.assertEqual([type(inst) for inst in decoded.instructions],
                             [parser.OFPInstructionMeter, parser.OFPInstructionActions])
            self.assertEqual((decoded.priority, decoded.hard_timeout, decoded.cookie),
                             (200, 10, COOKIE_RATELIMIT))
        requested = events(app, "ratelimit_requested")
        self.assertEqual([(e["source"], e["meter_id"], e["rate_pps"], e["burst_packets"],
                           e["hard_timeout_s"], e["offense_count"]) for e in requested],
                         [("10.0.0.21", 1021, 20, 20, 10, 1), ("10.0.0.22", 1022, 20, 20, 10, 1)])
        self.assertEqual(len(app.pending_ratelimit_xids[1]), 4)
        reply_to_barrier(app)
        self.assertEqual(events(app, "ratelimit_confirmed")[0]["sources"], ["10.0.0.21", "10.0.0.22"])
        self.assertFalse(events(app, "drop_confirmed"))
        self.assertEqual(app.pending_ratelimit_xids[1], {})

    def test_installed_meter_is_modified_with_the_current_rate(self):
        app = make_serializing_app(action="rate_limit")
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 100)
        app.config["mitigation"]["rate_limit_pps"] = 50
        app.config["mitigation"]["rate_limit_burst_packets"] = 0
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 111)
        first, second = meter_mods(app)
        self.assertEqual((first.command, second.command), (ofp.OFPMC_ADD, ofp.OFPMC_MODIFY))
        self.assertEqual((second.bands[0].rate, second.bands[0].burst_size), (50, 0))
        self.assertEqual(second.flags, ofp.OFPMF_PKTPS | ofp.OFPMF_STATS)

    def test_meter_mod_failure_falls_back_to_drop_with_the_same_timeout(self):
        app = make_serializing_app(action="rate_limit", backoff=True)
        app.offenders[1].next_offense("10.0.0.21", 0)  # earlier offense: back-off gives 20 s
        flood(app)
        meter = meter_mods(app)[0]
        switch_error(app, ofp.OFPET_METER_MOD_FAILED, ofp.OFPMMFC_OUT_OF_METERS, meter.xid)
        self.assertEqual(app.meter_support[1], "unsupported")
        self.assertEqual(events(app, "openflow_error")[0]["error_type"], ofp.OFPET_METER_MOD_FAILED)
        self.assertFalse(flow_mods(app, COOKIE_DROP))  # nothing happens before the barrier
        reply_to_barrier(app)
        failed = events(app, "ratelimit_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual((failed[0]["sources"], failed[0]["error_type"], failed[0]["error_code"],
                          failed[0]["fallback"]),
                         (["10.0.0.21"], ofp.OFPET_METER_MOD_FAILED, ofp.OFPMMFC_OUT_OF_METERS, "drop"))
        self.assertEqual(events(app, "ratelimit_confirmed")[0]["sources"], ["10.0.0.22"])
        drops = flow_mods(app, COOKIE_DROP)
        self.assertEqual([(msg.match["ipv4_src"], msg.hard_timeout) for msg in drops], [("10.0.0.21", 20)])
        self.assertNotIn(1021, app.installed_meters[1])
        self.assertIn(1022, app.installed_meters[1])
        self.assertFalse(events(app, "drop_confirmed"))
        reply_to_barrier(app)  # the fallback has its own barrier
        self.assertEqual(events(app, "drop_confirmed")[0]["sources"], ["10.0.0.21"])
        # The switch is now known to lack meters: the next offender is dropped directly.
        app._mitigate(app.datapath, {"10.0.0.23": 200.0}, 4)
        self.assertEqual(flow_mods(app, COOKIE_DROP)[-1].match["ipv4_src"], "10.0.0.23")
        self.assertEqual(events(app, "ratelimit_failed")[-1]["reason"], "meter_unsupported")

    def test_rejected_metered_flow_falls_back_for_that_source_only(self):
        app = make_serializing_app(action="rate_limit")
        flood(app)
        flow = flow_mods(app, COOKIE_RATELIMIT)[1]
        switch_error(app, ofp.OFPET_BAD_INSTRUCTION, ofp.OFPBIC_UNSUP_INST, flow.xid)
        reply_to_barrier(app)
        self.assertEqual(events(app, "ratelimit_failed")[0]["sources"], ["10.0.0.22"])
        self.assertEqual(events(app, "ratelimit_confirmed")[0]["sources"], ["10.0.0.21"])
        self.assertEqual([msg.match["ipv4_src"] for msg in flow_mods(app, COOKIE_DROP)], ["10.0.0.22"])

    def test_unattributed_meter_error_fails_every_pending_rate_limit(self):
        app = make_serializing_app(action="rate_limit")
        flood(app)
        switch_error(app, ofp.OFPET_METER_MOD_FAILED, ofp.OFPMMFC_UNKNOWN, 0xFFFF)
        reply_to_barrier(app)
        self.assertFalse(events(app, "ratelimit_confirmed"))
        self.assertEqual({msg.match["ipv4_src"] for msg in flow_mods(app, COOKIE_DROP)},
                         {"10.0.0.21", "10.0.0.22"})

    def test_unrelated_switch_error_is_logged_without_fallback(self):
        app = make_serializing_app(action="rate_limit")
        flood(app)
        switch_error(app, ofp.OFPET_BAD_REQUEST, ofp.OFPBRC_BAD_TYPE, 0xFFFF)
        reply_to_barrier(app)
        self.assertEqual(len(events(app, "openflow_error")), 1)
        self.assertEqual(app.meter_support[1], "unknown")
        self.assertEqual(len(events(app, "ratelimit_confirmed")[0]["sources"]), 2)

    def test_switch_without_meters_gets_drop_rules_directly(self):
        app = make_serializing_app(action="rate_limit")
        app.meter_features_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=app.datapath,
            body=[parser.OFPMeterFeaturesStats(max_meter=0, band_types=1 << ofp.OFPMBT_DROP,
                                               capabilities=ofp.OFPMF_PKTPS, max_bands=1, max_color=0)])))
        self.assertEqual(app.meter_support[1], "unsupported")
        self.assertEqual(events(app, "meter_features")[0]["supported"], False)
        flood(app)
        self.assertFalse(meter_mods(app))
        self.assertFalse(flow_mods(app, COOKIE_RATELIMIT))
        self.assertEqual({msg.match["ipv4_src"] for msg in flow_mods(app, COOKIE_DROP)},
                         {"10.0.0.21", "10.0.0.22"})
        failed = events(app, "ratelimit_failed")
        self.assertEqual((failed[0]["sources"], failed[0]["error_type"], failed[0]["reason"]),
                         (["10.0.0.21", "10.0.0.22"], None, "meter_unsupported"))
        reply_to_barrier(app)
        self.assertEqual(events(app, "drop_confirmed")[0]["sources"], ["10.0.0.21", "10.0.0.22"])

    def test_meter_features_with_pps_drop_band_mark_switch_supported(self):
        app = make_app()
        app.meter_features_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=app.datapath,
            body=[parser.OFPMeterFeaturesStats(max_meter=200000, band_types=1 << ofp.OFPMBT_DROP,
                                               capabilities=0xF, max_bands=1, max_color=0)])))
        self.assertEqual(app.meter_support[1], "supported")
        app.meter_support[1] = "unsupported"  # an earlier meter error is never overridden
        app.meter_features_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=app.datapath,
            body=[parser.OFPMeterFeaturesStats(200000, 2, 0xF, 1, 0)])))
        self.assertEqual(app.meter_support[1], "unsupported")

    def test_graduated_policy_rate_limits_first_and_drops_repeat_offender(self):
        app = make_serializing_app(action="graduated")
        flood(app)
        self.assertEqual(len(flow_mods(app, COOKIE_RATELIMIT)), 2)
        self.assertFalse(flow_mods(app, COOKIE_DROP))
        reply_to_barrier(app)
        # The 10.0.0.21 rule expires while the episode is still active.
        app.flow_removed_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=app.datapath, cookie=COOKIE_RATELIMIT, match=flow_mods(app, COOKIE_RATELIMIT)[0].match,
            packet_count=180, reason=ofp.OFPRR_HARD_TIMEOUT)))
        removed = events(app, "ratelimit_removed")[0]
        self.assertEqual((removed["source"], removed["packets"]), ("10.0.0.21", 180))
        self.assertNotIn("10.0.0.21", app.active_blocks[1])
        flood(app, times=(4, 5), start=600)
        drops = flow_mods(app, COOKIE_DROP)
        self.assertEqual([msg.match["ipv4_src"] for msg in drops], ["10.0.0.21"])
        request = events(app, "drop_requested")[0]
        self.assertEqual((request["offense_count"], request["action"]), (2, "drop"))
        self.assertEqual(len(flow_mods(app, COOKIE_RATELIMIT)), 2)  # 10.0.0.22 still limited

    def test_backoff_doubles_timeout_for_repeat_offense_within_memory(self):
        app = make_serializing_app(action="drop", backoff=True)
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 100)
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 111)
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 131.5)
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 500)  # memory (120 s) has passed
        self.assertEqual([msg.hard_timeout for msg in flow_mods(app, COOKIE_DROP)], [10, 20, 40, 10])

    def test_active_block_suppresses_rate_limited_source_until_rule_ends(self):
        app = make_serializing_app(action="rate_limit")
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 100)
        app._mitigate(app.datapath, {"10.0.0.21": 200.0}, 105)
        self.assertEqual(len(flow_mods(app, COOKIE_RATELIMIT)), 1)
        self.assertEqual(app.offenders[1].offense_count("10.0.0.21"), 1)


class DetectorSelectionTests(unittest.TestCase):
    class StubDetector:
        name = "stub"

        def __init__(self, protected_sources):
            self.protected_sources = frozenset(protected_sources)
            self.alert_active = False
            self.high_windows = 0

        def observe(self, rates):
            if self.alert_active or not rates["source_pps"]:
                return None
            self.alert_active = True
            return {"victim_pps": rates["victim_pps"], "sources": dict(rates["source_pps"]),
                    "detector": self.name, "scores": {"10.0.0.21": 9.5}}

        def qualifying_sources(self, rates):
            return {}

        def reset(self):
            self.alert_active = False

        def state(self):
            return {"detector": self.name, "alert_active": self.alert_active}

    def test_configured_detector_is_built_with_victim_and_client_protected(self):
        app = make_app()
        app.config["detector"] = "ewma"
        calls = []

        def fake_build(config, protected_sources=None):
            calls.append((config["detector"], set(protected_sources)))
            return self.StubDetector(protected_sources)

        with mock.patch("controller.forwarding.build_detector", side_effect=fake_build):
            detector = app._new_detector()
        self.assertEqual(detector.name, "stub")
        self.assertEqual(calls, [("ewma", {"10.0.0.10", CLIENT_IP})])

    def test_threshold_detector_comes_from_the_registry(self):
        app = make_app()
        detector = app._new_detector()
        self.assertIsInstance(detector, TwoWindowDetector)
        self.assertEqual((detector.victim_pps, detector.source_pps, detector.consecutive_windows),
                         (100.0, 30.0, 2))

    def test_ewma_detector_when_available(self):
        app = make_app()
        app.config["detector"] = "ewma"
        try:
            detector = app._new_detector()
        except ValueError:
            self.skipTest("ewma detector not available in controller.detectors yet")
        self.assertEqual(detector.name, "ewma")
        self.assertIn(CLIENT_IP, detector.protected_sources)

    def test_alert_event_carries_detector_name_scores_and_state(self):
        app = make_serializing_app()
        app.detectors[1] = self.StubDetector({"10.0.0.10", CLIENT_IP})
        flood(app, times=(1, 2))
        alert = events(app, "alert")[0]
        self.assertEqual((alert["detector"], alert["scores"]), ("stub", {"10.0.0.21": 9.5}))
        self.assertEqual(events(app, "sample")[-1]["detector_state"]["detector"], "stub")
        self.assertEqual(len(flow_mods(app, COOKIE_DROP)), 2)

    def test_threshold_alert_event_names_threshold_with_empty_scores(self):
        app = make_app()
        flood(app)
        alert = events(app, "alert")[0]
        self.assertEqual((alert["detector"], alert["scores"]), ("threshold", {}))
        self.assertEqual(alert["sources"], {"10.0.0.21": 200.0, "10.0.0.22": 200.0})
        self.assertEqual(events(app, "sample")[-1]["detector_state"],
                         {"detector": "threshold", "high_windows": 2, "alert_active": True})


class MeterTelemetryTests(unittest.TestCase):
    def _meter_reply(self, app, *stats):
        app.meter_stats_handler(SimpleNamespace(msg=SimpleNamespace(datapath=app.datapath, body=list(stats))))

    @staticmethod
    def _stat(meter_id, packets_in, band_packets, flow_count=1):
        return parser.OFPMeterStats(meter_id=meter_id, flow_count=flow_count, packet_in_count=packets_in,
                                    byte_in_count=packets_in * 128, duration_sec=1, duration_nsec=0,
                                    band_stats=[parser.OFPMeterBandStats(band_packets, band_packets * 128)])

    def test_meter_sample_reports_band_drop_deltas(self):
        app = make_app()
        self._meter_reply(app, self._stat(1021, 100, 60), self._stat(7, 5, 5))
        self._meter_reply(app, self._stat(1021, 250, 150))
        self._meter_reply(app, self._stat(1021, 10, 5))  # meter re-created
        self._meter_reply(app, self._stat(1021, 10, 5, flow_count=0))  # idle meter
        samples = events(app, "meter_sample")
        self.assertEqual([(s["meter_id"], s["source"], s["packet_in_delta"], s["band_drop_delta"],
                           s["band_drop_total"]) for s in samples],
                         [(1021, "10.0.0.21", 100, 60, 60), (1021, "10.0.0.21", 150, 90, 150),
                          (1021, "10.0.0.21", 10, 5, 5)])

    def test_rate_limited_counters_are_reported_but_not_fed_to_the_detector(self):
        app = make_app()
        for now, packets in ((1, 0), (2, 500), (3, 1000)):
            poll(app, now, [flow_stat("10.0.0.21", 3, packets, cookie=COOKIE_RATELIMIT),
                            flow_stat("10.0.0.22", 4, packets // 10)])
        sample = events(app, "sample")[-1]
        self.assertEqual(sample["ratelimit_packet_delta"], {"10.0.0.21": 500})
        self.assertEqual(sample["ratelimit_packet_total"], {"10.0.0.21": 1000})
        self.assertEqual(sample["source_pps"], {"10.0.0.22": 50.0})
        self.assertEqual(sample["drop_packet_delta"], {})

    def test_monitor_requests_meter_stats_only_while_meters_exist(self):
        app = make_app()
        app.datapaths = {1: app.datapath}
        for meters, expected in ((set(), 0), ({1021}, 1)):
            app._messages.clear()
            app.installed_meters[1] = meters
            with mock.patch("controller.forwarding.hub.sleep", side_effect=StopIteration):
                with self.assertRaises(StopIteration):
                    app._monitor()
            requests = [msg for msg in app._messages if isinstance(msg, parser.OFPMeterStatsRequest)]
            self.assertEqual(len(requests), expected)
            self.assertTrue(all(msg.meter_id == ofp.OFPM_ALL for msg in requests))

    def test_drop_rule_removal_is_unchanged(self):
        app = make_app()
        app.active_blocks[1]["10.0.0.21"] = 50
        app.flow_removed_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=app.datapath, cookie=COOKIE_DROP,
            match=parser.OFPMatch(**drop_match_fields("10.0.0.21")), packet_count=7, reason=0)))
        self.assertEqual(events(app, "drop_removed")[0]["packets"], 7)
        self.assertFalse(events(app, "ratelimit_removed"))
        self.assertNotIn("10.0.0.21", app.active_blocks[1])


class SwitchConnectMeterTests(unittest.TestCase):
    def test_connect_deletes_stale_meters_queries_features_and_resets_state(self):
        app = make_serializing_app(action="rate_limit")
        app.installed_meters[1] = {1021}
        app.meter_support[1] = "unsupported"
        app.switch_features_handler(SimpleNamespace(msg=SimpleNamespace(datapath=app.datapath)))
        deletes = [msg for msg in meter_mods(app) if msg.command == ofp.OFPMC_DELETE]
        self.assertEqual(len(deletes), 1)
        self.assertEqual((deletes[0].meter_id, deletes[0].flags, deletes[0].bands), (ofp.OFPM_ALL, 0, []))
        self.assertEqual(len([msg for msg in app._messages
                              if isinstance(msg, parser.OFPMeterFeaturesStatsRequest)]), 1)
        self.assertEqual(app.meter_support[1], "unknown")
        self.assertEqual(app.installed_meters[1], set())
        self.assertEqual(app.pending_ratelimit_xids[1], {})
        self.assertEqual(app.offenders[1].offense_count("10.0.0.21"), 0)


if __name__ == "__main__":
    unittest.main()
