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
from controller.forwarding import (
    CLIENT_IP, COOKIE_CONTROL, COOKIE_DROP, COOKIE_PUNT, COOKIE_UDP,
    DEFAULT_CONFIG, LAB_MAC_TO_IP, LAB_MAC_TO_PORT, LAB_IP_TO_MAC,
    PRIORITY_CONTROL, PRIORITY_UDP,
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


if __name__ == "__main__":
    unittest.main()
