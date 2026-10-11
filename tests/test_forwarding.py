"""Focused tests for match boundaries that protect later flow statistics."""

import unittest
from types import SimpleNamespace

from os_ken.lib.packet import ether_types

from controller.forwarding import COOKIE_CONTROL, COOKIE_UDP, PRIORITY_CONTROL, PRIORITY_UDP, forwarding_match_fields
from topology.lab_topology import HOSTS
from controller.forwarding import LAB_MAC_TO_IP


class ForwardingMatchTests(unittest.TestCase):
    def test_allowed_hosts_match_topology(self):
        self.assertEqual(LAB_MAC_TO_IP, {mac: address.split("/")[0] for address, mac in HOSTS.values()})

    def test_udp_match_is_attributable(self):
        ip_packet = SimpleNamespace(proto=17, src="10.0.0.11", dst="10.0.0.10")
        priority, cookie, match = forwarding_match_fields(
            ether_types.ETH_TYPE_IP, 2, "02:00:00:00:00:11", "02:00:00:00:00:10", ip_packet
        )
        self.assertEqual((priority, cookie), (PRIORITY_UDP, COOKIE_UDP))
        self.assertEqual(match["ipv4_src"], "10.0.0.11")
        self.assertEqual(match["ipv4_dst"], "10.0.0.10")
        self.assertEqual(match["ip_proto"], 17)
        self.assertEqual(match["in_port"], 2)

    def test_arp_match_cannot_capture_udp(self):
        priority, cookie, match = forwarding_match_fields(
            ether_types.ETH_TYPE_ARP, 2, "02:00:00:00:00:11", "02:00:00:00:00:10", None
        )
        self.assertEqual((priority, cookie), (PRIORITY_CONTROL, COOKIE_CONTROL))
        self.assertEqual(match["eth_type"], ether_types.ETH_TYPE_ARP)
        self.assertNotIn("ipv4_src", match)

    def test_other_ip_does_not_get_broad_forwarding_flow(self):
        tcp_packet = SimpleNamespace(proto=6, src="10.0.0.11", dst="10.0.0.10")
        self.assertIsNone(
            forwarding_match_fields(
                ether_types.ETH_TYPE_IP, 2, "02:00:00:00:00:11", "02:00:00:00:00:10", tcp_packet
            )
        )


if __name__ == "__main__":
    unittest.main()
