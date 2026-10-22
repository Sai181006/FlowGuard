"""OpenFlow 1.3 meter builders, checked against OS-Ken's real encoder."""

import struct
import unittest
from types import SimpleNamespace

from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

from controller.lab import LAB_IP_TO_MAC, VICTIM_IP, VICTIM_SWITCH_PORT
from controller.meters import (
    METER_ID_BASE, meter_delete_all, meter_features_request, meter_id_for, meter_mod_add,
    meter_stats_request, parse_meter_features, ratelimit_instructions, ratelimit_match_fields,
    source_for_meter_id,
)


def fake_datapath():
    return SimpleNamespace(id=1, ofproto=ofp, ofproto_parser=parser)


def encode(msg, xid=1):
    msg.set_xid(xid)
    msg.serialize()
    return bytes(msg.buf)


def decode_meter_mod(buf):
    version, msg_type, length, xid = struct.unpack_from(ofp.OFP_HEADER_PACK_STR, buf, 0)
    command, flags, meter_id = struct.unpack_from(ofp.OFP_METER_MOD_PACK_STR, buf, ofp.OFP_HEADER_SIZE)
    bands = []
    offset = ofp.OFP_METER_MOD_SIZE
    while offset < length:
        bands.append(struct.unpack_from(ofp.OFP_METER_BAND_DROP_PACK_STR, buf, offset))
        offset += ofp.OFP_METER_BAND_DROP_SIZE
    return {"version": version, "type": msg_type, "length": length, "xid": xid,
            "command": command, "flags": flags, "meter_id": meter_id, "bands": bands}


class MeterIdTests(unittest.TestCase):
    def test_meter_id_is_base_plus_last_octet(self):
        self.assertEqual(METER_ID_BASE, 1000)
        self.assertEqual(meter_id_for("10.0.0.21"), 1021)
        self.assertEqual(meter_id_for("10.0.0.23"), 1023)
        self.assertEqual(source_for_meter_id(1022), "10.0.0.22")

    def test_foreign_ids_and_addresses_are_rejected(self):
        with self.assertRaises(ValueError):
            meter_id_for("8.8.8.8")
        for meter_id in (1, 1000, 1099, ofp.OFPM_ALL, None):
            self.assertIsNone(source_for_meter_id(meter_id))


class MeterModTests(unittest.TestCase):
    def test_add_is_a_packet_rate_drop_meter_with_burst_and_stats(self):
        msg = meter_mod_add(fake_datapath(), 1021, 20, 20)
        self.assertIsInstance(msg, parser.OFPMeterMod)
        wire = decode_meter_mod(encode(msg, xid=42))
        self.assertEqual((wire["version"], wire["type"], wire["length"], wire["xid"]),
                         (ofp.OFP_VERSION, ofp.OFPT_METER_MOD, 32, 42))
        self.assertEqual(wire["command"], ofp.OFPMC_ADD)
        self.assertEqual(wire["flags"], ofp.OFPMF_PKTPS | ofp.OFPMF_BURST | ofp.OFPMF_STATS)
        self.assertEqual(wire["meter_id"], 1021)
        self.assertEqual(wire["bands"], [(ofp.OFPMBT_DROP, ofp.OFP_METER_BAND_DROP_SIZE, 20, 20)])

    def test_modify_without_burst_drops_the_burst_flag(self):
        wire = decode_meter_mod(encode(meter_mod_add(fake_datapath(), 1022, 50, 0, modify=True)))
        self.assertEqual(wire["command"], ofp.OFPMC_MODIFY)
        self.assertEqual(wire["flags"], ofp.OFPMF_PKTPS | ofp.OFPMF_STATS)
        self.assertEqual(wire["bands"][0][2:], (50, 0))

    def test_delete_all_targets_every_meter_without_bands(self):
        wire = decode_meter_mod(encode(meter_delete_all(fake_datapath())))
        self.assertEqual((wire["command"], wire["flags"], wire["meter_id"], wire["bands"], wire["length"]),
                         (ofp.OFPMC_DELETE, 0, ofp.OFPM_ALL, [], ofp.OFP_METER_MOD_SIZE))


class RateLimitFlowTests(unittest.TestCase):
    def test_match_is_service_specific_and_identity_bound(self):
        self.assertEqual(ratelimit_match_fields("10.0.0.22"), {
            "eth_type": 0x0800, "ip_proto": 17, "ipv4_src": "10.0.0.22", "ipv4_dst": VICTIM_IP,
            "udp_dst": 9000, "in_port": 4, "eth_src": LAB_IP_TO_MAC["10.0.0.22"],
            "eth_dst": LAB_IP_TO_MAC[VICTIM_IP]})
        for source in (VICTIM_IP, "10.0.0.11", "192.0.2.1"):
            with self.assertRaises((ValueError, KeyError)):
                ratelimit_match_fields(source)

    def test_instructions_meter_then_forward_to_victim_and_encode(self):
        datapath = fake_datapath()
        instructions = ratelimit_instructions(datapath, 1021)
        self.assertEqual([type(inst) for inst in instructions],
                         [parser.OFPInstructionMeter, parser.OFPInstructionActions])
        self.assertEqual(instructions[0].meter_id, 1021)
        self.assertEqual(instructions[1].type, ofp.OFPIT_APPLY_ACTIONS)
        self.assertEqual([action.port for action in instructions[1].actions], [VICTIM_SWITCH_PORT])
        flow = parser.OFPFlowMod(datapath=datapath, priority=200, cookie=0xDD05000000000006,
                                 match=parser.OFPMatch(**ratelimit_match_fields("10.0.0.21")),
                                 instructions=instructions, hard_timeout=10,
                                 flags=ofp.OFPFF_SEND_FLOW_REM)
        buf = encode(flow, xid=9)
        decoded = parser.OFPFlowMod.parser(datapath, ofp.OFP_VERSION, ofp.OFPT_FLOW_MOD, len(buf), 9, buf)
        self.assertEqual(decoded.instructions[0].meter_id, 1021)
        self.assertEqual(decoded.instructions[1].actions[0].port, VICTIM_SWITCH_PORT)
        self.assertEqual(dict(decoded.match.items()), ratelimit_match_fields("10.0.0.21"))
        self.assertEqual((decoded.cookie, decoded.priority, decoded.hard_timeout),
                         (0xDD05000000000006, 200, 10))


class MeterMultipartTests(unittest.TestCase):
    def test_requests_encode(self):
        features = meter_features_request(fake_datapath())
        self.assertIsInstance(features, parser.OFPMeterFeaturesStatsRequest)
        buf = encode(features)
        self.assertEqual(struct.unpack_from("!H", buf, ofp.OFP_HEADER_SIZE)[0], ofp.OFPMP_METER_FEATURES)
        stats = meter_stats_request(fake_datapath())
        buf = encode(stats)
        self.assertEqual(struct.unpack_from("!H", buf, ofp.OFP_HEADER_SIZE)[0], ofp.OFPMP_METER)
        self.assertEqual(struct.unpack_from("!I", buf, ofp.OFP_MULTIPART_REQUEST_SIZE)[0], ofp.OFPM_ALL)

    def test_features_need_meters_drop_band_and_packet_rate(self):
        drop = 1 << ofp.OFPMBT_DROP
        cases = (
            ((200000, drop, ofp.OFPMF_PKTPS | ofp.OFPMF_KBPS), True),
            ((0, drop, ofp.OFPMF_PKTPS), False),
            ((200000, 1 << ofp.OFPMBT_DSCP_REMARK, ofp.OFPMF_PKTPS), False),
            ((200000, drop, ofp.OFPMF_KBPS), False),
        )
        for (max_meter, band_types, capabilities), supported in cases:
            with self.subTest(max_meter=max_meter, band_types=band_types, capabilities=capabilities):
                body = [parser.OFPMeterFeaturesStats(max_meter, band_types, capabilities, 1, 0)]
                self.assertEqual(parse_meter_features(body, ofp), {
                    "supported": supported, "max_meter": max_meter, "band_types": band_types,
                    "capabilities": capabilities})
        self.assertFalse(parse_meter_features([], ofp)["supported"])


if __name__ == "__main__":
    unittest.main()
