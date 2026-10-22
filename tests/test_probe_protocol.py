import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traffic.probe_protocol import (FLOOD, HEADER, HEADER_LEN, MAGIC, PROBE_REQUEST, VERSION,
                                    JitterEstimator, ProbeStats, decode, describe, encode,
                                    percentile, rfc3550_jitter)

MS = 1_000_000


class WireFormatTests(unittest.TestCase):
    def test_header_layout(self):
        self.assertEqual(HEADER.size, 32)
        self.assertEqual(HEADER_LEN, 32)
        packet = encode(12, 0xDEADBEEF, 1_700_000_000_123_456_789, total_bytes=64)
        self.assertEqual(packet[:4], MAGIC)
        self.assertEqual(packet[4], VERSION)
        self.assertEqual(packet[5], PROBE_REQUEST)
        self.assertEqual(packet[8:12], bytes.fromhex("deadbeef"))
        self.assertEqual(packet[12:16], (12).to_bytes(4, "big"))

    def test_roundtrip(self):
        for total in (32, 64, 512):
            packet = encode(7, 0x1234ABCD, 1_700_000_000_000_000_001, FLOOD, total)
            self.assertEqual(len(packet), total)
            header = decode(packet)
            self.assertIsNotNone(header)
            self.assertEqual((header.seq, header.session_id, header.tx_time_ns, header.msg_type),
                             (7, 0x1234ABCD, 1_700_000_000_000_000_001, FLOOD))
            self.assertEqual(header.payload_len, total - 32)
            self.assertEqual(header.flags, 1 if total > 32 else 0)
            self.assertTrue(header.crc_ok)

    def test_encode_is_deterministic(self):
        self.assertEqual(encode(1, 2, 3), encode(1, 2, 3))

    def test_encode_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            encode(1, 1, 1, total_bytes=31)

    def test_single_bit_flip_fails_crc(self):
        packet = encode(5, 99, 123, total_bytes=64)
        for index in (9, 13, 20, 40, 63):
            corrupted = bytearray(packet)
            corrupted[index] ^= 0x01
            header = decode(bytes(corrupted))
            self.assertIsNotNone(header, index)
            self.assertFalse(header.crc_ok, index)

    def test_non_fgpb_returns_none(self):
        good = encode(1, 1, 1, total_bytes=64)
        wrong_version = bytearray(good)
        wrong_version[4] = 2
        self.assertIsNone(decode(b"ddos-probe:1:2"))
        self.assertIsNone(decode(good[:31]))
        self.assertIsNone(decode(good + b"x"))
        self.assertIsNone(decode(good[:-1]))
        self.assertIsNone(decode(bytes(wrong_version)))
        self.assertIsNone(decode(b"XXXX" + good[4:]))


class DescribeTests(unittest.TestCase):
    def test_binary_probe(self):
        text = describe(encode(12, 0xAB, 1, total_bytes=64))
        self.assertEqual(text, "FGPB probe seq=12 session=0x000000ab len=64 crc=ok")
        corrupted = bytearray(encode(12, 0xAB, 1, total_bytes=64))
        corrupted[-1] ^= 0xFF
        self.assertIn("crc=BAD", describe(bytes(corrupted)))
        self.assertTrue(describe(encode(3, 1, 1, FLOOD, 128)).startswith("FGPB flood seq=3"))

    def test_text_families(self):
        self.assertEqual(describe(b"ddos-probe:4:1700000000000000000"),
                         "legacy text probe seq=4 tx_ns=1700000000000000000")
        self.assertEqual(describe(b"FLOWGUARD-LAB-ONLY:".ljust(128, b"X")), "Mininet lab flood (128 bytes)")
        native = b"flowguard:a1:attack:42:1700000000000000000".ljust(128, b".")
        self.assertEqual(describe(native), "native lab a1 phase=attack seq=42 (128 bytes)")

    def test_fallback_is_ascii_and_bounded(self):
        text = describe(b"\x00\xffhello" + b"z" * 200)
        self.assertTrue(text.startswith("..hello"))
        self.assertLessEqual(len(text), 64)
        self.assertTrue(text.isascii())
        self.assertEqual(describe(b""), "(empty)")


class StatisticsTests(unittest.TestCase):
    def test_percentile_nearest_rank(self):
        values = [50, 15, 40, 20, 35]
        self.assertEqual(percentile(values, 5), 15)
        self.assertEqual(percentile(values, 30), 20)
        self.assertEqual(percentile(values, 40), 20)
        self.assertEqual(percentile(values, 50), 35)
        self.assertEqual(percentile(values, 100), 50)
        self.assertEqual(percentile(list(range(1, 101)), 95), 95)
        self.assertEqual(percentile(list(range(1, 21)), 95), 19)
        self.assertIsNone(percentile([], 50))
        with self.assertRaises(ValueError):
            percentile(values, 0)

    def test_rfc3550_jitter_hand_example(self):
        # Transit 10, 12, 9 ms: J = 2/16 = 0.125, then 0.125 + (3 - 0.125)/16 = 0.3046875.
        pairs = [(0, 10 * MS), (100 * MS, 112 * MS), (200 * MS, 209 * MS)]
        self.assertAlmostEqual(rfc3550_jitter(pairs), 0.3046875)
        self.assertIsNone(rfc3550_jitter(pairs[:1]))
        estimator = JitterEstimator()
        estimator.update(*pairs[0])
        self.assertIsNone(estimator.jitter_ms)
        estimator.update(*pairs[1])
        self.assertAlmostEqual(estimator.jitter_ms, 0.125)

    def test_probe_stats_classification(self):
        stats = ProbeStats()
        for seq in range(1, 7):
            stats.on_send(seq, seq * 100 * MS)
        self.assertEqual(stats.on_reply(1, 100 * MS + 1 * MS), "ok")
        self.assertEqual(stats.on_reply(3, 300 * MS + 3 * MS), "ok")
        self.assertEqual(stats.on_reply(2, 200 * MS + 2 * MS), "ok")  # reordered but on time
        self.assertEqual(stats.on_reply(2, 200 * MS + 9 * MS), "duplicate")
        self.assertEqual(stats.on_reply(4, 900 * MS, deadline_passed=True), "late")
        self.assertEqual(stats.on_reply(99, 1), "unknown")
        summary = stats.summary()
        self.assertEqual(summary["sent"], 6)
        self.assertEqual(summary["received"], 3)
        self.assertEqual(summary["loss_percent"], 50.0)
        self.assertEqual((summary["late"], summary["duplicates"], summary["reordered"]), (1, 1, 1))
        self.assertEqual(summary["max_consecutive_loss"], 3)
        self.assertEqual(summary["rtt_ms"], {"min": 1.0, "mean": 2.0, "p50": 2.0, "p95": 3.0,
                                             "p99": 3.0, "max": 3.0})
        # Arrival order 1, 3, 2 ms: J = 2/16, then + (1 - 0.125)/16.
        self.assertEqual(summary["jitter_ms_rfc3550"], round(0.125 + 0.875 / 16, 3))

    def test_empty_summary(self):
        summary = ProbeStats().summary()
        self.assertEqual((summary["sent"], summary["received"], summary["loss_percent"]), (0, 0, 0.0))
        self.assertIsNone(summary["rtt_ms"]["p50"])
        self.assertIsNone(summary["jitter_ms_rfc3550"])

    def test_from_csv_ignores_summary_rows(self):
        text = ("timestamp_utc,sequence,status,rtt_ms\n"
                "2026-01-01T00:00:00+00:00,1,ok,1.000\n"
                "2026-01-01T00:00:00+00:00,2,ok,3.000\n"
                "2026-01-01T00:00:00+00:00,3,timeout,\n"
                "2026-01-01T00:00:00+00:00,4,timeout,\n"
                "2026-01-01T00:00:00+00:00,5,ok,2.000\n"
                "sent=5 received=3 loss=40.0%\n"
                "metrics p50=2.000 p95=3.000 p99=3.000 jitter=0.180\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.csv"
            path.write_text(text, encoding="utf-8")
            summary = ProbeStats.from_csv(path).summary()
        self.assertEqual((summary["sent"], summary["received"], summary["loss_percent"]), (5, 3, 40.0))
        self.assertIsNone(summary["duplicates"])
        self.assertIsNone(summary["reordered"])
        self.assertIsNone(summary["late"])
        self.assertEqual(summary["max_consecutive_loss"], 2)
        self.assertEqual(summary["rtt_ms"]["p50"], 2.0)
        self.assertEqual(summary["rtt_ms"]["mean"], 2.0)
        self.assertEqual(summary["jitter_ms_rfc3550"], round(0.125 + 0.875 / 16, 3))


if __name__ == "__main__":
    unittest.main()
