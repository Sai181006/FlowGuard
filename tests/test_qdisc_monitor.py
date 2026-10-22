"""qdisc_monitor: tc JSON normalisation and a sampler that survives tc errors."""

import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from experiments import analyze
from experiments.qdisc_monitor import QdiscMonitor, parse_tc_json, read_qdiscs, root_qdisc, tc_command


# `tc -s -j qdisc show dev s1-eth1` from iproute2 6.x for Mininet's
# TCLink(bw=0.5, max_queue_size=50): htb 5: root and its netem 10: leaf.
TC_FIXTURE = (
    '[{"kind":"htb","handle":"5:","root":true,"refcnt":2,"options":{"r2q":10,"default":"0x1",'
    '"direct_packets_stat":0,"direct_qlen":1000},"bytes":1395330,"packets":8208,"drops":15302,'
    '"overlimits":21544,"requeues":0,"backlog":8500,"qlen":50},'
    '{"kind":"netem","handle":"10:","parent":"5:1","options":{"limit":50,"seed":1234567890123,'
    '"ecn":false,"gap":0},"bytes":1395330,"packets":8208,"drops":15302,"overlimits":0,'
    '"requeues":0,"backlog":8500,"qlen":50}]\n'
)


class ParseTests(unittest.TestCase):
    def test_parse_htb_netem_tree(self):
        qdiscs = parse_tc_json(TC_FIXTURE)
        self.assertEqual(qdiscs, [
            {"kind": "htb", "handle": "5:", "parent": "root", "packets": 8208, "bytes": 1395330,
             "drops": 15302, "overlimits": 21544, "requeues": 0, "backlog_bytes": 8500, "qlen": 50},
            {"kind": "netem", "handle": "10:", "parent": "5:1", "packets": 8208, "bytes": 1395330,
             "drops": 15302, "overlimits": 0, "requeues": 0, "backlog_bytes": 8500, "qlen": 50,
             "limit": 50},
        ])
        self.assertEqual(root_qdisc(qdiscs)["kind"], "htb")

    def test_parse_edge_cases(self):
        self.assertEqual(parse_tc_json(""), [])
        noqueue = parse_tc_json('[{"kind":"noqueue","handle":"0:","root":true,"options":{}}]')
        self.assertEqual(noqueue[0]["parent"], "root")
        self.assertEqual(noqueue[0]["drops"], 0)
        with self.assertRaises(ValueError):
            parse_tc_json('{"kind":"htb"}')
        with self.assertRaises(ValueError):
            parse_tc_json("Cannot find device \"s1-eth1\"")
        self.assertIsNone(root_qdisc([]))

    def test_read_qdiscs_uses_the_runner(self):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return TC_FIXTURE

        raw, qdiscs = read_qdiscs("s1-eth1", runner)
        self.assertEqual(raw, TC_FIXTURE)
        self.assertEqual(len(qdiscs), 2)
        self.assertEqual(calls[0][0], ["tc", "-s", "-j", "qdisc", "show", "dev", "s1-eth1"])
        self.assertEqual(calls[0][0], tc_command("s1-eth1"))
        self.assertTrue(calls[0][1]["text"])


class MonitorTests(unittest.TestCase):
    def test_monitor_writes_jsonl_and_survives_tc_errors(self):
        responses = [TC_FIXTURE, subprocess.CalledProcessError(1, "tc"), "not json", TC_FIXTURE]
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            response = responses[min(len(calls) - 1, len(responses) - 1)]
            if isinstance(response, Exception):
                raise response
            return response

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qdisc.jsonl"
            monitor = QdiscMonitor("s1-eth1", path, interval=0.01, runner=runner).start()
            self.assertTrue(monitor.active)
            deadline = time.monotonic() + 5
            while len(calls) < 4 and time.monotonic() < deadline:
                time.sleep(0.01)
            summary = monitor.stop()
            self.assertFalse(monitor.active)
            self.assertEqual(monitor.stop()["samples"], summary["samples"])  # idempotent
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            qdisc = analyze.qdisc_summary(path)
        self.assertGreaterEqual(len(records), 4)
        self.assertEqual(summary["samples"], len(records))
        self.assertEqual(summary["errors"], 2)
        for record in records:
            self.assertEqual(record["dev"], "s1-eth1")
            self.assertIn("monotonic_s", record)
            self.assertIn("time_utc", record)
        self.assertEqual(records[0]["qdiscs"][0]["kind"], "htb")
        self.assertIn("CalledProcessError", records[1]["error"])
        self.assertEqual(records[1]["qdiscs"], [])
        self.assertIn("error", records[2])
        self.assertEqual(records[3]["qdiscs"][1]["limit"], 50)
        self.assertEqual(qdisc["errors"], 2)
        self.assertEqual(qdisc["root_kind"], "htb")
        self.assertEqual(qdisc["drops"], 0)  # identical cumulative counters
        self.assertEqual(qdisc["max_qlen"], 50)

    def test_sample_records_missing_tc(self):
        def runner(command, **kwargs):
            raise FileNotFoundError("tc")

        with tempfile.TemporaryDirectory() as directory:
            monitor = QdiscMonitor("s1-eth1", Path(directory) / "q.jsonl", runner=runner, clock=lambda: 7.5)
            record = monitor.sample()
        self.assertEqual(record["monotonic_s"], 7.5)
        self.assertEqual(record["qdiscs"], [])
        self.assertIn("FileNotFoundError", record["error"])
        with self.assertRaises(ValueError):
            QdiscMonitor("s1-eth1", "x", interval=0)


if __name__ == "__main__":
    unittest.main()
