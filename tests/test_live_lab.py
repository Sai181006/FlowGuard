import csv
import io
import json
import socket
import time
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path

from controller.config import apply_overrides
from demo import live_lab
from demo.live_lab import (Gateway, LivePolicy, SOURCE_BY_PORT, bound_socket, client_phase_metrics,
                           phase_at, trial_seconds, wave_phase)
from demo.queueing import BottleneckQueue

ROOT = Path(__file__).resolve().parents[1]


class LiveLabTests(unittest.TestCase):
    def policy(self, mitigation=True):
        config = json.loads((ROOT / "config/detector.json").read_text())
        events = []
        return LivePolicy(config, mitigation, 0, lambda kind, **fields: events.append((kind, fields))), events

    def high_window(self, policy, now):
        for source in ("10.0.0.21", "10.0.0.22"):
            for _ in range(600):
                if policy.receive(source, 128, now - 0.1):
                    policy.forwarded_packet(source, 128)
        return policy.sample(now)

    def test_live_counts_trigger_real_policy_and_protected_client_bypasses_drops(self):
        policy, events = self.policy()
        self.high_window(policy, 1)
        self.assertFalse(policy.rules)
        self.high_window(policy, 2)
        self.assertEqual(set(policy.rules), {"10.0.0.21", "10.0.0.22"})
        self.assertFalse(policy.receive("10.0.0.21", 128, 3))
        self.assertTrue(policy.receive("10.0.0.11", 128, 3))
        self.assertEqual(policy.dropped["10.0.0.21"], 1)
        self.assertEqual([e[0] for e in events].count("alert"), 1)

    def test_disabled_policy_alerts_but_never_drops(self):
        policy, _ = self.policy(False)
        self.high_window(policy, 1)
        self.high_window(policy, 2)
        self.assertEqual(policy.alerts, 1)
        self.assertFalse(policy.rules)
        self.assertTrue(policy.receive("10.0.0.21", 128, 3))

    def test_rule_expiry_restores_forwarding_at_deadline(self):
        policy, events = self.policy()
        self.high_window(policy, 1)
        self.high_window(policy, 2)
        self.assertFalse(policy.receive("10.0.0.21", 128, 11.999))
        self.assertTrue(policy.receive("10.0.0.21", 128, 12))
        self.assertFalse(policy.rules)
        self.assertEqual([e[0] for e in events].count("rule_expired"), 2)

    def test_actual_socket_path_forwards_echo_then_discards_without_backend_packet(self):
        policy, _ = self.policy()
        with bound_socket(0) as frontend, bound_socket(0) as backend, bound_socket(0) as echo, bound_socket(0) as client:
            frontend.settimeout(1)
            port = client.getsockname()[1]
            # Ephemeral test port substitutes for the documented fixed localhost mapping.
            SOURCE_BY_PORT[port] = "10.0.0.21"
            try:
                output = io.StringIO()
                gateway = Gateway(frontend, backend, policy, csv.writer(output), 0, echo.getsockname()[1])
                payload = b"real-udp-forwarding-test"
                client.sendto(payload, frontend.getsockname())
                gateway.incoming(0.1, "attack")
                echo.settimeout(1)
                data, peer = echo.recvfrom(2048)
                self.assertEqual(data, payload)
                echo.sendto(data, peer)
                backend.settimeout(1)
                gateway.reply()
                client.settimeout(1)
                self.assertEqual(client.recvfrom(2048)[0], payload)
                self.assertEqual(gateway.echoes["10.0.0.21"], 1)
                policy.rules["10.0.0.21"] = 10
                client.sendto(b"must-be-discarded", frontend.getsockname())
                gateway.incoming(1, "attack")
                echo.settimeout(0.05)
                with self.assertRaises(socket.timeout):
                    echo.recvfrom(2048)
                self.assertEqual(policy.dropped["10.0.0.21"], 1)
                self.assertIn("DROP", output.getvalue())
            finally:
                SOURCE_BY_PORT.pop(port, None)

    def test_unknown_source_port_cannot_reach_echo(self):
        policy, _ = self.policy()
        with bound_socket(0) as frontend, bound_socket(0) as backend, bound_socket(0) as client:
            frontend.settimeout(1)
            gateway = Gateway(frontend, backend, policy, csv.writer(io.StringIO()), time.monotonic())
            port = client.getsockname()[1]
            previous = SOURCE_BY_PORT.pop(port, None)
            try:
                client.sendto(b"unknown", frontend.getsockname())
                gateway.incoming(0.1, "baseline")
                self.assertEqual(gateway.errors["unknown_source"], 1)
                self.assertFalse(policy.forwarded)
            finally:
                if previous is not None:
                    SOURCE_BY_PORT[port] = previous


class LiveLabResponseTests(unittest.TestCase):
    """Rate limiting, graduated response, back-off and the bottleneck queue path."""

    def policy(self, **overrides):
        config = apply_overrides(json.loads((ROOT / "config/detector.json").read_text()), **overrides)
        events = []
        return LivePolicy(config, True, 0, lambda kind, **fields: events.append((kind, fields))), events

    def alert(self, policy, first, second):
        for now in (first, second):
            for source in ("10.0.0.21", "10.0.0.22"):
                for _ in range(600):
                    if policy.receive(source, 128, now - 0.1):
                        policy.forwarded_packet(source, 128)
            policy.sample(now)

    def test_rate_limit_rule_passes_up_to_the_bucket_and_drops_above(self):
        policy, events = self.policy(action="rate_limit", rate_limit_pps=16)
        self.alert(policy, 1, 2)
        self.assertEqual({rule.action for rule in policy.rules.values()}, {"rate_limit"})
        installed = [fields for kind, fields in events if kind == "gateway_ratelimit_installed"]
        self.assertEqual(len(installed), 2)
        self.assertEqual({key: installed[0][key] for key in ("rate_pps", "burst", "timeout_s", "offense_count")},
                         {"rate_pps": 16, "burst": 20, "timeout_s": 10, "offense_count": 1})
        # The burst of 20 passes at once; the next datagram is over the limit.
        decisions = [policy.classify("10.0.0.21", 128, 2.0) for _ in range(21)]
        self.assertEqual(decisions, ["RL_PASS"] * 20 + ["RL_DROP"])
        # At exactly the configured 16 pps (exact binary fractions) every datagram passes ...
        at_limit = [policy.classify("10.0.0.21", 128, 2.0 + n / 16) for n in range(1, 41)]
        self.assertEqual(set(at_limit), {"RL_PASS"})
        # ... and at 32 pps half are dropped.
        above = [policy.classify("10.0.0.21", 128, 4.5 + n / 32) for n in range(1, 81)]
        self.assertAlmostEqual(above.count("RL_DROP"), 40, delta=2)
        self.assertFalse(policy.receive("10.0.0.21", 128, 7.0))
        self.assertTrue(policy.receive("10.0.0.11", 128, 7.0))
        self.assertEqual(policy.dropped["10.0.0.21"], policy.rl_dropped["10.0.0.21"])
        self.assertEqual(policy.rl_passed["10.0.0.21"], 20 + 40 + above.count("RL_PASS"))
        policy.expire(12)
        expired = [fields for kind, fields in events if kind == "rule_expired"]
        self.assertEqual(expired[0]["action"], "rate_limit")
        self.assertEqual(expired[0]["offense_count"], 1)

    def test_graduated_response_with_backoff_escalates_to_a_longer_drop(self):
        policy, events = self.policy(action="graduated", backoff=True)
        self.alert(policy, 1, 2)
        self.assertEqual(policy.rule("10.0.0.21"), policy.rules["10.0.0.21"])
        self.assertEqual(policy.rules["10.0.0.21"].action, "rate_limit")
        self.assertEqual(policy.rules["10.0.0.21"].deadline, 12)
        policy.sample(15)  # a quiet window clears the alert; the rules expired at 12
        self.assertFalse(policy.rules)
        self.alert(policy, 16, 17)
        rule = policy.rules["10.0.0.21"]
        self.assertEqual((rule.action, rule.deadline), ("drop", 17 + 20))
        drops = [fields for kind, fields in events if kind == "gateway_drop_installed"]
        self.assertEqual({(f["offense_count"], f["timeout_s"]) for f in drops}, {(2, 20)})
        self.assertEqual(policy.classify("10.0.0.21", 128, 30), "DROP")
        self.assertEqual(policy.classify("10.0.0.21", 128, 37), "FORWARD")

    def test_backoff_off_keeps_the_original_timeout(self):
        policy, events = self.policy()
        self.alert(policy, 1, 2)
        policy.sample(15)
        self.alert(policy, 16, 17)
        drops = [fields for kind, fields in events if kind == "gateway_drop_installed"]
        self.assertEqual([f["timeout_s"] for f in drops], [10, 10, 10, 10])
        self.assertEqual(sorted(f["offense_count"] for f in drops), [1, 1, 2, 2])

    def test_queue_socket_path_forwards_what_it_echoes_and_drops_never_reach_backend(self):
        policy, _ = self.policy()
        queue = BottleneckQueue(1000, 3)
        with bound_socket(0) as frontend, bound_socket(0) as backend, bound_socket(0) as echo, bound_socket(0) as client:
            port = client.getsockname()[1]
            SOURCE_BY_PORT[port] = "10.0.0.21"
            try:
                output = io.StringIO()
                gateway = Gateway(frontend, backend, policy, csv.writer(output), 0, echo.getsockname()[1], queue)
                payloads = [f"queued-{n}".encode() for n in range(6)]
                frontend.settimeout(1)
                for payload in payloads:
                    client.sendto(payload, frontend.getsockname())
                    gateway.incoming(0.0, "attack")
                self.assertEqual(gateway.queue_drops["10.0.0.21"], 3)
                self.assertEqual(policy.forwarded["10.0.0.21"], 6)  # counted before the queue
                self.assertEqual(gateway.service(0.0005), 0)
                self.assertEqual(gateway.service(0.01), 3)
                echo.settimeout(1)
                received = []
                for _ in range(3):
                    data, peer = echo.recvfrom(2048)
                    received.append(data)
                    echo.sendto(data, peer)
                self.assertEqual(received, payloads[:3])
                echo.settimeout(0.05)
                with self.assertRaises(socket.timeout):
                    echo.recvfrom(2048)
                backend.settimeout(1)
                for _ in range(3):
                    gateway.reply()
                client.settimeout(1)
                self.assertEqual([client.recvfrom(2048)[0] for _ in range(3)], payloads[:3])
                self.assertEqual(gateway.delivered["10.0.0.21"], gateway.echoes["10.0.0.21"])
                self.assertEqual(gateway.echoes["10.0.0.21"], 3)
                self.assertFalse(gateway.pending)
                rows = list(csv.reader(io.StringIO(output.getvalue())))
                self.assertEqual([row[8] for row in rows], ["FORWARD"] * 3 + ["QUEUE_TAIL_DROP"] * 3)
                self.assertEqual([row[10] for row in rows], ["1", "2", "3", "3", "3", "3"])
            finally:
                SOURCE_BY_PORT.pop(port, None)

    def test_direct_path_logs_an_empty_queue_depth(self):
        policy, _ = self.policy()
        with bound_socket(0) as frontend, bound_socket(0) as backend, bound_socket(0) as echo, bound_socket(0) as client:
            port = client.getsockname()[1]
            SOURCE_BY_PORT[port] = "10.0.0.21"
            try:
                output = io.StringIO()
                gateway = Gateway(frontend, backend, policy, csv.writer(output), 0, echo.getsockname()[1])
                frontend.settimeout(1)
                client.sendto(b"direct", frontend.getsockname())
                gateway.incoming(0.1, "baseline")
                self.assertEqual(gateway.service(1.0), 0)
                row = next(csv.reader(io.StringIO(output.getvalue())))
                self.assertEqual((row[8], row[10]), ("FORWARD", ""))
                self.assertEqual(gateway.delivered["10.0.0.21"], policy.forwarded["10.0.0.21"])
            finally:
                SOURCE_BY_PORT.pop(port, None)


class LiveLabScheduleTests(unittest.TestCase):
    def test_single_wave_matches_original_phases(self):
        self.assertEqual([phase_at(t, 8, 11) for t in (0, 1.99, 2, 9.99, 10, 20.99, 21, 25)],
                         ["baseline", "baseline", "attack", "attack", "expiry-wait", "expiry-wait",
                          "recovery", "recovery"])

    def test_waves_are_separated_by_gaps(self):
        self.assertEqual([wave_phase(t, 8, 11, waves=2) for t in (3, 10, 15.9, 16, 24)],
                         [("attack", 1), ("gap", 1), ("gap", 1), ("attack", 2), ("expiry-wait", 0)])

    def test_adaptive_detectors_get_a_warm_up_baseline_and_backoff_lengthens_the_hold(self):
        config = apply_overrides(json.loads((ROOT / "config/detector.json").read_text()))
        self.assertEqual(trial_seconds(config, 8, 1), (2, 11, 23))
        config["mitigation"]["backoff"]["enabled"] = True
        self.assertEqual(trial_seconds(config, 8, 3), (2, 41, 2 + 24 + 12 + 41 + 2))
        config["detector"] = "ewma"
        self.assertEqual(trial_seconds(config, 8, 1)[0], 5)

    def test_probe_metrics_per_phase_from_send_timestamps(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        rows = [{"timestamp_utc": (start + timedelta(seconds=t)).isoformat(), "sequence": str(seq),
                 "status": status, "rtt_ms": rtt}
                for seq, (t, status, rtt) in enumerate([(0.5, "ok", "1.0"), (2.5, "timeout", ""),
                                                        (3.0, "ok", "160.0"), (3.5, "ok", "170.0"),
                                                        (4.0, "timeout", "")], 1)]
        phases = client_phase_metrics(rows, start, 8, 11, 1)
        self.assertEqual(phases["baseline"]["loss_percent"], 0)
        attack = phases["attack"]
        self.assertEqual((attack["sent"], attack["received"], attack["loss_percent"]), (4, 2, 50))
        self.assertEqual(attack["rtt_ms"]["p95"], 170.0)
        self.assertAlmostEqual(attack["jitter_ms_rfc3550"], 10 / 16, places=3)

    def test_invalid_command_lines_are_rejected_before_any_socket_opens(self):
        for argv in (["--bottleneck-pps", "10"], ["--queue-packets", "50"], ["--queue-discipline", "red"],
                     ["--bottleneck-pps", "300", "--queue-packets", "4"], ["--waves", "4"],
                     ["--config", "/etc/hostname"], ["--rate-limit-pps", "0"],
                     ["--waves", "3", "--backoff", "--duration-s", "30"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                live_lab.main(argv)
            self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
