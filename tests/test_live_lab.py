import csv
import io
import json
import socket
import time
import unittest
from pathlib import Path

from demo.live_lab import Gateway, LivePolicy, SOURCE_BY_PORT, bound_socket

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


if __name__ == "__main__":
    unittest.main()
