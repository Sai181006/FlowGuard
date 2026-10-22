from contextlib import redirect_stdout
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from tempfile import TemporaryDirectory
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from demo import terminal
from demo.engine import ALL_SCENARIOS, recorded_data, simulate
from demo.server import DASHBOARD_ROOT, FlowGuardHandler, static_asset


def _events(data, event_type):
    return [event for event in data["events"] if event["type"] == event_type]


class DemoEngineTests(unittest.TestCase):
    def test_simulation_is_deterministic_and_uses_two_consecutive_windows(self):
        first = simulate("sustained", mitigation=False)
        second = simulate("sustained", mitigation=False)

        self.assertEqual(first, second)
        self.assertEqual(first["summary"]["first_alert_s"], 7)
        self.assertEqual([event["t_s"] for event in _events(first, "alert")], [7])
        self.assertEqual(first["frames"][7]["high_windows"], 2)
        self.assertTrue(first["frames"][7]["detector_alert"])
        self.assertEqual(first["frames"][7]["detector_input"]["victim_pps"], 1210)

    def test_modeled_drop_ttl_expires_and_detector_rearms(self):
        result = simulate("sustained", mitigation=True)

        self.assertEqual([event["t_s"] for event in _events(result, "alert")], [7, 19])
        self.assertEqual([event["t_s"] for event in _events(result, "rule_expired")], [17, 17, 29, 29])
        self.assertEqual(result["frames"][8]["source_delivered_pps"]["10.0.0.21"], 0)
        self.assertEqual(result["frames"][8]["source_dropped_pps"]["10.0.0.21"], 600)
        self.assertEqual(result["frames"][8]["victim_delivered_pps"], 10)
        self.assertEqual(result["frames"][18]["high_windows"], 1)
        self.assertEqual(result["frames"][19]["state"], "mitigating")
        self.assertIn("does not contact Open vSwitch", result["provenance"]["warning"])

    def test_one_window_burst_does_not_alert(self):
        result = simulate("burst", mitigation=True)

        self.assertEqual(result["summary"]["alert_count"], 0)
        self.assertEqual(result["frames"][6]["high_windows"], 1)
        self.assertEqual(result["frames"][7]["high_windows"], 0)
        self.assertFalse(_events(result, "drop_confirmed"))

    def test_detector_documents_source_count_and_rate_threshold_blind_spots(self):
        single = simulate("single-source", mitigation=True)
        low_rate = simulate("low-rate", mitigation=True)

        self.assertEqual(single["frames"][7]["detector_input"]["victim_pps"], 612)
        self.assertEqual(single["frames"][7]["detector_input"]["source_pps"]["10.0.0.21"], 600)
        self.assertEqual(single["summary"]["alert_count"], 0)
        self.assertEqual(low_rate["frames"][7]["detector_input"]["victim_pps"], 90)
        self.assertEqual(low_rate["summary"]["alert_count"], 0)

    def test_recorded_mode_preserves_original_probe_counts_and_rtts(self):
        result = recorded_data()

        for trial in result["trials"].values():
            with self.subTest(trial=trial["id"]):
                self.assertEqual(trial["summary"]["client"], {"sent": 80, "received": 80})
                self.assertEqual(len(trial["client_probe_rows"]), 80)
                self.assertTrue(all(row["status"] == "ok" and row["rtt_ms"] is not None for row in trial["client_probe_rows"]))
                self.assertTrue(all("raw_sample" in frame for frame in trial["frames"]))

    def test_first_recorded_drop_observation_is_a_baseline_not_zero_rate(self):
        frames = recorded_data()["trials"]["attack_on"]["frames"]
        first_drop = next(frame for frame in frames if frame["raw_sample"].get("drop_packet_total"))
        self.assertFalse(first_drop["drop_rate_available"])
        self.assertIsNone(first_drop["drop_pps"])
        self.assertTrue(any(frame["drop_rate_available"] and (frame["drop_pps"] or 0) > 1000
                            for frame in frames if frame["t_s"] > first_drop["t_s"]))

    def test_static_server_path_resolves_only_named_dashboard_assets(self):
        self.assertEqual(static_asset("/app.js")[0].name, "app.js")
        self.assertEqual(static_asset("/")[0].name, "index.html")
        self.assertEqual(static_asset("/assets/favicon.svg")[0].name, "favicon.svg")
        self.assertEqual(static_asset("/vendor/d3.min.js")[0].name, "d3.min.js")
        self.assertEqual(static_asset("/assets/fonts/fonts.css")[0].name, "fonts.css")
        self.assertEqual(static_asset("/assets/fonts/font-0.ttf")[0].name, "font-0.ttf")
        self.assertEqual(static_asset("/assets/fonts/dmsans-LICENSE.txt")[0].name, "dmsans-LICENSE.txt")

        for url_path in (
            "/../demo/engine.py",
            "/%2e%2e/demo/engine.py",
            "/assets/../index.html",
            "/assets/%2e%2e/index.html",
            "/assets/fonts/%2e%2e/%2e%2e/README.md",
            "/vendor/%2e%2e/%2e%2e/README.md",
            "/assets/%252e%252e%252findex.html",
            "/assets/..%5c..%5cdemo%5cengine.py",
            "/assets/not-a-supported-type.json",
            "/README.md",
        ):
            with self.subTest(path=url_path):
                self.assertIsNone(static_asset(url_path))

        for url_path, expected_type in (
            ("/assets/favicon.svg", "image/svg+xml"),
            ("/vendor/d3.min.js", "text/javascript; charset=utf-8"),
            ("/assets/fonts/fonts.css", "text/css; charset=utf-8"),
            ("/assets/fonts/font-0.ttf", "font/ttf"),
            ("/assets/fonts/dmsans-LICENSE.txt", "text/plain; charset=utf-8"),
        ):
            with self.subTest(mime=url_path):
                source, content_type = static_asset(url_path)
                self.assertEqual(content_type, expected_type)
                self.assertTrue(source.resolve().is_relative_to(DASHBOARD_ROOT.resolve()))

    def test_static_asset_enforces_mime_allowlist_and_resolved_root(self):
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            dashboard = temporary_root / "dashboard"
            assets = dashboard / "assets"
            assets.mkdir(parents=True)
            (assets / "payload.json").write_text("{}", encoding="utf-8")
            (temporary_root / "outside.txt").write_text("private", encoding="utf-8")
            escape = assets / "escape.txt"
            try:
                escape.symlink_to(temporary_root / "outside.txt")
            except OSError:
                escape = None

            with patch("demo.server.DASHBOARD_ROOT", dashboard):
                self.assertIsNone(static_asset("/assets/payload.json"))
                if escape is not None:
                    self.assertIsNone(static_asset("/assets/escape.txt"))


class DashboardServerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), FlowGuardHandler)
        cls.httpd.daemon_threads = True
        cls.httpd.csrf_token = "dashboard-test-token"
        cls.thread = Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_port
        cls.origin = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _request(self, method, path, headers=None, body=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        response_body = response.read()
        status = response.status
        response_headers = response.headers
        connection.close()
        return status, response_body, response_headers

    def test_unknown_host_is_rejected(self):
        status, _, _ = self._request("GET", "/api/bootstrap", {"Host": "attacker.example"})

        self.assertEqual(status, 403)

    def test_probe_post_requires_csrf_token_and_same_origin(self):
        common_headers = {
            "Content-Type": "application/json",
            "Origin": self.origin,
        }
        status, _, _ = self._request("POST", "/api/probe", common_headers, b"{}")
        self.assertEqual(status, 403)

        bad_origin_headers = {
            **common_headers,
            "Origin": "http://attacker.example",
            "X-FlowGuard-CSRF": self.httpd.csrf_token,
        }
        status, _, _ = self._request("POST", "/api/probe", bad_origin_headers, b"{}")
        self.assertEqual(status, 403)

    def test_response_csp_allows_only_local_runtime_assets_and_api(self):
        status, _, headers = self._request("GET", "/")

        self.assertEqual(status, 200)
        policy = headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", policy)
        self.assertIn("img-src 'self'", policy)
        self.assertIn("font-src 'self'", policy)
        self.assertIn("connect-src 'self'", policy)
        self.assertNotIn("https:", policy)

    def test_local_runtime_assets_are_served_with_expected_mime_types(self):
        assets = (
            ("/vendor/d3.min.js", "text/javascript; charset=utf-8"),
            ("/assets/favicon.svg", "image/svg+xml"),
            ("/assets/fonts/fonts.css", "text/css; charset=utf-8"),
            ("/assets/fonts/font-0.ttf", "font/ttf"),
            ("/assets/fonts/dmsans-LICENSE.txt", "text/plain; charset=utf-8"),
        )
        for path, expected_type in assets:
            with self.subTest(path=path):
                status, body, headers = self._request("GET", path)
                self.assertEqual(status, 200)
                self.assertTrue(body)
                self.assertEqual(headers.get("Content-Type"), expected_type)

        status, _, _ = self._request("GET", "/assets/%2e%2e/README.md")
        self.assertEqual(status, 404)


class AdvancedSimulationTests(unittest.TestCase):
    def test_explicit_shipped_options_match_the_defaults(self):
        for scenario in ("normal", "burst", "sustained", "waves", "single-source", "low-rate"):
            with self.subTest(scenario=scenario):
                default = simulate(scenario, mitigation=True)
                explicit = simulate(scenario, mitigation=True, detector="threshold", action="drop",
                                    backoff=False, rate_limit_pps=20)
                self.assertEqual(default["frames"], explicit["frames"])
                self.assertEqual(default["events"], explicit["events"])
                self.assertIsNone(default["frames"][10]["queue_depth_packets"])
                self.assertEqual(default["frames"][10]["detector_state"]["detector"], "threshold")
                self.assertTrue(all(rule["status"] == "modeled drop"
                                    for frame in default["frames"] for rule in frame["active_rules"]))

    def test_rate_limit_passes_burst_then_configured_rate(self):
        result = simulate("sustained", mitigation=True, action="rate_limit")

        self.assertEqual([event["t_s"] for event in _events(result, "ratelimit_requested")], [7, 7, 19, 19])
        # Rules installed at t = 7 apply from the interval [7, 8): the 20-packet
        # burst plus 20 pps in that first second, then 20 pps.
        self.assertEqual(result["frames"][8]["source_delivered_pps"]["10.0.0.21"], 40)
        self.assertEqual(result["frames"][9]["source_delivered_pps"]["10.0.0.21"], 20)
        self.assertEqual(result["frames"][9]["source_dropped_pps"]["10.0.0.21"], 580)
        rule = result["frames"][9]["active_rules"][0]
        self.assertEqual(rule["status"], "modeled rate-limit 20 pps")
        self.assertEqual((rule["action"], rule["rate_pps"], rule["ttl_s"]), ("rate_limit", 20, 10))
        # As in the controller, a source under a rule reads as 0 pps to the detector.
        self.assertEqual(result["frames"][9]["detector_input"]["source_pps"]["10.0.0.21"], 0)
        custom = simulate("sustained", mitigation=True, action="rate_limit", rate_limit_pps=50)
        self.assertEqual(custom["frames"][9]["source_delivered_pps"]["10.0.0.21"], 50)

    def test_graduated_rate_limits_first_and_drops_repeat_offenders(self):
        result = simulate("waves", mitigation=True, action="graduated")
        actions = [(entry["action"], entry["offense_count"])
                   for entry in result["summary"]["rules"] if entry["source"] == "10.0.0.21"]

        self.assertEqual(actions[0], ("rate_limit", 1))
        self.assertGreater(len(actions), 1)
        self.assertTrue(all(action == "drop" for action, count in actions[1:] if count >= 2))

    def test_repeat_offender_backoff_doubles_the_rule_lifetime(self):
        plain = simulate("repeat-offender", mitigation=True)
        backoff = simulate("repeat-offender", mitigation=True, backoff=True)

        def ttls(result):
            return [entry["ttl_s"] for entry in result["summary"]["rules"] if entry["source"] == "10.0.0.21"]

        self.assertEqual(plain["timeline"]["duration_s"], 50)
        self.assertEqual(len(plain["frames"]), 51)
        self.assertEqual(ttls(plain), [10, 10, 10])
        # The second offense gets 20 s (installed at 24 s, active until 44 s), which
        # already covers the whole third wave [39, 44): it is never re-detected.
        self.assertEqual(ttls(backoff), [10, 20])
        self.assertEqual([frame["source_delivered_pps"]["10.0.0.21"] for frame in backoff["frames"][40:45]],
                         [0, 0, 0, 0, 0])
        self.assertEqual(plain["frames"][40]["source_delivered_pps"]["10.0.0.21"], 600)
        self.assertIn("Offense 2.", next(event["message"] for event in _events(backoff, "drop_requested")
                                         if event["t_s"] == 24))

    def test_bottleneck_queue_shows_mitigation_restoring_client_success(self):
        off = simulate("sustained", mitigation=False, pps=2000, queue_packets=50)
        on = simulate("sustained", mitigation=True, pps=2000, queue_packets=50)

        self.assertLess(off["frames"][10]["client_success"], 0.5)
        self.assertEqual(off["frames"][10]["queue_depth_packets"], 50)
        self.assertGreater(off["frames"][10]["queue_drops_pps"], 0)
        self.assertAlmostEqual(off["frames"][10]["queue_delay_ms"], 50.0)
        self.assertEqual(on["frames"][10]["client_success"], 1.0)
        self.assertGreater(on["summary"]["mean_client_success"], off["summary"]["mean_client_success"])
        self.assertEqual(on["summary"]["queue"]["queue_packets"], 50)

    def test_every_detector_runs_every_scenario_and_serializes(self):
        for detector in ("threshold", "ewma", "cusum", "entropy"):
            for scenario in [item["id"] for item in ALL_SCENARIOS]:
                with self.subTest(detector=detector, scenario=scenario):
                    result = simulate(scenario, mitigation=True, detector=detector, action="graduated",
                                      backoff=True, queue_packets=50, noise_seed=7)
                    json.dumps(result, allow_nan=False)
                    self.assertEqual(result["provenance"]["detector"], detector)
                    self.assertIn("Detector", result["provenance"]["label"])
                    self.assertTrue(result["provenance"]["model"].startswith("Model:"))
                    self.assertEqual(result["frames"][-1]["detector_state"]["detector"], detector)

    def test_new_scenarios_shape_the_model(self):
        three = simulate("three-source", mitigation=True)
        self.assertIn("10.0.0.23", three["frames"][6]["source_offered_pps"])
        self.assertEqual(sorted(rule["source"] for rule in three["frames"][9]["active_rules"]),
                         ["10.0.0.21", "10.0.0.22", "10.0.0.23"])
        self.assertEqual(simulate("pulsing", mitigation=True)["summary"]["alert_count"], 0)
        self.assertGreater(simulate("pulsing", mitigation=True, detector="cusum")["summary"]["alert_count"], 0)
        self.assertEqual(simulate("flash-crowd", detector="entropy")["summary"]["alert_count"], 0)

    def test_noise_is_seeded_and_options_are_validated(self):
        self.assertEqual(simulate("sustained", noise_seed=3), simulate("sustained", noise_seed=3))
        self.assertNotEqual(simulate("sustained", noise_seed=3)["frames"], simulate("sustained")["frames"])
        for kwargs in ({"detector": "magic"}, {"action": "nuke"}, {"rate_limit_pps": 0},
                       {"queue_packets": 0}, {"noise_seed": -1}, {"scenario": "unknown"}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    simulate(**kwargs)


class TerminalSectionTests(unittest.TestCase):
    def test_detectors_section_prints_the_committed_benchmark(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["terminal.py", "--section", "detectors"]), redirect_stdout(output):
            self.assertEqual(terminal.main(), 0)
        text = output.getvalue()
        self.assertIn("OFFLINE DETECTOR BENCHMARK", text)
        self.assertIn("pulsing", text)
        self.assertIn("FP 0/20", text)

    def test_bottleneck_section_runs_the_live_lab_comparison(self):
        calls = []

        def fake_run(command, *args, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(sys, "argv", ["terminal.py", "--section", "bottleneck"]), \
                patch.object(terminal, "doctor", return_value={"passed": True}), \
                patch.object(terminal, "live_lab_supports_bottleneck", return_value=True), \
                patch.object(terminal.subprocess, "run", side_effect=fake_run), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(terminal.main(), 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1].endswith("live_lab.py"))
        self.assertEqual(calls[0][2:], ["--bottleneck-pps", "300", "--queue-packets", "50", "--mitigation", "compare"])


if __name__ == "__main__":
    unittest.main()
