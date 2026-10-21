from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from demo.engine import recorded_data, simulate
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

if __name__ == "__main__":
    unittest.main()
