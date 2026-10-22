"""HTTP checks for the dashboard's advanced simulation options and the offline benchmark."""

import json
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread

from demo.server import FlowGuardHandler

EXPECTED_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)


class DashboardApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), FlowGuardHandler)
        cls.httpd.daemon_threads = True
        cls.httpd.csrf_token = "dashboard-api-test-token"
        cls.thread = Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_port

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _request(self, method, path, headers=None, body=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, json.loads(payload) if payload else None, response.headers

    def _get(self, path, headers=None):
        return self._request("GET", path, headers)

    def test_bootstrap_lists_detectors_actions_queue_and_every_scenario(self):
        status, data, _ = self._get("/api/bootstrap")

        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in data["detectors"]], ["threshold", "ewma", "cusum", "entropy"])
        self.assertEqual([item["id"] for item in data["mitigation_actions"]], ["drop", "rate_limit", "graduated"])
        self.assertEqual(data["queue_defaults"]["queue_packets"], 50)
        ids = [item["id"] for item in data["scenarios"]]
        self.assertEqual(ids[:6], ["normal", "burst", "sustained", "waves", "single-source", "low-rate"])
        for scenario in ("pulsing", "ramp", "flash-crowd", "three-source", "repeat-offender"):
            self.assertIn(scenario, ids)
        self.assertEqual(data["scenario_durations_s"]["repeat-offender"], 50)
        self.assertEqual(data["simulation_defaults"]["detector"], "threshold")
        self.assertEqual(data["provenance"]["offline_benchmark"]["kind"], "offline_benchmark")

    def test_simulation_accepts_allow_listed_options(self):
        status, data, _ = self._get(
            "/api/simulation?scenario=repeat-offender&detector=cusum&action=graduated&backoff=1"
            "&rate_limit=30&queue=50&mitigation=1")

        self.assertEqual(status, 200)
        self.assertEqual(data["parameters"]["detector"], "cusum")
        self.assertEqual(data["parameters"]["action"], "graduated")
        self.assertTrue(data["parameters"]["backoff"])
        self.assertEqual(data["parameters"]["rate_limit_pps"], 30)
        self.assertEqual(data["parameters"]["queue_packets"], 50)
        self.assertEqual(data["timeline"]["duration_s"], 50)
        self.assertEqual(data["provenance"]["detector_class"], "CusumDetector")
        self.assertIsNotNone(data["frames"][10]["queue_depth_packets"])

    def test_queue_zero_means_off(self):
        status, data, _ = self._get("/api/simulation?scenario=sustained&queue=0")

        self.assertEqual(status, 200)
        self.assertIsNone(data["parameters"]["queue_packets"])
        self.assertIsNone(data["frames"][10]["queue_depth_packets"])

    def test_simulation_rejects_unknown_or_out_of_range_options(self):
        for query in ("detector=magic", "action=nuke", "backoff=maybe", "rate_limit=0", "rate_limit=abc",
                      "queue=3", "queue=20000", "detector=ewma&detector=cusum", "scenario=unknown"):
            with self.subTest(query=query):
                status, data, _ = self._get("/api/simulation?" + query)
                self.assertEqual(status, 400)
                self.assertIn("error", data)

    def test_benchmark_is_served_read_only_with_provenance(self):
        status, data, headers = self._get("/api/benchmark")

        self.assertEqual(status, 200)
        self.assertEqual(data["mode"], "offline_benchmark")
        self.assertEqual(data["provenance"]["kind"], "offline_benchmark")
        self.assertEqual(data["provenance"]["label"], "Simulated scenarios, real detector code.")
        self.assertEqual(data["benchmark"]["detectors"], ["threshold", "ewma", "cusum", "entropy"])
        self.assertIn("pulsing", data["benchmark"]["results"]["cusum"])
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        status, _, _ = self._request("POST", "/api/benchmark", {"Origin": f"http://127.0.0.1:{self.port}"}, b"{}")
        self.assertEqual(status, 403)

    def test_security_headers_and_host_check_are_unchanged(self):
        for path in ("/", "/api/benchmark", "/api/simulation?detector=ewma"):
            with self.subTest(path=path):
                connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
                connection.request("GET", path)
                response = connection.getresponse()
                response.read()
                connection.close()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers.get("Content-Security-Policy"), EXPECTED_CSP)
                self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
                status, _, _ = self._get(path if path.startswith("/api") else "/api/bootstrap",
                                         {"Host": "attacker.example"})
                self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
