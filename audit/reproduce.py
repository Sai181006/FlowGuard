"""Run current security and experiment-integrity regression suites."""

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
RESULT_PATH = ROOT / "audit/reproductions.json"


def run_suite(patterns):
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    for pattern in patterns:
        suite.addTests(loader.discover(str(TESTS), pattern=pattern))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return {
        "status": "passed" if result.wasSuccessful() else "failed",
        "tests_run": result.testsRun,
        "failures": [
            {"test": test.id(), "details": details.strip()}
            for test, details in (*result.failures, *result.errors)
        ],
    }


def main():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    checks = {
        "security": run_suite(("test_forwarding.py", "test_demo_engine.py")),
        "experiment_integrity": run_suite(("test_experiments.py", "test_qdisc_monitor.py",
                                           "test_topology.py")),
        "advanced_networking": run_suite((
            "test_config.py", "test_detectors.py", "test_mitigation_primitives.py", "test_meters.py",
            "test_queueing.py", "test_live_lab.py", "test_probe_protocol.py", "test_probe_cli.py",
            "test_scenarios.py", "test_benchmark.py", "test_wireshark_dissector.py")),
    }
    total_tests = sum(check["tests_run"] for check in checks.values())
    report = {
        "status": "passed" if all(check["status"] == "passed" for check in checks.values()) else "failed",
        "purpose": "Current regression checks verify hardening and experiment-integrity behavior.",
        "historical_note": (
            "The original audit proofs describe the earlier upstream code and are preserved in "
            "audit/reproductions-original.json."
        ),
        "scope": ("Mocked OpenFlow messages (real OS-Ken serializer), saved experiment artifacts, local dashboard "
                  "HTTP checks, and bounded localhost UDP for the native lab and probe tests; no live switch, "
                  "kernel qdisc or Wireshark."),
        "checks": checks,
        "total_tests": total_tests,
    }
    rendered = json.dumps(report, indent=2) + "\n"
    RESULT_PATH.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
