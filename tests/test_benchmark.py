"""Detector benchmark: determinism, committed outputs and the qualitative result matrix."""

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from controller.config import load_config
from controller.detectors import build_detector
from demo import engine
from demo.scenarios import SCENARIOS
from experiments import benchmark_detectors as bench

COMMITTED = ROOT / "results" / "benchmarks"


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = bench.run_benchmark(seeds=20, seed_base=1729)
        cls.cells = cls.result["results"]

    def test_same_seed_gives_identical_json(self):
        first = bench.render_all(bench.run_benchmark(seeds=3, seed_base=11, roc=True))
        second = bench.render_all(bench.run_benchmark(seeds=3, seed_base=11, roc=True))
        self.assertEqual(first, second)
        self.assertNotEqual(first, bench.render_all(bench.run_benchmark(seeds=3, seed_base=12, roc=True)))

    def test_committed_outputs_are_current(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bench.main(["--check", "--output", str(COMMITTED)]), 0)
        committed = json.loads((COMMITTED / "detector-benchmark.json").read_text(encoding="utf-8"))
        self.assertEqual(committed["parameters"]["seeds"], 20)
        self.assertTrue(committed["parameters"]["roc"])
        self.assertIn("no network traffic", committed["provenance"]["method"])
        text = json.dumps(committed).lower()
        for wall_clock in ("utc", "timestamp", "generated_at", "date"):
            self.assertNotIn(wall_clock, text)

    def test_latency_frame_matches_engine(self):
        config = {**load_config(), "detector": "threshold"}
        samples = bench.traffic(SCENARIOS["sustained"], seed=None, pps=600)
        run = bench.run_once(build_detector(config), SCENARIOS["sustained"], samples, 2)
        self.assertEqual(run["detection_latency_s"],
                         engine.simulate("sustained", mitigation=False)["summary"]["first_alert_s"]
                         - engine.ATTACK_START_S)

    def test_every_detector_catches_plain_floods_in_two_seconds(self):
        for detector in bench.DETECTOR_NAMES:
            for scenario in ("sustained", "waves", "three-source", "repeat-offender"):
                cell = self.cells[detector][scenario]
                self.assertEqual(cell["detection_rate"], 1.0, (detector, scenario))
                self.assertEqual(cell["median_latency_s"], 2, (detector, scenario))
            for scenario in ("normal", "burst"):
                self.assertEqual(self.cells[detector][scenario]["false_positive_runs"], 0, (detector, scenario))

    def test_threshold_blind_spots_are_closed_by_adaptive_detectors(self):
        threshold = self.cells["threshold"]
        self.assertEqual(threshold["single-source"]["detection_rate"], 0.0)
        self.assertEqual(threshold["pulsing"]["detection_rate"], 0.0)
        # Only Poisson excursions of the 90 pps aggregate over 100 pps trigger it.
        self.assertLess(threshold["low-rate"]["detection_rate"], 0.5)
        for detector in ("ewma", "cusum", "entropy"):
            for scenario in ("single-source", "low-rate"):
                self.assertEqual(self.cells[detector][scenario]["detection_rate"], 1.0, (detector, scenario))

    def test_pulsing_ramp_and_flash_crowd_separate_the_detectors(self):
        self.assertEqual(self.cells["cusum"]["pulsing"]["detection_rate"], 1.0)
        self.assertEqual(self.cells["cusum"]["pulsing"]["median_latency_s"], 3)  # second pulse
        for detector in ("threshold", "ewma", "entropy"):
            self.assertEqual(self.cells[detector]["pulsing"]["detection_rate"], 0.0, detector)
        self.assertEqual(self.cells["cusum"]["ramp"]["detection_rate"], 1.0)
        self.assertLess(self.cells["entropy"]["ramp"]["detection_rate"], 0.5)
        flash = {detector: self.cells[detector]["flash-crowd"]["false_positive_runs"]
                 for detector in bench.DETECTOR_NAMES}
        self.assertEqual(flash["entropy"], 0)
        self.assertEqual(flash["threshold"], 20)
        self.assertEqual(flash["cusum"], 20)
        self.assertGreaterEqual(flash["ewma"], 10)

    def test_source_attribution_never_blames_protected_client(self):
        for detector in bench.DETECTOR_NAMES:
            for scenario_id, scenario in SCENARIOS.items():
                if not scenario.benign:
                    self.assertEqual(self.cells[detector][scenario_id]["source_fp"], 0, (detector, scenario_id))

    def test_roc_sweeps_five_values_per_detector(self):
        roc = bench.run_benchmark(seeds=2, seed_base=1729, roc=True)["roc"]
        self.assertEqual(set(roc), set(bench.DETECTOR_NAMES))
        for detector, curve in roc.items():
            self.assertEqual([point["value"] for point in curve["points"]], list(bench.ROC_KNOBS[detector][1]))
            for point in curve["points"]:
                self.assertTrue(0 <= point["tpr"] <= 1 and 0 <= point["fpr"] <= 1)


if __name__ == "__main__":
    unittest.main()
