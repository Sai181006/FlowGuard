"""Behaviour of the pluggable threshold, EWMA, CUSUM and entropy detectors."""

import json
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller.config import DEFAULTS, LEGACY_KEYS, load_config
from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector
from controller.detectors import (DETECTOR_NAMES, CusumDetector, EntropyDetector, EwmaDetector,
                                  build_detector)
from demo.scenarios import A1, A2, CLIENT, SCENARIOS, VICTIM

CONFIG = load_config()


def detector(name, protected=None):
    return build_detector({**CONFIG, "detector": name}, protected)


def run(det, scenario_id, pps=600, seed=None):
    """Feed a scenario's cumulative counters through CounterTracker; return alert times."""
    scenario = SCENARIOS[scenario_id]
    rng = None if seed is None else random.Random(seed)
    tracker = CounterTracker()
    cumulative = dict.fromkeys(scenario.sources, 0)
    tracker.sample(0, [FlowCounter(source, VICTIM, "t", 0, 0) for source in scenario.sources])
    alerts = []
    for t_s in range(1, scenario.duration_s + 1):
        offered = scenario.offered(t_s - 1, pps, rng)
        for source in scenario.sources:
            cumulative[source] += offered[source]
        rates = tracker.sample(t_s, [FlowCounter(source, VICTIM, "t", cumulative[source], cumulative[source])
                                     for source in scenario.sources])
        alert = det.observe(rates)
        if alert:
            alerts.append((t_s, alert))
    return alerts


def rates(a1=2.0, a2=2.0, client=10.0, **extra):
    source_pps = {A1: a1, A2: a2, CLIENT: client, **extra}
    return {"elapsed_s": 1.0, "source_pps": source_pps, "source_bytes_per_s": {},
            "victim_pps": sum(source_pps.values()), "counter_resets": []}


def warmed(det, windows=5):
    for _ in range(windows):
        det.observe(rates())
    return det


class ThresholdTests(unittest.TestCase):
    def test_build_returns_original_class_with_original_alert(self):
        det = detector("threshold")
        self.assertIs(type(det), TwoWindowDetector)
        self.assertIsNone(det.observe(rates(70, 70)))
        self.assertIsNone(det.observe(rates(2, 2)))
        self.assertIsNone(det.observe(rates(70, 70)))
        alert = det.observe(rates(70, 70))
        self.assertEqual(alert, {"victim_pps": 150.0, "sources": {A1: 70, A2: 70}})
        self.assertEqual([t for t, _ in run(detector("threshold"), "sustained")], [7])
        self.assertEqual(run(detector("threshold"), "single-source"), [])
        self.assertEqual(run(detector("threshold"), "low-rate"), [])


class EwmaTests(unittest.TestCase):
    def test_quiet_and_burst_do_not_alert(self):
        self.assertEqual(run(detector("ewma"), "normal"), [])
        self.assertEqual(run(detector("ewma"), "burst"), [])
        for seed in range(5):
            self.assertEqual(run(detector("ewma"), "normal", seed=seed), [])

    def test_sustained_and_low_rate_alert_after_two_windows(self):
        for scenario in ("sustained", "low-rate", "single-source"):
            alerts = run(detector("ewma"), scenario)
            self.assertEqual([t for t, _ in alerts], [7], scenario)
            self.assertEqual(alerts[0][1]["detector"], "ewma")
            self.assertEqual(set(alerts[0][1]["scores"]), set(alerts[0][1]["sources"]))
        # low-rate stays under the 100 pps victim threshold the fixed detector needs.
        self.assertEqual(run(detector("ewma"), "low-rate")[0][1]["victim_pps"], 90)

    def test_pulsing_is_missed_because_high_windows_never_repeat(self):
        self.assertEqual(run(detector("ewma"), "pulsing"), [])

    def test_baseline_frozen_during_alert_and_episode_rearms(self):
        det = warmed(detector("ewma"))
        before = det.state()["baselines"][A1]
        self.assertIsNone(det.observe(rates(600, 600)))
        self.assertIsNotNone(det.observe(rates(600, 600)))
        self.assertIsNone(det.observe(rates(600, 600)))
        self.assertTrue(det.alert_active)
        self.assertEqual(det.state()["baselines"][A1], before)
        self.assertEqual(set(det.qualifying_sources(rates(600, 0))), {A1})
        self.assertIsNone(det.observe(rates(0, 0)))  # mitigated: condition gone
        self.assertFalse(det.alert_active)
        self.assertIsNone(det.observe(rates(600, 600)))
        self.assertIsNotNone(det.observe(rates(600, 600)))

    def test_source_first_seen_late_starts_from_zero(self):
        det = warmed(detector("ewma"))
        det.observe(rates(**{"10.0.0.23": 500.0}))
        alert = det.observe(rates(**{"10.0.0.23": 500.0}))
        self.assertEqual(set(alert["sources"]), {"10.0.0.23"})

    def test_missing_source_counts_as_zero(self):
        det = warmed(detector("ewma"))
        det.observe({"source_pps": {CLIENT: 10.0}, "victim_pps": 10.0})
        self.assertLess(det.state()["scores"][A1], 0)


class CusumTests(unittest.TestCase):
    def test_sustained_alarms_in_window_two(self):
        det = warmed(detector("cusum"))
        self.assertIsNone(det.observe(rates(600, 600)))
        self.assertEqual(det.state()["cusum"][A1], 3.5)
        alert = det.observe(rates(600, 600))
        self.assertEqual(det.state()["cusum"][A1], 7.0)
        self.assertEqual(alert["scores"], {A1: 7.0, A2: 7.0})
        self.assertEqual(det.high_windows, 2)
        self.assertEqual([t for t, _ in run(detector("cusum"), "sustained")], [7])

    def test_burst_never_alarms_but_pulsing_does_on_second_pulse(self):
        self.assertEqual(run(detector("cusum"), "burst"), [])
        det = warmed(detector("cusum"))
        sequence = []
        for a1 in (600, 2, 600):
            alert = det.observe(rates(a1, a1))
            sequence.append(det.state()["cusum"][A1])
        self.assertEqual(sequence, [3.5, 3.0, 6.5])
        self.assertIsNotNone(alert)
        self.assertEqual(run(detector("cusum"), "pulsing")[0][0], 8)  # pulses start at 5 and 7

    def test_mitigation_decays_statistic_and_clears_alert(self):
        det = warmed(detector("cusum"))
        det.observe(rates(600, 600))
        self.assertIsNotNone(det.observe(rates(600, 600)))
        self.assertIsNone(det.observe(rates(0, 0)))
        self.assertFalse(det.alert_active)
        self.assertEqual(det.state()["cusum"][A1], 5.5)  # z = -1, drift 0.5
        for _ in range(4):
            det.observe(rates(0, 0))
        self.assertEqual(det.state()["cusum"][A1], 0.0)

    def test_noisy_burst_rarely_alarms(self):
        # Residual evidence from background jitter can lift a lone burst over h.
        alarms = sum(bool(run(detector("cusum"), "burst", seed=seed)) for seed in range(200))
        self.assertLess(alarms, 10)


class EntropyTests(unittest.TestCase):
    def test_single_source_and_sustained_alert(self):
        for scenario in ("single-source", "sustained"):
            alerts = run(detector("entropy"), scenario)
            self.assertEqual([t for t, _ in alerts], [7], scenario)
            self.assertEqual(alerts[0][1]["detector"], "entropy")
        self.assertEqual(set(run(detector("entropy"), "single-source")[0][1]["sources"]), {A1})

    def test_flash_crowd_keeps_shares_and_does_not_alert(self):
        self.assertEqual(run(detector("entropy"), "flash-crowd"), [])
        for seed in range(5):
            self.assertEqual(run(detector("entropy"), "flash-crowd", seed=seed), [])

    def test_kl_moves_far_more_than_normalised_entropy(self):
        det = warmed(detector("entropy"))
        quiet = det.state()
        det.observe(rates(600, 600))
        flood = det.state()
        self.assertAlmostEqual(quiet["normalised_entropy"], 0.776, places=3)
        self.assertAlmostEqual(flood["normalised_entropy"], 0.671, places=3)
        self.assertAlmostEqual(flood["kl_bits"], 1.551, places=3)
        self.assertEqual(quiet["kl_bits"], 0.0)

    def test_unsmoothed_numbers_quoted_in_docstring(self):
        params = {**DEFAULTS["detectors"]["entropy"], "smoothing_pps": 1e-9}
        det = warmed(EntropyDetector(params, (CLIENT,)))
        self.assertAlmostEqual(det.state()["normalised_entropy"], 0.725, places=3)
        det.observe(rates(600, 600))
        self.assertAlmostEqual(det.state()["normalised_entropy"], 0.669, places=3)
        self.assertAlmostEqual(det.state()["kl_bits"], 1.727, places=3)


class SharedInterfaceTests(unittest.TestCase):
    def test_protected_sources_are_never_offenders(self):
        for name in DETECTOR_NAMES:
            det = detector(name, protected=(A1, CLIENT))
            self.assertEqual(run(det, "single-source"), [], name)
            self.assertNotIn(A1, det.qualifying_sources(rates(600, 600)), name)
            self.assertEqual(det.protected_sources, frozenset({A1, CLIENT}))

    def test_state_and_reset_are_json_safe(self):
        for name in DETECTOR_NAMES:
            det = detector(name)
            fresh = json.dumps(det.state(), sort_keys=True, allow_nan=False)
            run(det, "waves", seed=3)
            json.dumps(det.state(), allow_nan=False)
            self.assertEqual(det.state()["detector"], name)
            det.reset()
            self.assertFalse(det.alert_active)
            self.assertEqual(det.high_windows, 0)
            if name != "threshold":
                self.assertEqual(json.dumps(det.state(), sort_keys=True), fresh)

    def test_build_each_name_from_effective_and_legacy_config(self):
        legacy = {key: CONFIG[key] for key in LEGACY_KEYS}
        classes = {"threshold": TwoWindowDetector, "ewma": EwmaDetector,
                   "cusum": CusumDetector, "entropy": EntropyDetector}
        for name in DETECTOR_NAMES:
            self.assertIs(type(detector(name)), classes[name])
            built = build_detector({**legacy, "detector": name})
            self.assertEqual(built.name, name)
            self.assertEqual(built.protected_sources, frozenset(CONFIG["protected_sources"]))
            self.assertEqual([t for t, _ in run(built, "sustained")], [7])
        self.assertIs(type(build_detector(legacy)), TwoWindowDetector)
        partial = {**legacy, "detector": "cusum", "detectors": {"cusum": {"threshold_h": 2.0}}}
        self.assertEqual(build_detector(partial).threshold_h, 2.0)
        self.assertEqual(build_detector(partial).drift_k, DEFAULTS["detectors"]["cusum"]["drift_k"])
        with self.assertRaises(ValueError):
            build_detector({**legacy, "detector": "magic"})

    def test_counter_reset_window_leaves_baseline_untouched(self):
        for name in ("ewma", "cusum"):
            det = warmed(detector(name))
            before = det.state()["baselines"][A1]
            sample = rates(a1=0.0)
            del sample["source_pps"][A1]
            sample["counter_resets"] = [A1]
            det.observe(sample)
            self.assertEqual(det.state()["baselines"][A1], before, name)


if __name__ == "__main__":
    unittest.main()
