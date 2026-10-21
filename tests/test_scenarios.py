"""Scenario catalogue: parity with demo.engine and shapes of the new patterns."""

import random
import statistics
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo import engine
from demo.scenarios import (A1, A2, A3, CLIENT, DASHBOARD_SCENARIOS, SCENARIOS, Scenario,
                            poisson)

ORIGINAL = [item["id"] for item in engine.SCENARIOS]


class EngineParityTests(unittest.TestCase):
    def test_original_scenarios_match_engine_every_second(self):
        self.assertEqual(ORIGINAL, list(SCENARIOS)[:6])
        for scenario_id in ORIGINAL:
            scenario = SCENARIOS[scenario_id]
            for pps in (1, 37, 600, 5000):
                for t in range(engine.DURATION_S + 1):
                    expected = engine._offered_rates(scenario_id, t, t + 1, pps)
                    self.assertEqual(scenario.offered(t, pps), expected, (scenario_id, pps, t))
                    self.assertEqual(scenario.is_active(t), engine._is_attack_active(scenario_id, t, t + 1))

    def test_dashboard_entries_extend_engine_list(self):
        self.assertEqual(list(DASHBOARD_SCENARIOS[:6]), list(engine.SCENARIOS))
        self.assertEqual([item["id"] for item in DASHBOARD_SCENARIOS], list(SCENARIOS))
        for item in DASHBOARD_SCENARIOS:
            self.assertEqual(set(item), {"id", "label", "description"})


class NewScenarioTests(unittest.TestCase):
    def test_pulsing_alternates_seconds(self):
        pulsing = SCENARIOS["pulsing"]
        self.assertEqual([t for t in range(30) if pulsing.is_active(t)], list(range(5, 25, 2)))
        self.assertEqual(pulsing.offered(5, 600)[A1], 600)
        self.assertEqual(pulsing.offered(6, 600), {A1: 2, A2: 2, CLIENT: 10})

    def test_ramp_is_linear_low_and_slow(self):
        ramp = [SCENARIOS["ramp"].offered(t, 600)[A1] for t in range(5, 25)]
        self.assertEqual((ramp[0], ramp[-1]), (5, 150))
        self.assertTrue(all(0 < b - a < 9 for a, b in zip(ramp, ramp[1:])))
        self.assertEqual(SCENARIOS["ramp"].offered(25, 600)[A1], 2)

    def test_flash_crowd_scales_everyone_and_keeps_shares(self):
        flash = SCENARIOS["flash-crowd"]
        self.assertTrue(flash.benign)
        self.assertFalse(flash.attackers)
        quiet, peak = flash.offered(0, 600), flash.offered(12, 600)
        self.assertEqual(peak, {source: rate * 20 for source, rate in quiet.items()})
        for t in range(30):
            rates = flash.offered(t, 600)
            self.assertAlmostEqual(rates[CLIENT] / sum(rates.values()), 10 / 16, delta=0.02)
        steps = [sum(flash.offered(t, 600).values()) for t in range(4, 11)]
        self.assertEqual(steps, sorted(steps))

    def test_three_source_and_repeat_offender(self):
        three = SCENARIOS["three-source"]
        self.assertEqual(three.attackers, {A1, A2, A3})
        self.assertEqual(three.offered(10, 400), {A1: 400, A2: 400, A3: 400, CLIENT: 10})
        repeat = SCENARIOS["repeat-offender"]
        self.assertEqual(repeat.duration_s, 50)
        self.assertEqual(repeat.attack_intervals, ((5, 10), (22, 27), (39, 44)))
        self.assertTrue(repeat.is_active(43) and not repeat.is_active(44))
        with_a3 = {sid for sid, scenario in SCENARIOS.items() if A3 in scenario.sources}
        self.assertEqual(with_a3, {"flash-crowd", "three-source"})

    def test_scenarios_are_frozen(self):
        with self.assertRaises(Exception):
            SCENARIOS["normal"].benign = False
        self.assertIsInstance(SCENARIOS["normal"], Scenario)


class NoiseTests(unittest.TestCase):
    def test_poisson_is_seeded_and_unbiased(self):
        self.assertEqual(poisson(random.Random(1), 0), 0)
        for lam in (2, 10, 40, 600):
            first = [poisson(random.Random(7), lam) for _ in range(3)]
            self.assertEqual(first, [poisson(random.Random(7), lam) for _ in range(3)])
            rng = random.Random(lam)
            draws = [poisson(rng, lam) for _ in range(4000)]
            self.assertAlmostEqual(statistics.fmean(draws), lam, delta=0.05 * lam + 0.1)
            self.assertAlmostEqual(statistics.pvariance(draws), lam, delta=0.15 * lam + 0.3)
            self.assertTrue(all(draw >= 0 for draw in draws))

    def test_noisy_offered_rates_are_reproducible(self):
        scenario = SCENARIOS["sustained"]
        first = [scenario.offered(t, 600, rng) for rng in [random.Random(3)] for t in range(30)]
        second = [scenario.offered(t, 600, rng) for rng in [random.Random(3)] for t in range(30)]
        self.assertEqual(first, second)
        self.assertNotEqual(first, [scenario.offered(t, 600) for t in range(30)])
        self.assertEqual(set(first[10]), {A1, A2, CLIENT})


if __name__ == "__main__":
    unittest.main()
