"""Behavioral checks for counter resets, missing flows and alerts."""

import unittest

from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector


def flow(source, packets, bytes_=None, identity="flow"):
    return FlowCounter(source, "10.0.0.10", identity, packets, packets * 80 if bytes_ is None else bytes_)


class CounterTrackerTests(unittest.TestCase):
    def test_first_missing_and_reset_samples_do_not_spike(self):
        tracker = CounterTracker()
        self.assertEqual(tracker.sample(1, [flow("10.0.0.21", 100)])["victim_pps"], 0)
        self.assertAlmostEqual(tracker.sample(2, [flow("10.0.0.21", 140)])["victim_pps"], 40)
        self.assertEqual(tracker.sample(3, [])["victim_pps"], 0)
        self.assertEqual(tracker.sample(4, [flow("10.0.0.21", 2)])["victim_pps"], 0)
        self.assertEqual(tracker.sample(5, [flow("10.0.0.21", 1)])["victim_pps"], 0)
        self.assertEqual(tracker.sample(6, [flow("10.0.0.21", 20)])["victim_pps"], 19)
        tracker.reset()
        self.assertEqual(tracker.sample(7, [flow("10.0.0.21", 500)])["victim_pps"], 0)

    def test_sources_aggregate_without_mixing_destinations(self):
        tracker = CounterTracker()
        initial = [flow("10.0.0.21", 10, identity="a"), flow("10.0.0.21", 2, identity="b")]
        tracker.sample(1, initial)
        rates = tracker.sample(2, [flow("10.0.0.21", 30, identity="a"), flow("10.0.0.21", 12, identity="b")])
        self.assertEqual(rates["source_pps"], {"10.0.0.21": 30})


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = TwoWindowDetector(100, 30, protected_sources=("10.0.0.11",))

    def rates(self, a1=0, a2=0, client=0):
        source_pps = {"10.0.0.21": a1, "10.0.0.22": a2, "10.0.0.11": client}
        return {"source_pps": source_pps, "victim_pps": sum(source_pps.values())}

    def test_burst_does_not_alert_and_attack_alerts_once(self):
        self.assertIsNone(self.detector.observe(self.rates(70, 70)))
        self.assertIsNone(self.detector.observe(self.rates(2, 2)))
        self.assertIsNone(self.detector.observe(self.rates(70, 70)))
        alert = self.detector.observe(self.rates(70, 70))
        self.assertEqual(set(alert["sources"]), {"10.0.0.21", "10.0.0.22"})
        self.assertIsNone(self.detector.observe(self.rates(70, 70)))
        self.detector.observe(self.rates(1, 1))
        self.assertIsNone(self.detector.observe(self.rates(70, 70)))
        self.assertIsNotNone(self.detector.observe(self.rates(70, 70)))

    def test_protected_client_cannot_be_second_source(self):
        self.assertIsNone(self.detector.observe(self.rates(80, 0, 80)))
        self.assertIsNone(self.detector.observe(self.rates(80, 0, 80)))


if __name__ == "__main__":
    unittest.main()
