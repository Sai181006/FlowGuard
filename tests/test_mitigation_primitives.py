import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller.mitigation import OffenderHistory, TokenBucket, choose_action  # noqa: E402


class TokenBucketTests(unittest.TestCase):
    def test_burst_then_steady_rate(self):
        bucket = TokenBucket(rate_pps=10, burst=5, now=0.0)
        self.assertEqual(sum(bucket.allow(0.0) for _ in range(20)), 5)
        self.assertFalse(bucket.allow(0.05))
        self.assertTrue(bucket.allow(0.1))
        # One second at 10 tokens/s, capped at the burst size.
        self.assertAlmostEqual(bucket.tokens(1.1), 5.0)

    def test_long_run_admits_rate_plus_burst(self):
        bucket = TokenBucket(rate_pps=20, burst=20, now=0.0)
        admitted = sum(bucket.allow(i / 600) for i in range(600 * 5))  # 600 pps for 5 s
        self.assertTrue(20 * 5 + 20 - 1 <= admitted <= 20 * 5 + 20 + 1, admitted)

    def test_clock_stepping_backwards_adds_nothing(self):
        bucket = TokenBucket(rate_pps=10, burst=1, now=5.0)
        self.assertTrue(bucket.allow(5.0))
        self.assertFalse(bucket.allow(4.0))
        self.assertFalse(bucket.allow(5.0))

    def test_zero_burst_still_admits_single_packets(self):
        bucket = TokenBucket(rate_pps=2, burst=0, now=0.0)
        self.assertTrue(bucket.allow(0.0))
        self.assertFalse(bucket.allow(0.1))
        self.assertTrue(bucket.allow(0.6))

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            TokenBucket(0, 1, 0.0)
        with self.assertRaises(ValueError):
            TokenBucket(1, -1, 0.0)


class OffenderHistoryTests(unittest.TestCase):
    def test_exponential_backoff_with_cap(self):
        history = OffenderHistory(10, factor=2.0, max_timeout_s=80, memory_s=120, enabled=True)
        timeouts = []
        now = 0.0
        for _ in range(5):
            count, timeout = history.next_offense("10.0.0.21", now)
            timeouts.append((count, timeout))
            now += timeout + 5
        self.assertEqual(timeouts, [(1, 10), (2, 20), (3, 40), (4, 80), (5, 80)])

    def test_history_is_forgotten_after_memory(self):
        history = OffenderHistory(10, enabled=True, memory_s=120)
        history.next_offense("10.0.0.21", 0.0)
        self.assertEqual(history.next_offense("10.0.0.21", 10.0 + 121), (1, 10))

    def test_disabled_backoff_keeps_base_timeout_but_counts(self):
        history = OffenderHistory(10, enabled=False)
        self.assertEqual(history.next_offense("10.0.0.22", 0.0), (1, 10))
        self.assertEqual(history.next_offense("10.0.0.22", 15.0), (2, 10))
        self.assertEqual(history.offense_count("10.0.0.21"), 0)

    def test_from_config(self):
        config = {"mitigation_hard_timeout_s": 10,
                  "mitigation": {"backoff": {"enabled": True, "factor": 3.0, "max_timeout_s": 60,
                                             "memory_s": 30}}}
        history = OffenderHistory.from_config(config)
        self.assertEqual([history.next_offense("s", t)[1] for t in (0, 11, 42)], [10, 30, 60])


class ChooseActionTests(unittest.TestCase):
    def test_policy_table(self):
        self.assertEqual(choose_action("drop", 1), "drop")
        self.assertEqual(choose_action("rate_limit", 5), "rate_limit")
        self.assertEqual(choose_action("graduated", 1, 2), "rate_limit")
        self.assertEqual(choose_action("graduated", 2, 2), "drop")
        self.assertEqual(choose_action("graduated", 2, 3), "rate_limit")
        with self.assertRaises(ValueError):
            choose_action("nope", 1)


if __name__ == "__main__":
    unittest.main()
