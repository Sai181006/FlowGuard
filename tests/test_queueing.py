import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.queueing import BottleneckQueue, FluidQueue, red_defaults  # noqa: E402


def exact(service_pps, capacity, **options):
    """A queue whose missed service is never capped, for pure timing arithmetic."""
    return BottleneckQueue(service_pps, capacity, max_catch_up_s=math.inf, **options)


class BottleneckQueueTests(unittest.TestCase):
    def test_fifo_order_and_deterministic_departures(self):
        queue = exact(100, 10)
        for item in "abc":
            self.assertEqual(queue.offer(item, 0.0), "enqueued")
        self.assertEqual(queue.depth, 3)
        self.assertEqual(queue.due(0.005), [])
        first = queue.due(0.015)
        self.assertEqual([item for item, _ in first], ["a"])
        self.assertAlmostEqual(first[0][1], 0.01)
        rest = queue.due(0.035)
        self.assertEqual([item for item, _ in rest], ["b", "c"])
        self.assertAlmostEqual(rest[0][1], 0.02)
        self.assertAlmostEqual(rest[1][1], 0.03)
        self.assertEqual(queue.depth, 0)

    def test_tail_drop_at_capacity(self):
        queue = exact(10, 3)
        outcomes = [queue.offer(index, 0.0) for index in range(5)]
        self.assertEqual(outcomes, ["enqueued"] * 3 + ["tail_drop"] * 2)
        self.assertEqual(queue.depth, 3)
        # One departure frees one slot.
        self.assertEqual(len(queue.due(0.1)), 1)
        self.assertEqual(queue.offer("late", 0.1), "enqueued")
        stats = queue.stats()
        self.assertEqual((stats["enqueued"], stats["tail_drops"], stats["max_depth"]), (4, 2, 3))

    def test_delay_includes_waiting_behind_backlog(self):
        queue = exact(50, 100)
        for index in range(10):
            queue.offer(index, 0.0)
        released = queue.due(1.0)
        self.assertEqual([item for item, _ in released], list(range(10)))
        for index, (_, delay) in enumerate(released):
            self.assertAlmostEqual(delay, (index + 1) / 50)
        self.assertAlmostEqual(queue.stats()["delay_ms"]["max"], 200.0)

    def test_idle_link_restarts_service_from_the_arrival(self):
        queue = exact(100, 10)
        queue.offer("first", 0.0)
        self.assertEqual(len(queue.due(0.5)), 1)
        queue.offer("second", 5.0)
        self.assertEqual(queue.due(5.005), [])
        (item, delay), = queue.due(5.01)
        self.assertEqual(item, "second")
        self.assertAlmostEqual(delay, 0.01)

    def test_scheduler_stall_releases_only_capped_catch_up(self):
        queue = BottleneckQueue(64, 100, max_catch_up_s=1 / 32)  # exact binary fractions
        for index in range(50):
            queue.offer(index, 0.0)
        # 10 s without service: only 1/32 s of credit (two intervals) plus the head leave.
        self.assertEqual(len(queue.due(10.0)), 3)
        self.assertEqual(queue.depth, 47)

    def test_overload_drops_the_excess_and_delay_is_queue_over_rate(self):
        queue = BottleneckQueue(300, 50)
        arrivals, outcomes, t = 1210, [], 0.0
        for step in range(2000):  # 2 s in 1 ms event-loop steps
            now = step / 1000
            while t <= now:
                outcomes.append(queue.offer(len(outcomes), t))
                t += 1 / arrivals
            queue.due(now)
        steady = outcomes[200:]  # after the queue has filled
        drop_fraction = steady.count("tail_drop") / len(steady)
        self.assertAlmostEqual(drop_fraction, 1 - 300 / arrivals, delta=0.03)
        self.assertAlmostEqual(queue.stats()["delay_ms"]["p95"], 1000 * 50 / 300, delta=4)

    def test_red_drops_begin_between_thresholds_and_are_seeded(self):
        params = {"min_th": 5, "max_th": 15, "max_p": 0.1, "w_q": 0.2}

        def run(seed):
            queue = BottleneckQueue(1, 1000, "red", params, seed=seed)  # due() never called
            history = []
            for index in range(80):
                avg_before = queue.avg
                outcome = queue.offer(index, 0.0)
                history.append((outcome, avg_before, queue.avg))
            return queue, history

        queue, history = run(7)
        drops = [entry for entry in history if entry[0] == "red_drop"]
        self.assertTrue(drops)
        self.assertEqual(queue.tail_drops, 0)
        # No early drop while the average is below min_th ...
        self.assertTrue(all(entry[0] == "enqueued" for entry in history if entry[2] < 5))
        # ... the first drops are probabilistic, between the thresholds ...
        self.assertTrue(5 <= drops[0][2] < 15, drops[0])
        # ... and every arrival is dropped once the average reaches max_th.
        self.assertTrue(all(entry[0] == "red_drop" for entry in history if entry[2] >= 15))
        self.assertEqual(history, run(7)[1])

    def test_red_average_decays_while_idle_and_tail_drop_still_applies(self):
        queue = BottleneckQueue(100, 50, "red", {"min_th": 5, "max_th": 15, "max_p": 0.1, "w_q": 0.2})
        for index in range(12):
            queue.offer(index, 0.0)
        self.assertGreater(queue.avg, 5)
        for step in range(1, 400):
            queue.due(step / 1000)
        self.assertEqual(queue.depth, 0)
        queue.offer("after-idle", 10.0)
        self.assertLess(queue.avg, 1e-6)
        small = BottleneckQueue(10, 5, "red", red_defaults(50))  # thresholds above the capacity
        outcomes = [small.offer(index, 0.0) for index in range(7)]
        self.assertEqual(outcomes.count("tail_drop"), 2)
        self.assertEqual(small.red_drops, 0)

    def test_red_defaults_scale_with_capacity(self):
        self.assertEqual(red_defaults(50), {"min_th": 10.0, "max_th": 30.0, "max_p": 0.1, "w_q": 0.02})

    def test_invalid_parameters(self):
        for args in ((0, 10), (100, 0), (100, 10, "wfq")):
            with self.assertRaises(ValueError):
                BottleneckQueue(*args)
        with self.assertRaises(ValueError):
            BottleneckQueue(100, 10, "red", {"min_th": 20, "max_th": 10})
        with self.assertRaises(ValueError):
            BottleneckQueue(100, 10, "red", {"bogus": 1})


class FluidQueueTests(unittest.TestCase):
    def test_backlog_overflow_and_mean_delay(self):
        fluid = FluidQueue()
        first = fluid.step(500, 300, 50)
        self.assertEqual((first["depth"], first["drops"]), (50, 150))
        self.assertAlmostEqual(first["delay_ms"], 1000 * 25 / 300)
        self.assertAlmostEqual(first["served"], 300)
        second = fluid.step(500, 300, 50)
        self.assertEqual((second["depth"], second["drops"]), (50, 200))
        self.assertAlmostEqual(second["delay_ms"], 1000 * 50 / 300)
        drained = fluid.step(0, 300, 50)
        self.assertEqual((drained["depth"], drained["drops"], drained["served"]), (0, 0, 50))
        self.assertAlmostEqual(drained["delay_ms"], 1000 * 25 / 300)

    def test_short_interval_and_underload(self):
        fluid = FluidQueue()
        result = fluid.step(10, 300, 50, dt=0.1)
        self.assertEqual((result["depth"], result["drops"], result["delay_ms"]), (0, 0, 0))
        with self.assertRaises(ValueError):
            fluid.step(10, 0, 50)


if __name__ == "__main__":
    unittest.main()
