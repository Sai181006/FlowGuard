"""Bottleneck queue models used by the native lab and the simulation engine.

BottleneckQueue is a packet queue with deterministic (D/1) service: one packet
leaves every 1/service_pps seconds while the queue is busy. The native
localhost lab uses it as an emulated egress link inside the Python gateway, so
a flood can congest the path to the victim the way a slow access link would.
It is a model in userspace, not a kernel qdisc or a NIC queue.

Disciplines:
  fifo  drop-tail: an arrival that finds `capacity_packets` queued is dropped.
  red   Random Early Detection (Floyd and Jacobson, 1993). Each arrival updates
        an EWMA of the queue length, avg <- (1 - w_q) avg + w_q q. After an idle
        period the average decays as avg <- (1 - w_q)^m avg, where m is the
        number of packets the link could have sent while idle. Below min_th
        nothing is dropped; at or above max_th every arrival is dropped; in
        between the drop probability is
            p_b = max_p (avg - min_th) / (max_th - min_th)
            p_a = p_b / (1 - count p_b)
        where count is the number of packets since the last drop, which spreads
        drops out evenly. Tail drop still applies at capacity.

The textbook weight w_q = 0.002 suits router queues of hundreds of packets. For
a 50-packet queue it reacts too slowly: about 1/w_q = 500 arrivals pass before
the average follows the real queue, so the queue would overflow (tail drop)
long before RED acts. The default here is w_q = 0.02 (about 50 arrivals).

FluidQueue is the per-interval fluid approximation used by the simulation
engine: B' = clamp(B + A - C dt, 0, Q); the overflow is dropped and the
reported delay uses the mean backlog over the interval.

Stdlib only; the offline dashboard runs with `python -S`.
"""

from __future__ import annotations

import math
import random
from collections import deque


DISCIPLINES = ("fifo", "red")
RED_DEFAULTS = {"min_th": 10.0, "max_th": 30.0, "max_p": 0.1, "w_q": 0.02}
MAX_CATCH_UP_S = 0.02
_MAX_DELAY_SAMPLES = 200_000


def red_defaults(capacity_packets):
    """RED thresholds scaled to the queue: 20% and 60% of capacity (10 and 30 for 50)."""
    return {**RED_DEFAULTS, "min_th": 0.2 * capacity_packets, "max_th": 0.6 * capacity_packets}


def _percentile(values, p):
    """Nearest-rank percentile, the same rule the probe metrics use; None if empty."""
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, math.ceil(round(p * len(ordered) / 100, 9)))
    return ordered[rank - 1]


class BottleneckQueue:
    """Finite packet queue served at a constant rate (D/1), FIFO or RED."""

    def __init__(self, service_pps, capacity_packets, discipline="fifo", red=None, seed=0,
                 max_catch_up_s=MAX_CATCH_UP_S):
        if not (isinstance(service_pps, (int, float)) and math.isfinite(service_pps) and service_pps > 0):
            raise ValueError("service_pps must be a positive number")
        if isinstance(capacity_packets, bool) or not isinstance(capacity_packets, int) or capacity_packets < 1:
            raise ValueError("capacity_packets must be a positive integer")
        if discipline not in DISCIPLINES:
            raise ValueError(f"discipline must be one of: {', '.join(DISCIPLINES)}")
        self.service_pps = float(service_pps)
        self.service_s = 1.0 / self.service_pps
        self.capacity = capacity_packets
        self.discipline = discipline
        self.max_catch_up_s = float(max_catch_up_s)
        self.red = None
        if discipline == "red":
            params = {**red_defaults(capacity_packets), **(red or {})}
            unknown = params.keys() - RED_DEFAULTS.keys()
            if unknown:
                raise ValueError(f"unknown RED parameters: {', '.join(sorted(unknown))}")
            if not 0 <= params["min_th"] < params["max_th"]:
                raise ValueError("RED needs 0 <= min_th < max_th")
            if not 0 < params["max_p"] <= 1 or not 0 < params["w_q"] <= 1:
                raise ValueError("RED max_p and w_q must be in (0, 1]")
            self.red = {key: float(value) for key, value in params.items()}
        self._random = random.Random(seed)
        self._items = deque()  # (item, arrival time)
        self._next_departure = None  # scheduled departure of the head packet
        self._idle_since = None
        self.avg = 0.0
        self._count = -1  # RED: packets since the last drop (-1 = not in the drop region)
        self.enqueued = self.dequeued = self.tail_drops = self.red_drops = 0
        self.max_depth = 0
        self._delays = []

    @property
    def depth(self):
        """Packets in the system, including the one being transmitted."""
        return len(self._items)

    def _red_decision(self, now):
        red = self.red
        depth = len(self._items)
        if depth:
            self.avg = (1 - red["w_q"]) * self.avg + red["w_q"] * depth
        elif self._idle_since is not None:
            idle_packets = max(0.0, now - self._idle_since) * self.service_pps
            self.avg *= (1 - red["w_q"]) ** idle_packets
        if self.avg < red["min_th"]:
            self._count = -1
            return False
        if self.avg >= red["max_th"]:
            self._count = 0
            return True
        self._count += 1
        p_b = red["max_p"] * (self.avg - red["min_th"]) / (red["max_th"] - red["min_th"])
        denominator = 1 - self._count * p_b
        p_a = 1.0 if denominator <= 0 else min(1.0, p_b / denominator)
        if self._random.random() < p_a:
            self._count = 0
            return True
        return False

    def offer(self, item, now):
        """Admit one arrival: return "enqueued", "tail_drop" or "red_drop"."""
        if self.red is not None and self._red_decision(now):
            self.red_drops += 1
            return "red_drop"
        if len(self._items) >= self.capacity:
            self.tail_drops += 1
            return "tail_drop"
        if not self._items:
            # The link is idle: transmission of this packet starts now.
            self._next_departure = now + self.service_s
        self._items.append((item, now))
        self.enqueued += 1
        self.max_depth = max(self.max_depth, len(self._items))
        return "enqueued"

    def due(self, now):
        """Release packets whose departure time has passed; return [(item, delay_s)].

        Departures are spaced exactly 1/service_pps apart. If the caller was not
        scheduled for a while, at most `max_catch_up_s` of missed service is made
        up, so a stalled event loop cannot release a large burst at once.
        """
        released = []
        if not self._items:
            return released
        if self._next_departure < now - self.max_catch_up_s:
            self._next_departure = now - self.max_catch_up_s
        while self._items and self._next_departure <= now:
            item, arrived = self._items.popleft()
            delay = max(0.0, self._next_departure - arrived)
            released.append((item, delay))
            self.dequeued += 1
            if len(self._delays) < _MAX_DELAY_SAMPLES:
                self._delays.append(delay)
            if self._items:
                self._next_departure += self.service_s
            else:
                self._idle_since = self._next_departure
        return released

    def stats(self):
        def ms(value):
            return None if value is None else round(value * 1000, 3)

        return {"enqueued": self.enqueued, "dequeued": self.dequeued,
                "tail_drops": self.tail_drops, "red_drops": self.red_drops,
                "max_depth": self.max_depth,
                "delay_ms": {"p50": ms(_percentile(self._delays, 50)),
                             "p95": ms(_percentile(self._delays, 95)),
                             "max": ms(max(self._delays) if self._delays else None)},
                "red_avg": None if self.red is None else round(self.avg, 3)}


class FluidQueue:
    """Fluid (rate-based) bottleneck for per-interval simulation steps."""

    def __init__(self, depth=0.0):
        self.depth = float(depth)

    def step(self, arrivals_pkts, capacity_pps, limit_pkts, dt=1.0):
        """Advance one interval: B' = clamp(B + A - C dt, 0, Q).

        Returns {"depth": B', "drops": overflow, "served": packets sent,
        "delay_ms": 1000 (B + B') / 2 / C}, the queueing delay at the mean backlog.
        """
        if capacity_pps <= 0 or dt <= 0 or limit_pkts < 0 or arrivals_pkts < 0:
            raise ValueError("capacity_pps and dt must be positive; arrivals and limit non-negative")
        before = self.depth
        unclamped = before + arrivals_pkts - capacity_pps * dt
        drops = max(0.0, unclamped - limit_pkts)
        after = min(max(unclamped, 0.0), float(limit_pkts))
        self.depth = after
        return {"depth": after, "drops": drops,
                "served": before + arrivals_pkts - drops - after,
                "delay_ms": 1000 * (before + after) / 2 / capacity_pps}
