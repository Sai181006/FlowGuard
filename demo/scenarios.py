"""Traffic scenarios shared by the dashboard simulation and the detector benchmark.

A scenario gives the offered packets per second of every source for each
one-second interval [t, t + 1). The first six reproduce demo.engine's
built-in scenarios exactly when no noise generator is passed; the rest add
harder cases for the adaptive detectors. With a seeded random.Random every
source's rate is drawn from a Poisson distribution around its base rate, so
runs are reproducible. Standard library only (the dashboard runs `python -S`).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

A1, A2, A3 = "10.0.0.21", "10.0.0.22", "10.0.0.23"
CLIENT = "10.0.0.11"
VICTIM = "10.0.0.10"
DURATION_S = 30
ATTACK_START_S = 5
BACKGROUND_PPS = {A1: 2, A2: 2, A3: 2, CLIENT: 10}
LOW_RATE_PPS = 40
RAMP_PPS = (5, 150)
FLASH_CROWD_FACTOR = 20


def poisson(rng: random.Random, lam: float) -> int:
    """Seeded Poisson draw: Knuth's method below 30, a rounded normal approximation above."""
    if lam <= 0:
        return 0
    if lam < 30:
        limit, k, product = math.exp(-lam), 0, rng.random()
        while product > limit:
            k += 1
            product *= rng.random()
        return k
    return max(0, round(rng.gauss(lam, math.sqrt(lam))))


@dataclass(frozen=True)
class Scenario:
    """One traffic pattern; `attack_intervals` are [start, end) seconds of attacker load.

    `benign` marks scenarios in which no alert is wanted: normal traffic, a
    flash crowd, and the one-window burst that the consecutive-window rule is
    designed to ignore. `profile` selects how attacker rates are shaped:
    "step" (pps, or `fixed_pps` when set), "ramp" (linear RAMP_PPS) or
    "flash" (every host scaled up smoothly, shares unchanged).
    """

    id: str
    label: str
    description: str
    sources: tuple
    attackers: frozenset
    attack_intervals: tuple
    benign: bool = False
    dashboard: bool = True
    duration_s: int = DURATION_S
    profile: str = "step"
    fixed_pps: int | None = None

    def is_active(self, interval_start: int) -> bool:
        """Whether attacker hosts send elevated traffic during [t, t + 1)."""
        return any(start <= interval_start < end for start, end in self.attack_intervals)

    def first_attack_s(self) -> int | None:
        return min((start for start, _ in self.attack_intervals), default=None)

    def _flash_factor(self, t: int) -> float:
        # 1x until 5 s, smooth rise to 20x by 9 s, hold, then back to 1x by 25 s.
        rise = FLASH_CROWD_FACTOR - 1
        if 5 <= t < 10:
            return 1 + rise * (t - 4) / 5
        if 10 <= t < 20:
            return FLASH_CROWD_FACTOR
        if 20 <= t < 25:
            return FLASH_CROWD_FACTOR - rise * (t - 19) / 5
        return 1.0

    def base_rates(self, interval_start: int, pps: int) -> dict[str, int]:
        """Noise-free offered pps per source for the interval starting at `interval_start`."""
        rates = {source: BACKGROUND_PPS[source] for source in self.sources}
        if self.profile == "flash":
            factor = self._flash_factor(interval_start)
            return {source: round(rate * factor) for source, rate in rates.items()}
        if not self.is_active(interval_start):
            return rates
        if self.profile == "ramp":
            (start, end), (low, high) = self.attack_intervals[0], RAMP_PPS
            rate = round(low + (high - low) * (interval_start - start) / (end - start - 1))
        else:
            rate = pps if self.fixed_pps is None else self.fixed_pps
        for source in self.sources:
            if source in self.attackers:
                rates[source] = rate
        return rates

    def offered(self, interval_start: int, pps: int, rng: random.Random | None = None) -> dict[str, int]:
        """Offered pps per source; with `rng`, each rate is a Poisson draw around its base."""
        rates = self.base_rates(interval_start, pps)
        if rng is None:
            return rates
        return {source: poisson(rng, rate) for source, rate in rates.items()}

    def summary(self) -> dict:
        """Dashboard description in the shape of demo.engine.SCENARIOS."""
        return {"id": self.id, "label": self.label, "description": self.description}


_PAIR = (A1, A2, CLIENT)
_ATTACKERS = frozenset({A1, A2})
_SCENARIO_LIST = (
    Scenario("normal", "Normal traffic", "Two quiet sources and a protected 10 pps client.",
             _PAIR, frozenset(), (), benign=True),
    Scenario("burst", "One-window burst",
             "A single high window demonstrates the consecutive-window requirement.",
             _PAIR, _ATTACKERS, ((ATTACK_START_S, ATTACK_START_S + 1),), benign=True),
    Scenario("sustained", "Sustained two-source load",
             "Two sources send continuously, then stop; rules expire after the configured 10 second TTL.",
             _PAIR, _ATTACKERS, ((ATTACK_START_S, 25),)),
    Scenario("waves", "Repeated waves",
             "Three traffic waves show the effect of temporary rules and later redetection.",
             _PAIR, _ATTACKERS, ((5, 10), (14, 18), (22, 25))),
    Scenario("single-source", "Single-source blind spot",
             "One source exceeds the rate thresholds, but the configured two-source minimum is not met.",
             _PAIR, frozenset({A1}), ((ATTACK_START_S, 25),)),
    Scenario("low-rate", "Below victim threshold",
             "Two sources exceed their individual threshold while their combined rate stays below "
             "the victim threshold.",
             _PAIR, _ATTACKERS, ((ATTACK_START_S, 25),), fixed_pps=LOW_RATE_PPS),
    Scenario("pulsing", "Pulsing (1 s on / 1 s off)",
             "Two sources flood every other second, so no two consecutive windows are both high.",
             _PAIR, _ATTACKERS, tuple((t, t + 1) for t in range(ATTACK_START_S, 25, 2))),
    Scenario("ramp", "Low-and-slow ramp",
             "Two sources rise linearly from 5 to 150 pps over 20 seconds, too gradually for a "
             "self-adjusting baseline to notice.",
             _PAIR, _ATTACKERS, ((ATTACK_START_S, 25),), profile="ramp"),
    Scenario("flash-crowd", "Flash crowd (benign)",
             "Every host, including the client, smoothly scales to 20 times its usual rate with the "
             "same traffic mix: legitimate load that volume detectors mistake for a flood.",
             (A1, A2, A3, CLIENT), frozenset(), (), benign=True, profile="flash"),
    Scenario("three-source", "Three-source flood",
             "A third attacker, 10.0.0.23, joins the two usual sources.",
             (A1, A2, A3, CLIENT), frozenset({A1, A2, A3}), ((ATTACK_START_S, 25),)),
    Scenario("repeat-offender", "Repeat offender",
             "Three waves 17 seconds apart over 50 seconds, inside the escalating back-off memory.",
             _PAIR, _ATTACKERS, ((5, 10), (22, 27), (39, 44)), duration_s=50),
)

SCENARIOS: dict[str, Scenario] = {scenario.id: scenario for scenario in _SCENARIO_LIST}
DASHBOARD_SCENARIOS = tuple(scenario.summary() for scenario in _SCENARIO_LIST if scenario.dashboard)
