"""Pluggable flood detectors that consume CounterTracker samples.

Every detector exposes the same interface as the original TwoWindowDetector:
    name, protected_sources, alert_active, high_windows,
    observe(rates) -> alert dict | None, qualifying_sources(rates), reset(), state()
`rates` is the dict returned by CounterTracker.sample(). An alert dict holds
at least {"victim_pps": float, "sources": {source: pps}}; adaptive detectors
add "detector" and "scores". A source missing from rates["source_pps"] counts
as 0 pps; a source listed in rates["counter_resets"] has no valid rate this
window, so its baseline and score are left untouched. Protected sources still
contribute to the victim aggregate and to traffic shares but are never named.

Alerts fire once per episode: alert_active stays True while the alert
condition holds and clears as soon as it fails, so a new episode can alert
again. reset() returns an adaptive detector to its freshly built state.

Baselines use the West/Finch exponentially weighted mean and variance:
    delta = x - mu;  mu += alpha * delta;  var = (1 - alpha) * (var + alpha * delta**2)
The first window initialises mu = x, var = 0. A source first seen in a later
window starts from mu = 0 (it sent nothing before), so an attacker whose flow
only appears when the flood starts is still anomalous.
"""

import math

from controller.config import DEFAULTS, DETECTOR_NAMES
from controller.detection import TwoWindowDetector


__all__ = ("DETECTOR_NAMES", "CusumDetector", "EntropyDetector", "EwmaDetector",
           "TwoWindowDetector", "build_detector")


def _west_update(stats, x, alpha):
    """Update [mean, variance] in place with one exponentially weighted sample."""
    delta = x - stats[0]
    stats[0] += alpha * delta
    stats[1] = (1.0 - alpha) * (stats[1] + alpha * delta * delta)


def _r(value):
    """Round for compact, JSON-safe diagnostics."""
    return round(float(value), 4)


class _AdaptiveDetector:
    """Shared baseline bookkeeping for the EWMA, CUSUM and entropy detectors."""

    name = "adaptive"

    def __init__(self, params, protected_sources=(), consecutive_windows=2):
        self.params = dict(params)
        self.alpha = float(params["alpha"])
        self.warmup_windows = int(params["warmup_windows"])
        self.min_sources = int(params["min_sources"])
        self.consecutive_windows = int(consecutive_windows)
        self.protected_sources = frozenset(protected_sources)
        self.reset()

    def reset(self):
        """Forget every baseline and alert so the detector learns afresh."""
        self.alert_active = False
        self.high_windows = 0
        self.windows = 0
        self.baselines = {}  # source -> [mean, variance] of pps
        self.victim_baseline = None  # [mean, variance] of victim pps
        self.scores = {}

    def _source_rates(self, rates):
        """Per-source pps over every source seen so far (missing counts as 0)."""
        current = rates.get("source_pps") or {}
        return {source: float(current.get(source, 0.0))
                for source in sorted(self.baselines.keys() | current.keys())}

    def _baseline(self, source, x):
        """Return the source's [mean, variance], creating it when first seen."""
        stats = self.baselines.get(source)
        if stats is None:
            stats = self.baselines[source] = [x if self.windows <= 1 else 0.0, 0.0]
        return stats

    def _victim(self, victim):
        if self.victim_baseline is None:
            self.victim_baseline = [victim, 0.0]
        return self.victim_baseline

    @property
    def warm(self):
        return self.windows > self.warmup_windows

    def _alert(self, rates, offenders):
        return {"victim_pps": float(rates["victim_pps"]), "sources": dict(offenders),
                "detector": self.name,
                "scores": {source: _r(self.scores.get(source, 0.0)) for source in offenders}}

    def _base_state(self):
        return {
            "detector": self.name,
            "high_windows": self.high_windows,
            "alert_active": self.alert_active,
            "windows": self.windows,
            "warm": self.warm,
            "scores": {source: _r(score) for source, score in sorted(self.scores.items())},
            "baselines": {source: {"mean_pps": _r(mean), "std_pps": _r(math.sqrt(max(var, 0.0)))}
                          for source, (mean, var) in sorted(self.baselines.items())},
            "victim_baseline": None if self.victim_baseline is None else {
                "mean_pps": _r(self.victim_baseline[0]),
                "std_pps": _r(math.sqrt(max(self.victim_baseline[1], 0.0)))},
        }


class EwmaDetector(_AdaptiveDetector):
    """Per-source and aggregate EWMA control chart (mean + k standard deviations).

    A source is anomalous when x > mu + k*max(sigma, sigma_floor) and
    x > min_rate_pps; a window is high when at least min_sources unprotected
    sources are anomalous and the victim aggregate is anomalous by the same
    rule. A series' baseline is frozen while it is anomalous or an alert is
    active, so a flood is not learned as normal. Warm-up windows learn
    unconditionally and cannot alert. The alert needs consecutive_windows
    high windows, like the threshold detector.
    """

    name = "ewma"

    def __init__(self, params, protected_sources=(), consecutive_windows=2):
        super().__init__(params, protected_sources, consecutive_windows)
        self.k_sigma = float(params["k_sigma"])
        self.sigma_floor = float(params["sigma_floor_pps"])
        self.min_rate = float(params["min_rate_pps"])

    def _limit(self, stats):
        return stats[0] + self.k_sigma * max(math.sqrt(max(stats[1], 0.0)), self.sigma_floor)

    def _score(self, stats, x):
        return (x - stats[0]) / max(math.sqrt(max(stats[1], 0.0)), self.sigma_floor)

    def qualifying_sources(self, rates):
        """Unprotected sources above their EWMA limit and min_rate_pps now."""
        offenders = {}
        for source, x in (rates.get("source_pps") or {}).items():
            stats = self.baselines.get(source, [0.0, 0.0])
            if (source not in self.protected_sources and x > self.min_rate
                    and x > self._limit(stats)):
                offenders[source] = x
        return offenders

    def observe(self, rates):
        self.windows += 1
        resets = set(rates.get("counter_resets") or ())
        victim = float(rates["victim_pps"])
        xs = self._source_rates(rates)
        anomalous = {}
        for source, x in xs.items():
            stats = self._baseline(source, x)
            if source in resets:
                continue
            self.scores[source] = self._score(stats, x)
            if (source not in self.protected_sources and x > self.min_rate
                    and x > self._limit(stats)):
                anomalous[source] = x
        vstats = self._victim(victim)
        victim_anomalous = victim > self._limit(vstats)
        high = self.warm and victim_anomalous and len(anomalous) >= self.min_sources

        alert = None
        if not high:
            self.high_windows = 0
            self.alert_active = False
        else:
            self.high_windows += 1
            if not self.alert_active and self.high_windows >= self.consecutive_windows:
                self.alert_active = True
                alert = self._alert(rates, anomalous)

        if not self.alert_active:
            learning = not self.warm
            for source, x in xs.items():
                if source not in resets and (learning or source not in anomalous):
                    _west_update(self.baselines[source], x, self.alpha)
            if learning or not victim_anomalous:
                _west_update(vstats, victim, self.alpha)
        return alert

    def state(self):
        """JSON-safe diagnostics: z-scores against the EWMA baselines."""
        state = self._base_state()
        state.update(k_sigma=self.k_sigma, sigma_floor_pps=self.sigma_floor)
        return state


class CusumDetector(_AdaptiveDetector):
    """One-sided Page CUSUM per source on the clipped, standardised rate.

    z = clip((x - mu) / max(sigma, sigma_floor), -z_clip, z_clip) and
    S = max(0, S + z - drift_k). mu and sigma come from an EWMA baseline that is
    frozen while S > 0 or an alert is active. A source offends when S > h and
    x > min_rate_pps; the alert fires when at least min_sources offend.
    CUSUM accumulates evidence itself, so the top-level consecutive_windows
    is not used. With the shipped values (z_clip 4, k 0.5, h 6) a sustained
    flood gives S = 3.5, 7.0 (alarm in window 2), a single-window burst peaks
    at 3.5 and decays, and 1 s on / 1 s off pulsing gives 3.5, 3.0, 6.5
    (alarm on the second pulse). Background jitter can leave some evidence in
    S, so under Poisson noise a lone burst occasionally crosses h (about 1.6%
    of seeded runs of the burst scenario). high_windows counts consecutive
    windows in which the largest S increased.
    """

    name = "cusum"

    def __init__(self, params, protected_sources=(), consecutive_windows=2):
        super().__init__(params, protected_sources, consecutive_windows)
        self.drift_k = float(params["drift_k"])
        self.threshold_h = float(params["threshold_h"])
        self.z_clip = float(params["z_clip"])
        self.sigma_floor = float(params["sigma_floor_pps"])
        self.min_rate = float(params["min_rate_pps"])

    def reset(self):
        super().reset()
        self.cusum = {}
        self.last_max_cusum = 0.0

    def qualifying_sources(self, rates):
        """Unprotected sources whose CUSUM exceeds h and that send above min_rate_pps."""
        return {source: x for source, x in (rates.get("source_pps") or {}).items()
                if source not in self.protected_sources and x > self.min_rate
                and self.cusum.get(source, 0.0) > self.threshold_h}

    def observe(self, rates):
        self.windows += 1
        resets = set(rates.get("counter_resets") or ())
        xs = self._source_rates(rates)
        warm = self.warm
        for source, x in xs.items():
            stats = self._baseline(source, x)
            if source in resets:
                continue
            sigma = max(math.sqrt(max(stats[1], 0.0)), self.sigma_floor)
            z = max(-self.z_clip, min(self.z_clip, (x - stats[0]) / sigma))
            self.scores[source] = z
            if warm and source not in self.protected_sources:
                self.cusum[source] = max(0.0, self.cusum.get(source, 0.0) + z - self.drift_k)
        offenders = self.qualifying_sources(rates)

        max_cusum = max(self.cusum.values(), default=0.0)
        self.high_windows = self.high_windows + 1 if max_cusum > self.last_max_cusum else 0
        self.last_max_cusum = max_cusum

        alert = None
        if not (warm and len(offenders) >= self.min_sources):
            self.alert_active = False
        elif not self.alert_active:
            self.alert_active = True
            alert = {"victim_pps": float(rates["victim_pps"]), "sources": dict(offenders),
                     "detector": self.name,
                     "scores": {source: _r(self.cusum[source]) for source in offenders}}

        if not self.alert_active:
            for source, x in xs.items():
                if source not in resets and self.cusum.get(source, 0.0) == 0.0:
                    _west_update(self.baselines[source], x, self.alpha)
        return alert

    def state(self):
        """JSON-safe diagnostics: clipped z per source and the CUSUM statistics."""
        state = self._base_state()
        state.update(cusum={source: _r(value) for source, value in sorted(self.cusum.items())},
                     threshold_h=self.threshold_h, drift_k=self.drift_k)
        return state


class EntropyDetector(_AdaptiveDetector):
    """Traffic-share divergence detector (KL divergence against a baseline mix).

    Shares p_s = (x_s + eps) / sum(x + eps) over every source seen (protected
    hosts included). The decision statistic is D(P_t || P_base) in bits, where
    P_base is an EWMA of share vectors learned only in windows that are not
    high. A window is high when D > kl_threshold_bits and the victim rate
    exceeds max(min_victim_pps, mu_v + 3 sigma_v). Offenders are unprotected
    sources whose share rose by more than share_delta and whose rate exceeds
    the top-level source_pps. The alert needs consecutive_windows high windows
    and at least min_sources offenders.

    Plain Shannon entropy is reported but not used for decisions: a two-source
    flood moves the shares (a1, a2, client) from (.14, .14, .71) to
    (.50, .50, .01), which changes normalised entropy only from 0.73 to 0.67
    while D is 1.73 bits (0.78 to 0.67 and 1.55 bits with the shipped 0.5 pps
    smoothing). Entropy measures how even the mix is, not whether it changed.
    """

    name = "entropy"

    def __init__(self, params, protected_sources=(), consecutive_windows=2, source_pps=30.0):
        super().__init__(params, protected_sources, consecutive_windows)
        self.kl_threshold = float(params["kl_threshold_bits"])
        self.share_delta = float(params["share_delta"])
        self.min_victim = float(params["min_victim_pps"])
        self.smoothing = float(params["smoothing_pps"])
        self.source_pps = float(source_pps)

    def reset(self):
        super().reset()
        self.base_shares = {}
        self.shares = {}
        self.entropy_bits = 0.0
        self.normalised_entropy = 0.0
        self.kl_bits = 0.0

    def _shares(self, xs):
        total = sum(xs.values()) + self.smoothing * len(xs)
        return {source: (x + self.smoothing) / total for source, x in xs.items()} if total > 0 else {}

    def _base_for(self, shares):
        """Baseline shares over the current sources; new sources get a 0 pps share."""
        missing = shares.keys() - self.base_shares.keys()
        if self.base_shares and missing:
            volume = max(self.victim_baseline[0], 0.0) if self.victim_baseline else 0.0
            new_share = self.smoothing / (volume + self.smoothing * len(shares))
            for source in missing:
                self.base_shares[source] = new_share
        elif not self.base_shares:
            self.base_shares = dict(shares)
        total = sum(self.base_shares.values())
        self.base_shares = {source: share / total for source, share in self.base_shares.items()}
        return self.base_shares

    def _offenders(self, rates, shares, base):
        current = rates.get("source_pps") or {}
        return {source: float(current.get(source, 0.0)) for source, share in shares.items()
                if source not in self.protected_sources
                and float(current.get(source, 0.0)) > self.source_pps
                and share - base.get(source, 0.0) > self.share_delta}

    def qualifying_sources(self, rates):
        """Unprotected sources whose share rose past share_delta and that exceed source_pps."""
        xs = self._source_rates(rates)
        return self._offenders(rates, self._shares(xs), self.base_shares)

    def observe(self, rates):
        self.windows += 1
        victim = float(rates["victim_pps"])
        xs = self._source_rates(rates)
        for source, x in xs.items():
            self._baseline(source, x)  # remembers seen sources for share vectors
        shares = self._shares(xs)
        base = self._base_for(shares)
        self.shares = shares
        self.entropy_bits = -sum(p * math.log2(p) for p in shares.values() if p > 0)
        self.normalised_entropy = self.entropy_bits / math.log2(len(shares)) if len(shares) > 1 else 0.0
        self.kl_bits = sum(p * math.log2(p / base[source]) for source, p in shares.items() if p > 0)
        self.scores = {source: p - base.get(source, 0.0) for source, p in shares.items()}
        offenders = self._offenders(rates, shares, base)

        vstats = self._victim(victim)
        victim_limit = max(self.min_victim, vstats[0] + 3.0 * math.sqrt(max(vstats[1], 0.0)))
        high = self.warm and self.kl_bits > self.kl_threshold and victim > victim_limit

        alert = None
        if not high:
            self.high_windows = 0
            self.alert_active = False
            _west_update(vstats, victim, self.alpha)
            self.base_shares = {source: (1.0 - self.alpha) * base[source] + self.alpha * p
                                for source, p in shares.items()}
        else:
            self.high_windows += 1
            if len(offenders) < self.min_sources:
                self.alert_active = False
            elif not self.alert_active and self.high_windows >= self.consecutive_windows:
                self.alert_active = True
                alert = self._alert(rates, offenders)
        return alert

    def state(self):
        """JSON-safe diagnostics: shares, entropy, KL divergence and share deltas."""
        state = self._base_state()
        state.pop("baselines")
        state.update(
            entropy_bits=_r(self.entropy_bits), normalised_entropy=_r(self.normalised_entropy),
            kl_bits=_r(self.kl_bits), kl_threshold_bits=self.kl_threshold,
            shares={source: _r(p) for source, p in sorted(self.shares.items())},
            baseline_shares={source: _r(p) for source, p in sorted(self.base_shares.items())},
        )
        return state


def _section(config, name):
    """Detector parameters, completing legacy configurations with the defaults."""
    return {**DEFAULTS["detectors"][name], **(config.get("detectors") or {}).get(name, {})}


def build_detector(config, protected_sources=None):
    """Create the detector selected by an effective (or legacy seven-key) configuration.

    `protected_sources` defaults to the configured list; callers such as the
    controller may add the victim and client addresses.
    """
    name = config.get("detector", "threshold")
    protected = config["protected_sources"] if protected_sources is None else protected_sources
    if name == "threshold":
        return TwoWindowDetector(config["victim_pps"], config["source_pps"], config["min_sources"],
                                 config["consecutive_windows"], protected)
    windows = config["consecutive_windows"]
    if name == "ewma":
        return EwmaDetector(_section(config, name), protected, windows)
    if name == "cusum":
        return CusumDetector(_section(config, name), protected, windows)
    if name == "entropy":
        return EntropyDetector(_section(config, name), protected, windows, config["source_pps"])
    raise ValueError(f"detector {name!r} is not available; choose one of {', '.join(DETECTOR_NAMES)}")
