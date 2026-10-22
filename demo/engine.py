"""Dashboard data model for FlowGuard's native, local presentation."""

from __future__ import annotations

import csv
import importlib
import importlib.util
import json
import math
import random
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.config import DETECTOR_NAMES, MITIGATION_ACTIONS, apply_overrides
from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector  # noqa: F401 (public names)
from controller.detectors import build_detector
from controller.mitigation import OffenderHistory, choose_action
from experiments.analyze import ATTACKERS, attacker_windows, compare, flood_start, summarize_trial


def _sibling(name: str):
    """Import demo/<name>.py, even if experiments/demo.py shadows the namespace package `demo`."""
    try:
        return importlib.import_module(f"demo.{name}")
    except ImportError:
        module_name = f"_flowguard_demo_{name}"
        if module_name in sys.modules:
            return sys.modules[module_name]
        spec = importlib.util.spec_from_file_location(module_name, Path(__file__).with_name(f"{name}.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module  # dataclasses resolve their module by name
        spec.loader.exec_module(module)
        return module


_scenarios = _sibling("scenarios")
_queueing = _sibling("queueing")


SCENARIOS = (
    {
        "id": "normal",
        "label": "Normal traffic",
        "description": "Two quiet sources and a protected 10 pps client.",
    },
    {
        "id": "burst",
        "label": "One-window burst",
        "description": "A single high window demonstrates the consecutive-window requirement.",
    },
    {
        "id": "sustained",
        "label": "Sustained two-source load",
        "description": "Two sources send continuously, then stop; rules expire after the configured 10 second TTL.",
    },
    {
        "id": "waves",
        "label": "Repeated waves",
        "description": "Three traffic waves show the effect of temporary rules and later redetection.",
    },
    {
        "id": "single-source",
        "label": "Single-source blind spot",
        "description": "One source exceeds the rate thresholds, but the configured two-source minimum is not met.",
    },
    {
        "id": "low-rate",
        "label": "Below victim threshold",
        "description": "Two sources exceed their individual threshold while their combined rate stays below the victim threshold.",
    },
)

# Every dashboard scenario: the original six above, then the harder cases.
ALL_SCENARIOS = tuple(dict(item) for item in _scenarios.DASHBOARD_SCENARIOS)

ATTACKER_NAMES = ("10.0.0.21", "10.0.0.22")
CLIENT = "10.0.0.11"
VICTIM = "10.0.0.10"
DURATION_S = 30
ATTACK_START_S = 5
PACKET_BYTES = 128
BASE_LATENCY_MS = 2.0
QUEUE_DEFAULTS = {"enabled": False, "queue_packets": 50, "min_packets": 5, "max_packets": 500}
MAX_QUEUE_PACKETS = 10_000

DETECTORS = (
    {"id": "threshold", "label": "Two-window threshold", "class": "TwoWindowDetector",
     "description": "Fixed thresholds: victim rate and at least min_sources source rates high for "
                    "consecutive windows (the original detector)."},
    {"id": "ewma", "label": "EWMA control chart", "class": "EwmaDetector",
     "description": "Per-source baseline (exponentially weighted mean and deviation); a source is "
                    "anomalous above mean + k standard deviations."},
    {"id": "cusum", "label": "CUSUM change detector", "class": "CusumDetector",
     "description": "Page CUSUM accumulates standardised excess rate, so repeated short pulses add up."},
    {"id": "entropy", "label": "Traffic-mix divergence", "class": "EntropyDetector",
     "description": "KL divergence of the per-source traffic shares from a learned baseline mix."},
)
DETECTOR_CLASSES = {item["id"]: item["class"] for item in DETECTORS}
MITIGATION_CHOICES = (
    {"id": "drop", "label": "Drop", "description": "Discard the offender's UDP to the victim until the rule expires."},
    {"id": "rate_limit", "label": "Rate-limit",
     "description": "Police the offender with a token bucket (rate_limit_pps, burst) until the rule expires."},
    {"id": "graduated", "label": "Graduated",
     "description": "Rate-limit a first offense; drop from the graduated_drop_after-th offense on."},
)
BENCHMARK_PATH = ROOT / "results/benchmarks/detector-benchmark.json"


def detector_config() -> dict:
    return json.loads((ROOT / "config/detector.json").read_text(encoding="utf-8"))


def bootstrap_data(csrf_token: str) -> dict:
    config = detector_config()
    effective = apply_overrides(config)
    mitigation = effective["mitigation"]
    return {
        "provenance": {
            "simulation": {
                "kind": "simulation",
                "label": "Deterministic model using the project's actual CounterTracker and TwoWindowDetector code.",
                "scope": "No switch rules are installed and no attack traffic is sent.",
                "detectors": "Any selectable detector is the project's real class from controller/detectors.py; "
                             "traffic, forwarding, rule effects and the bottleneck queue are modeled.",
            },
            "offline_benchmark": {
                "kind": "offline_benchmark",
                "label": "Simulated scenarios, real detector code.",
                "scope": "Seeded Poisson traffic models fed to the real detector classes; no packets are sent.",
            },
            "recorded": {
                "kind": "recorded",
                "label": "Original historical m6 attack-off and attack-on experiment files.",
                "scope": "Counters, events, probe outcomes, and RTTs are preserved from the saved files; comparison fields derived from them are identified.",
            },
            "live_udp": {
                "kind": "live_udp",
                "label": "Five real UDP echo probes over 127.0.0.1 using the project's existing echo server and probe scripts.",
                "scope": "Loopback only; no external network traffic.",
            },
        },
        "config": config,
        "scenarios": [dict(item) for item in ALL_SCENARIOS],
        "scenario_durations_s": {key: value.duration_s for key, value in _scenarios.SCENARIOS.items()},
        "detectors": [dict(item) for item in DETECTORS],
        "mitigation_actions": [dict(item) for item in MITIGATION_CHOICES],
        "queue_defaults": dict(QUEUE_DEFAULTS),
        "benchmark_available": BENCHMARK_PATH.is_file(),
        "simulation_defaults": {
            "scenario": "sustained",
            "mitigation": True,
            "pps_per_attacker": 600,
            "hypothetical_server_capacity_pps": 1000,
            "duration_s": DURATION_S,
            "attack_start_s": ATTACK_START_S,
            "detector": effective["detector"],
            "action": mitigation["action"],
            "backoff": mitigation["backoff"]["enabled"],
            "rate_limit_pps": mitigation["rate_limit_pps"],
            "rate_limit_burst_packets": mitigation["rate_limit_burst_packets"],
            "graduated_drop_after": mitigation["graduated_drop_after"],
            "queue_packets": None,
        },
        "csrf_token": csrf_token,
    }


def benchmark_data() -> dict:
    """The committed offline detector benchmark, served read-only with its provenance."""
    data = json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))
    return {
        "mode": "offline_benchmark",
        "provenance": {
            "kind": "offline_benchmark",
            "label": "Simulated scenarios, real detector code.",
            "method": (data.get("provenance") or {}).get("method"),
            "source_file": "results/benchmarks/detector-benchmark.json",
            "warning": "No packets were sent; per-second counters are generated with seeded Poisson noise.",
        },
        "benchmark": data,
    }


def _is_attack_active(scenario: str, interval_start: int, interval_end: int) -> bool:
    """Whether an attacker sends at any point during this one-second interval."""
    if scenario == "normal":
        return False
    if scenario == "burst":
        return interval_start == ATTACK_START_S
    if scenario == "single-source":
        return ATTACK_START_S <= interval_start < 25
    if scenario == "low-rate":
        return ATTACK_START_S <= interval_start < 25
    if scenario == "sustained":
        return ATTACK_START_S <= interval_start < 25
    if scenario == "waves":
        return any(start <= interval_start < end for start, end in ((5, 10), (14, 18), (22, 25)))
    return False


def _offered_rates(scenario: str, interval_start: int, interval_end: int, pps: int) -> dict[str, int]:
    active = _is_attack_active(scenario, interval_start, interval_end)
    rates = {ATTACKER_NAMES[0]: 2, ATTACKER_NAMES[1]: 2, CLIENT: 10}
    if not active:
        return rates
    if scenario == "single-source":
        rates[ATTACKER_NAMES[0]] = pps
    elif scenario == "low-rate":
        # Both sources clear the default 30 pps source threshold, while
        # their combined rate (80 pps plus the protected client) stays under
        # the default 100 pps victim threshold.
        rates[ATTACKER_NAMES[0]] = 40
        rates[ATTACKER_NAMES[1]] = 40
    else:
        rates[ATTACKER_NAMES[0]] = pps
        rates[ATTACKER_NAMES[1]] = pps
    return rates


def _bool_query(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int_option(name: str, value, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _alert_message(detector_name: str, alert: dict, offenders: list[str]) -> str:
    if detector_name == "threshold":
        return f"Two-window detector alert: victim {alert['victim_pps']:.0f} pps; offenders {', '.join(offenders)}."
    scores = alert.get("scores") or {}
    named = ", ".join(f"{source} (score {scores[source]:g})" if source in scores else source for source in offenders)
    return f"{DETECTOR_CLASSES[detector_name]} alert: victim {alert['victim_pps']:.0f} pps; offenders {named}."


def simulate(
    scenario: str = "sustained",
    mitigation=True,
    pps: int = 600,
    capacity: int = 1000,
    victim_pps: float | None = None,
    source_pps: float | None = None,
    min_sources: int | None = None,
    consecutive_windows: int | None = None,
    *,
    detector: str | None = None,
    action: str | None = None,
    backoff=None,
    rate_limit_pps: int | None = None,
    queue_packets: int | None = None,
    noise_seed: int | None = None,
) -> dict:
    """Create a deterministic per-second trace driven by the real detector classes.

    Keyword options default to the shipped configuration; with all of them left
    as None every field of the original output is reproduced exactly (new
    fields such as detector_state are added alongside).

    detector        threshold | ewma | cusum | entropy (controller/detectors.py)
    action          drop | rate_limit | graduated (controller/mitigation.choose_action)
    backoff         exponential rule-timeout back-off (controller/mitigation.OffenderHistory)
    rate_limit_pps  token-bucket rate for rate_limit and graduated rules
    queue_packets   model a finite FIFO bottleneck queue in front of the server (FluidQueue)
                    instead of the proportional-share formula for client success and latency
    noise_seed      seeded Poisson noise around every offered rate (same draws as the benchmark)

    Like the controller, a source under an active drop or rate-limit rule reads
    as 0 pps to the detector: the rule (priority 200) takes its packets away
    from the forwarding flow whose counters are polled.
    """
    if scenario not in _scenarios.SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    if not isinstance(pps, int) or pps < 1 or pps > 100_000:
        raise ValueError("pps must be an integer between 1 and 100000")
    if not isinstance(capacity, int) or capacity < 1 or capacity > 1_000_000:
        raise ValueError("capacity must be an integer between 1 and 1000000")
    if detector is not None and detector not in DETECTOR_NAMES:
        raise ValueError(f"detector must be one of: {', '.join(DETECTOR_NAMES)}")
    if action is not None and action not in MITIGATION_ACTIONS:
        raise ValueError(f"action must be one of: {', '.join(MITIGATION_ACTIONS)}")
    if rate_limit_pps is not None:
        _int_option("rate_limit_pps", rate_limit_pps, 1, 100_000)
    if queue_packets is not None:
        _int_option("queue_packets", queue_packets, 1, MAX_QUEUE_PACKETS)
    if noise_seed is not None:
        _int_option("noise_seed", noise_seed, 0, 2**32 - 1)

    base_config = detector_config()
    config = apply_overrides(
        base_config,
        detector=detector,
        action=action,
        backoff=None if backoff is None else _bool_query(backoff),
        rate_limit_pps=rate_limit_pps,
    )
    config["victim_pps"] = float(base_config["victim_pps"] if victim_pps is None else victim_pps)
    config["source_pps"] = float(base_config["source_pps"] if source_pps is None else source_pps)
    config["min_sources"] = int(base_config["min_sources"] if min_sources is None else min_sources)
    config["consecutive_windows"] = int(
        base_config["consecutive_windows"] if consecutive_windows is None else consecutive_windows
    )
    if not math.isfinite(config["victim_pps"]) or config["victim_pps"] < 0:
        raise ValueError("victim_pps must be a finite nonnegative number")
    if not math.isfinite(config["source_pps"]) or config["source_pps"] < 0:
        raise ValueError("source_pps must be a finite nonnegative number")
    if not 1 <= config["min_sources"] <= 10 or not 1 <= config["consecutive_windows"] <= 10:
        raise ValueError("min_sources and consecutive_windows must be between 1 and 10")

    mitigation = _bool_query(mitigation)
    policy = config["mitigation"]
    detector_name = config["detector"]
    detector_class = DETECTOR_CLASSES[detector_name]
    model = _scenarios.SCENARIOS[scenario]
    duration_s = model.duration_s
    rng = None if noise_seed is None else random.Random(f"{scenario}:{noise_seed}")
    burst_capacity = max(float(policy["rate_limit_burst_packets"]), 1.0)  # TokenBucket's capacity rule
    rule_rate = int(policy["rate_limit_pps"])

    tracker = CounterTracker()
    detector_obj = build_detector(config, config["protected_sources"])
    history = OffenderHistory.from_config(config)
    queue = None if queue_packets is None else _queueing.FluidQueue()
    sources = tuple(model.sources)
    cumulative = dict.fromkeys(sources, 0)
    initial = [FlowCounter(source, VICTIM, "dashboard-sim", 0, 0) for source in sources]
    tracker.sample(0, initial)

    def queue_fields(depth, drops, delay):
        if queue is None:
            return {"queue_depth_packets": None, "queue_drops_pps": None, "queue_delay_ms": None}
        return {"queue_depth_packets": round(depth, 3), "queue_drops_pps": round(drops, 3),
                "queue_delay_ms": round(delay, 3)}

    events: list[dict] = []
    frames: list[dict] = [{
        "t_s": 0,
        "interval_start_s": 0,
        "source_offered_pps": dict.fromkeys(sources, 0),
        "source_delivered_pps": dict.fromkeys(sources, 0),
        "source_dropped_pps": dict.fromkeys(sources, 0),
        "victim_delivered_pps": 0,
        "ingress_pps": 0,
        "drop_pps": 0,
        "server_load_ratio": 0,
        "client_success": 1.0,
        "client_latency_ms": 2.0,
        "high_windows": 0,
        "detector_alert": False,
        "detector_input": {"victim_pps": 0, "source_pps": dict.fromkeys(sources, 0)},
        "state": "normal",
        "active_rules": [],
        "detector_state": detector_obj.state(),
        **queue_fields(0.0, 0.0, 0.0),
    }]
    packet_rows: list[dict] = []
    # source -> {expires_at, action, ttl, offense, tokens}
    active_rules: dict[str, dict] = {}
    rule_log: list[dict] = []
    ever_attack = False
    previous_attack_active = False
    first_alert_s = None
    alert_count = 0
    peak_ingress = 0
    peak_drop = 0
    peak_queue = 0.0
    total_queue_drops = 0.0
    success_values: list[float] = []

    def log_event(t_s, event_type, message, source=None, **extra):
        event = {"t_s": t_s, "type": event_type, "message": message}
        if source is not None:
            event["source"] = source
        event.update(extra)
        events.append(event)

    def describe(rule) -> str:
        return "drop" if rule["action"] == "drop" else "rate-limit"

    def install(t_s, offenders):
        """Install one modeled rule per offender without an active rule (as the controller does)."""
        installed = {"drop": [], "rate_limit": []}
        for source in offenders:
            current = active_rules.get(source)
            if current is not None and current["expires_at"] > t_s:
                continue
            offense, ttl = history.next_offense(source, t_s)
            rule_action = choose_action(policy["action"], offense, policy["graduated_drop_after"])
            active_rules[source] = {"expires_at": t_s + ttl, "action": rule_action, "ttl": ttl,
                                    "offense": offense, "tokens": burst_capacity, "installed_at": t_s}
            rule_log.append({"t_s": t_s, "source": source, "action": rule_action, "ttl_s": ttl,
                             "offense_count": offense})
            suffix = f" Offense {offense}." if (policy["backoff"]["enabled"] or policy["action"] == "graduated") else ""
            details = {"action": rule_action, "hard_timeout_s": ttl, "offense_count": offense}
            if rule_action == "drop":
                log_event(t_s, "drop_requested",
                          f"Modeled {ttl} second drop rule requested for UDP to {VICTIM}:9000.{suffix}",
                          source, **details)
            else:
                log_event(t_s, "ratelimit_requested",
                          f"Modeled {ttl} second rate-limit rule ({rule_rate} pps token bucket, burst "
                          f"{policy['rate_limit_burst_packets']}) requested for UDP to {VICTIM}:9000.{suffix}",
                          source, rate_pps=rule_rate, burst_packets=policy["rate_limit_burst_packets"], **details)
            installed[rule_action].append(source)
        if installed["drop"]:
            log_event(t_s, "drop_confirmed", "Modeled drop rules active; no switch was contacted.")
        if installed["rate_limit"]:
            log_event(t_s, "ratelimit_confirmed", "Modeled rate-limit rules active; no switch was contacted.")

    for t_s in range(1, duration_s + 1):
        interval_start = t_s - 1
        attack_active = model.is_active(interval_start)
        if attack_active:
            ever_attack = True
            if not previous_attack_active:
                log_event(interval_start, "attack_started", "Attacker traffic begins in the modeled interval.")
        elif previous_attack_active:
            log_event(interval_start, "attack_ended", "Attacker traffic stops in the modeled interval.")

        offered = model.offered(interval_start, pps, rng)
        dropped: dict[str, int] = {}
        delivered: dict[str, int] = {}
        for source in sources:
            rule = active_rules.get(source)
            if rule is not None and interval_start >= rule["expires_at"]:
                rule = None
            if rule is None:
                delivered_rate = offered[source]
            elif rule["action"] == "drop":
                delivered_rate = 0
            else:
                # Fluid token bucket over the one-second interval: the stored
                # tokens (at most the burst) plus rate x 1 s may pass.
                available = rule["tokens"] + rule_rate
                delivered_rate = min(offered[source], math.floor(available))
                rule["tokens"] = min(burst_capacity, available - delivered_rate)
            drop_rate = offered[source] - delivered_rate
            dropped[source] = drop_rate
            delivered[source] = delivered_rate
            # Only the forwarding flow is polled; a mitigation rule takes the source's packets.
            cumulative[source] += delivered_rate if rule is None else 0
            packet_rows.append({
                "t_s": t_s,
                "interval_start_s": interval_start,
                "source": source,
                "offered_pps": offered[source],
                "delivered_pps": delivered_rate,
                "dropped_pps": drop_rate,
                "packets_offered": offered[source],
                "packets_delivered": delivered_rate,
                "packets_dropped": drop_rate,
                "provenance": "simulated representative one-second packet counter row",
            })

        counter_rows = [
            FlowCounter(source, VICTIM, "dashboard-sim", cumulative[source], cumulative[source] * PACKET_BYTES)
            for source in sources
        ]
        rates = tracker.sample(t_s, counter_rows)
        alert = detector_obj.observe(rates)
        if alert:
            alert_count += 1
            first_alert_s = t_s if first_alert_s is None else first_alert_s
            offenders = sorted(alert["sources"])
            extra = {}
            if "scores" in alert:
                extra = {"detector": detector_name, "scores": dict(alert["scores"])}
            log_event(t_s, "alert", _alert_message(detector_name, alert, offenders), **extra)
            if mitigation:
                install(t_s, offenders)
        elif mitigation and detector_obj.alert_active:
            # The controller reconciles offenders throughout an active episode.
            install(t_s, sorted(detector_obj.qualifying_sources(rates)))

        expired = [source for source, rule in active_rules.items() if rule["expires_at"] <= t_s]
        for source in sorted(expired):
            rule = active_rules.pop(source)
            log_event(t_s, "rule_expired", f"Modeled {rule['ttl']} second {describe(rule)} rule expired.", source)

        ingress_pps = sum(offered.values())
        drop_pps = sum(dropped.values())
        victim_delivered_pps = sum(delivered.values())
        load_ratio = victim_delivered_pps / capacity
        if queue is None:
            success = min(1.0, capacity / victim_delivered_pps) if victim_delivered_pps else 1.0
            # A deliberately simple hypothetical queue model: 2 ms baseline, rising
            # as utilization approaches capacity and capped at 200 ms under overload.
            latency_ms = min(200.0, 2.0 / max(0.01, 1.0 - min(load_ratio, 0.99)))
            queue_now = queue_fields(0, 0, 0)
        else:
            # Finite FIFO at the server: B' = clamp(B + A - C, 0, Q). Overflow is
            # shared by every arriving packet, so the client loses the same fraction.
            step = queue.step(victim_delivered_pps, capacity, queue_packets)
            success = 1.0 - step["drops"] / victim_delivered_pps if victim_delivered_pps else 1.0
            latency_ms = BASE_LATENCY_MS + step["delay_ms"]
            queue_now = queue_fields(step["depth"], step["drops"], step["delay_ms"])
            peak_queue = max(peak_queue, step["depth"])
            total_queue_drops += step["drops"]
        success_values.append(success)
        if active_rules:
            state = "mitigating"
        elif attack_active or detector_obj.high_windows > 0 or detector_obj.alert_active:
            state = "suspect"
        elif ever_attack:
            state = "recovering"
        else:
            state = "normal"

        peak_ingress = max(peak_ingress, ingress_pps)
        peak_drop = max(peak_drop, drop_pps)
        frames.append({
            "t_s": t_s,
            "interval_start_s": interval_start,
            "source_offered_pps": offered,
            "source_delivered_pps": delivered,
            "source_dropped_pps": dropped,
            "victim_delivered_pps": victim_delivered_pps,
            "ingress_pps": ingress_pps,
            "drop_pps": drop_pps,
            "server_load_ratio": round(load_ratio, 5),
            "client_success": round(success, 5),
            "client_latency_ms": round(latency_ms, 3),
            "high_windows": detector_obj.high_windows,
            "detector_alert": bool(alert),
            "detector_input": {
                "victim_pps": rates["victim_pps"],
                "source_pps": dict(rates["source_pps"]),
            },
            "state": state,
            "active_rules": [
                {
                    "source": source,
                    "expires_at_s": rule["expires_at"],
                    "status": "modeled drop" if rule["action"] == "drop" else f"modeled rate-limit {rule_rate} pps",
                    "target": f"{VICTIM}:9000",
                    "action": rule["action"],
                    "rate_pps": None if rule["action"] == "drop" else rule_rate,
                    "ttl_s": rule["ttl"],
                    "offense_count": rule["offense"],
                }
                for source, rule in sorted(active_rules.items())
            ],
            "detector_state": detector_obj.state(),
            **queue_now,
        })
        previous_attack_active = attack_active

    scenario_info = model.summary()
    model_note = (
        f"Model: offered traffic, forwarding, {policy['action'].replace('_', '-')} rules"
        + (" with exponential back-off" if policy["backoff"]["enabled"] else "")
        + (f" and a {queue_packets}-packet bottleneck queue" if queue is not None else "")
        + " are computed in Python; only the detector decision comes from project code."
    )
    return {
        "mode": "simulation",
        "provenance": {
            "kind": "simulation",
            "label": f"Deterministic simulation using the actual CounterTracker and {detector_class} implementation.",
            "warning": "This model does not contact Open vSwitch or install enforcement rules.",
            "detector": detector_name,
            "detector_class": detector_class,
            "model": model_note,
        },
        "scenario": dict(scenario_info),
        "parameters": {
            "scenario": scenario,
            "mitigation": mitigation,
            "pps_per_attacker": pps,
            "hypothetical_server_capacity_pps": capacity,
            "detector": detector_name,
            "action": policy["action"],
            "backoff": policy["backoff"]["enabled"],
            "rate_limit_pps": rule_rate,
            "rate_limit_burst_packets": policy["rate_limit_burst_packets"],
            "graduated_drop_after": policy["graduated_drop_after"],
            "queue_packets": queue_packets,
            "noise_seed": noise_seed,
        },
        "thresholds": {
            "victim_pps": config["victim_pps"],
            "source_pps": config["source_pps"],
            "min_sources": config["min_sources"],
            "consecutive_windows": config["consecutive_windows"],
            "protected_sources": config["protected_sources"],
            "mitigation_hard_timeout_s": config["mitigation_hard_timeout_s"],
        },
        "detector_parameters": (
            dict(config["detectors"][detector_name]) if detector_name in config["detectors"] else None
        ),
        "timeline": {
            "duration_s": duration_s,
            "step_s": 1,
            "attack_start_s": model.first_attack_s() if model.first_attack_s() is not None else ATTACK_START_S,
        },
        "frames": frames,
        "events": events,
        "packet_rows": packet_rows,
        "summary": {
            "alert_count": alert_count,
            "first_alert_s": first_alert_s,
            "peak_ingress_pps": peak_ingress,
            "peak_drop_pps": peak_drop,
            "modeled_capacity_pps": capacity,
            "modeled_rule_expiries": sum(event["type"] == "rule_expired" for event in events),
            "rules": rule_log,
            "rule_ttls_s": [entry["ttl_s"] for entry in rule_log],
            "mean_client_success": round(sum(success_values) / len(success_values), 5),
            "queue": None if queue is None else {
                "queue_packets": queue_packets,
                "peak_depth_packets": round(peak_queue, 3),
                "total_drops_packets": round(total_queue_drops, 3),
            },
            "assumption": (
                "Server capacity is a hypothetical packets-per-second input. Client success is modeled as "
                "capacity/delivered traffic under overload, and latency is a simple queue estimate. Neither "
                "is a measured server result."
                if queue is None else
                "Server capacity is a hypothetical packets-per-second input served by a modeled finite FIFO "
                f"queue of {queue_packets} packets (fluid approximation, demo/queueing.FluidQueue). Client "
                "success is the share of arrivals not dropped at that queue and latency is 2 ms plus the "
                "modeled queueing delay. Neither is a measured server result."
            ),
        },
    }


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _probe_rows(path: Path, attack_started_utc: str) -> list[dict]:
    attack_time = _parse_utc(attack_started_utc)
    rows = []
    with path.open(newline="", encoding="utf-8") as stream:
        for raw in csv.DictReader(stream):
            # The existing probe script writes its human-readable sent/received
            # summary to stderr; recorded experiment capture files include that
            # final line after the CSV rows. Preserve only actual numbered probes.
            if not (raw.get("sequence") or "").isdigit() or not raw.get("timestamp_utc"):
                continue
            row = {
                "timestamp_utc": raw["timestamp_utc"],
                "sequence": int(raw["sequence"]),
                "status": raw["status"],
                "rtt_ms": float(raw["rtt_ms"]) if raw["rtt_ms"] else None,
            }
            row["t_s"] = (_parse_utc(row["timestamp_utc"]) - attack_time).total_seconds()
            row["relative_time_source"] = "inferred from recorded UTC timestamps and recorded attack start"
            rows.append(row)
    return rows


def _recorded_trial(trial_id: str) -> dict:
    path = ROOT / "results" / trial_id
    summary = summarize_trial(path)
    start_s = flood_start(path)
    attack_starts = []
    for attack_log in ("attack-a1.jsonl", "attack-a2.jsonl"):
        attack_starts.extend(row for row in _jsonl(path / attack_log) if row.get("event") == "start")
    attack_utc = (
        min(attack_starts, key=lambda row: row["monotonic_s"])["time_utc"]
        if attack_starts
        else json.loads((path / "metadata.json").read_text(encoding="utf-8"))["phase_start_utc"]
    )
    metadata = json.loads((path / "metadata.json").read_text(encoding="utf-8"))

    frames = []
    previous_drop_sources = set()
    raw_events = _jsonl(path / "controller.jsonl")
    for row in raw_events:
        if row.get("type") != "sample":
            continue
        elapsed = row.get("elapsed_s")
        drop_counts = row.get("drop_packet_delta") or {}
        drop_totals = row.get("drop_packet_total") or {}
        new_drop_baseline = bool(set(drop_totals) - previous_drop_sources)
        previous_drop_sources = set(drop_totals)
        source_delivered = dict(row.get("source_pps") or {})
        source_dropped = {
            source: (count / elapsed if elapsed and elapsed > 0 else 0.0)
            for source, count in drop_counts.items()
        }
        source_offered = dict(source_delivered)
        for source in ATTACKERS:
            source_offered[source] = source_offered.get(source, 0.0) + source_dropped.get(source, 0.0)
        dropped_pps = sum(source_dropped.values())
        frames.append({
            "t_s": row["monotonic_s"] - start_s,
            "source_offered_pps": source_offered,
            "source_delivered_pps": source_delivered,
            "source_dropped_pps": source_dropped,
            "victim_delivered_pps": row.get("victim_pps", 0.0),
            "ingress_pps": row.get("victim_pps", 0.0) + dropped_pps,
            "drop_pps": None if new_drop_baseline else dropped_pps,
            "drop_rate_available": not new_drop_baseline,
            "drop_rate_note": (
                "First observation establishes drop-counter baselines; an interval rate is not yet known."
                if new_drop_baseline else "Derived from recorded counter deltas and elapsed time."
            ),
            "server_load_ratio": None,
            "client_success": None,
            "client_latency_ms": None,
            "high_windows": None,
            "state": "recorded sample",
            "raw_sample": row,
        })
    frames.sort(key=lambda row: row["t_s"])

    victim_frames = []
    for row in _jsonl(path / "victim.jsonl"):
        victim_frames.append({
            "t_s": row["window_start_s"] - start_s,
            "elapsed_s": row["elapsed_s"],
            "by_source_packets": row["by_source"],
            "packets": row["packets"],
            "total_packets": row["total_packets"],
            "packets_per_s": row["packets"] / row["elapsed_s"] if row["elapsed_s"] else 0,
            "raw_sample": row,
        })

    event_rows = []
    for row in raw_events:
        if row.get("type") == "sample":
            continue
        event = dict(row)
        if "monotonic_s" in event:
            event["t_s"] = event["monotonic_s"] - start_s
        event_rows.append(event)
    for attack_log in ("attack-a1.jsonl", "attack-a2.jsonl"):
        for row in _jsonl(path / attack_log):
            event = dict(row)
            event["t_s"] = row["monotonic_s"] - start_s
            event["source_log"] = attack_log
            event_rows.append(event)
    event_rows.sort(key=lambda row: row.get("t_s", 0))

    return {
        "id": trial_id,
        "summary": summary,
        "metadata": metadata,
        "attack_start_utc": attack_utc,
        "frames": frames,
        "victim_frames": victim_frames,
        "client_probe_rows": _probe_rows(path / "client.csv", attack_utc),
        "recovery_probe_rows": _probe_rows(path / "recovery-client.csv", attack_utc),
        "events": event_rows,
        "attacker_windows": attacker_windows(path),
        "source_files": [
            f"results/{trial_id}/metadata.json",
            f"results/{trial_id}/controller.jsonl",
            f"results/{trial_id}/victim.jsonl",
            f"results/{trial_id}/client.csv",
            f"results/{trial_id}/recovery-client.csv",
            f"results/{trial_id}/attack-a1.jsonl",
            f"results/{trial_id}/attack-a2.jsonl",
        ],
    }


def recorded_data() -> dict:
    off_path = ROOT / "results/m6-attack-off"
    on_path = ROOT / "results/m6-attack-on"
    comparison = compare(off_path, on_path)
    duration_s = min(
        json.loads((off_path / "metadata.json").read_text(encoding="utf-8"))["duration_s"],
        json.loads((on_path / "metadata.json").read_text(encoding="utf-8"))["duration_s"],
    )
    comparison_start_s = comparison["comparison_start_s"]
    return {
        "mode": "recorded",
        "provenance": {
            "kind": "recorded",
            "label": "Original historical data from the matched m6 experiment; raw measurements are retained.",
            "derived_fields": [
                "Relative times are offsets from the recorded attacker start.",
                "Offered attacker rates are inferred by adding recorded drop-counter deltas to recorded delivered flow rates.",
                "The first drop-counter observation establishes a baseline, so its drop rate is unknown and offered rates are lower bounds.",
                "No server-capacity estimate is available in this experiment, so server load and modeled client fields are null.",
            ],
        },
        "comparison": comparison,
        "trials": {
            "attack_off": _recorded_trial("m6-attack-off"),
            "attack_on": _recorded_trial("m6-attack-on"),
        },
        "comparison_traces": {
            "attack_off": attacker_windows(off_path, comparison_start_s, duration_s),
            "attack_on": attacker_windows(on_path, comparison_start_s, duration_s),
            "comparison_window_s": {
                "start": comparison_start_s,
                "end": duration_s,
                "source": "raw victim.jsonl attacker counts, offset from attack start; same window as experiments.analyze.compare",
            },
        },
    }
