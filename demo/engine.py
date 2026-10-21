"""Dashboard data model for FlowGuard's native, local presentation."""

from __future__ import annotations

import csv
import json
import math
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector
from experiments.analyze import ATTACKERS, attacker_windows, compare, flood_start, summarize_trial


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

ATTACKER_NAMES = ("10.0.0.21", "10.0.0.22")
CLIENT = "10.0.0.11"
VICTIM = "10.0.0.10"
DURATION_S = 30
ATTACK_START_S = 5
PACKET_BYTES = 128


def detector_config() -> dict:
    return json.loads((ROOT / "config/detector.json").read_text(encoding="utf-8"))


def bootstrap_data(csrf_token: str) -> dict:
    config = detector_config()
    return {
        "provenance": {
            "simulation": {
                "kind": "simulation",
                "label": "Deterministic model using the project's actual CounterTracker and TwoWindowDetector code.",
                "scope": "No switch rules are installed and no attack traffic is sent.",
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
        "scenarios": [dict(item) for item in SCENARIOS],
        "simulation_defaults": {
            "scenario": "sustained",
            "mitigation": True,
            "pps_per_attacker": 600,
            "hypothetical_server_capacity_pps": 1000,
            "duration_s": DURATION_S,
            "attack_start_s": ATTACK_START_S,
        },
        "csrf_token": csrf_token,
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


def simulate(
    scenario: str = "sustained",
    mitigation=True,
    pps: int = 600,
    capacity: int = 1000,
    victim_pps: float | None = None,
    source_pps: float | None = None,
    min_sources: int | None = None,
    consecutive_windows: int | None = None,
) -> dict:
    """Create a 30 second deterministic trace driven by the real detector classes."""
    if scenario not in {item["id"] for item in SCENARIOS}:
        raise ValueError(f"unknown scenario: {scenario}")
    if not isinstance(pps, int) or pps < 1 or pps > 100_000:
        raise ValueError("pps must be an integer between 1 and 100000")
    if not isinstance(capacity, int) or capacity < 1 or capacity > 1_000_000:
        raise ValueError("capacity must be an integer between 1 and 1000000")

    base_config = detector_config()
    config = dict(base_config)
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
    tracker = CounterTracker()
    detector = TwoWindowDetector(
        config["victim_pps"],
        config["source_pps"],
        config["min_sources"],
        config["consecutive_windows"],
        config["protected_sources"],
    )
    sources = (*ATTACKER_NAMES, CLIENT)
    cumulative = dict.fromkeys(sources, 0)
    initial = [FlowCounter(source, VICTIM, "dashboard-sim", 0, 0) for source in sources]
    tracker.sample(0, initial)

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
    }]
    packet_rows: list[dict] = []
    active_rules: dict[str, float] = {}
    ever_attack = False
    previous_attack_active = False
    first_alert_s = None
    alert_count = 0
    peak_ingress = 0
    peak_drop = 0

    def log_event(t_s, event_type, message, source=None):
        event = {"t_s": t_s, "type": event_type, "message": message}
        if source is not None:
            event["source"] = source
        events.append(event)

    for t_s in range(1, DURATION_S + 1):
        interval_start = t_s - 1
        attack_active = _is_attack_active(scenario, interval_start, t_s)
        if attack_active:
            ever_attack = True
            if not previous_attack_active:
                log_event(interval_start, "attack_started", "Attacker traffic begins in the modeled interval.")
        elif previous_attack_active:
            log_event(interval_start, "attack_ended", "Attacker traffic stops in the modeled interval.")

        offered = _offered_rates(scenario, interval_start, t_s, pps)
        dropped: dict[str, int] = {}
        delivered: dict[str, int] = {}
        for source in sources:
            is_filtered = source in active_rules and interval_start < active_rules[source]
            drop_rate = offered[source] if is_filtered else 0
            delivered_rate = offered[source] - drop_rate
            dropped[source] = drop_rate
            delivered[source] = delivered_rate
            cumulative[source] += delivered_rate
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
        alert = detector.observe(rates)
        if alert:
            alert_count += 1
            first_alert_s = t_s if first_alert_s is None else first_alert_s
            offenders = sorted(alert["sources"])
            log_event(
                t_s,
                "alert",
                f"Two-window detector alert: victim {alert['victim_pps']:.0f} pps; offenders {', '.join(offenders)}.",
            )
            if mitigation:
                for source in offenders:
                    active_rules[source] = t_s + int(config["mitigation_hard_timeout_s"])
                    log_event(
                        t_s,
                        "drop_requested",
                        f"Modeled 10 second drop rule requested for UDP to {VICTIM}:9000.",
                        source,
                    )
                log_event(t_s, "drop_confirmed", "Modeled drop rules active; no switch was contacted.")

        expired = [source for source, expires_at in active_rules.items() if expires_at <= t_s]
        for source in sorted(expired):
            del active_rules[source]
            log_event(t_s, "rule_expired", "Modeled 10 second drop rule expired.", source)

        ingress_pps = sum(offered.values())
        drop_pps = sum(dropped.values())
        victim_delivered_pps = sum(delivered.values())
        load_ratio = victim_delivered_pps / capacity
        success = min(1.0, capacity / victim_delivered_pps) if victim_delivered_pps else 1.0
        # A deliberately simple hypothetical queue model: 2 ms baseline, rising
        # as utilization approaches capacity and capped at 200 ms under overload.
        latency_ms = min(200.0, 2.0 / max(0.01, 1.0 - min(load_ratio, 0.99)))
        if active_rules:
            state = "mitigating"
        elif attack_active or detector.high_windows > 0 or detector.alert_active:
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
            "high_windows": detector.high_windows,
            "detector_alert": bool(alert),
            "detector_input": {
                "victim_pps": rates["victim_pps"],
                "source_pps": dict(rates["source_pps"]),
            },
            "state": state,
            "active_rules": [
                {"source": source, "expires_at_s": expires_at, "status": "modeled drop", "target": f"{VICTIM}:9000"}
                for source, expires_at in sorted(active_rules.items())
            ],
        })
        previous_attack_active = attack_active

    scenario_info = next(item for item in SCENARIOS if item["id"] == scenario)
    return {
        "mode": "simulation",
        "provenance": {
            "kind": "simulation",
            "label": "Deterministic simulation using the actual CounterTracker and TwoWindowDetector implementation.",
            "warning": "This model does not contact Open vSwitch or install enforcement rules.",
        },
        "scenario": dict(scenario_info),
        "parameters": {
            "scenario": scenario,
            "mitigation": mitigation,
            "pps_per_attacker": pps,
            "hypothetical_server_capacity_pps": capacity,
        },
        "thresholds": {
            "victim_pps": config["victim_pps"],
            "source_pps": config["source_pps"],
            "min_sources": config["min_sources"],
            "consecutive_windows": config["consecutive_windows"],
            "protected_sources": config["protected_sources"],
            "mitigation_hard_timeout_s": config["mitigation_hard_timeout_s"],
        },
        "timeline": {"duration_s": DURATION_S, "step_s": 1, "attack_start_s": ATTACK_START_S},
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
            "assumption": (
                "Server capacity is a hypothetical packets-per-second input. Client success is modeled as "
                "capacity/delivered traffic under overload, and latency is a simple queue estimate. Neither "
                "is a measured server result."
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
