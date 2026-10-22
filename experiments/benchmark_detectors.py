"""Benchmark every flood detector against every traffic scenario over seeded runs.

Each run feeds per-second cumulative flow counters (the scenario's offered
rates with seeded Poisson noise, mitigation off) through the real
CounterTracker and the detector built from the shipped configuration. The
window reported at t covers [t - 1, t), so a detector needing two high
windows on an attack starting at 5 s alerts at t = 7: a 2 s latency.

    python3 experiments/benchmark_detectors.py --seeds 20 --seed-base 1729 \
        --output results/benchmarks --roc
    python3 experiments/benchmark_detectors.py --check   # verify committed outputs

Outputs are byte-deterministic (no wall-clock fields). Standard library only.
"""

from __future__ import annotations

import argparse
import copy
import csv
import io
import json
import math
import random
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    # A script run puts experiments/ first on sys.path, where demo.py would
    # shadow the top-level demo package that holds the scenarios.
    sys.path[:] = [entry for entry in sys.path if Path(entry or ".").resolve() != ROOT / "experiments"]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.config import DEFAULT_CONFIG, config_digest, load_config, validate_config
from controller.detection import CounterTracker, FlowCounter
from controller.detectors import DETECTOR_NAMES, build_detector
from demo.scenarios import SCENARIOS, VICTIM

DEFAULT_SEEDS = 20
DEFAULT_SEED_BASE = 1729
DEFAULT_PPS = 600
DEFAULT_OUTPUT = ROOT / "results" / "benchmarks"
PACKET_BYTES = 128
OUTPUT_NAMES = ("detector-benchmark.json", "detector-benchmark.csv", "detector-benchmark.md")
PROVENANCE = ("simulated per-second counters with seeded Poisson noise fed to the real detector "
              "classes; no network traffic")
# One knob per detector: (config path, swept values).
ROC_KNOBS = {
    "threshold": (("source_pps",), (10, 20, 30, 50, 100)),
    "ewma": (("detectors", "ewma", "k_sigma"), (2, 3, 4, 6, 8)),
    "cusum": (("detectors", "cusum", "threshold_h"), (2, 4, 6, 8, 12)),
    "entropy": (("detectors", "entropy", "kl_threshold_bits"), (0.1, 0.25, 0.5, 1, 2)),
}
CSV_FIELDS = ("detector", "scenario", "benign", "runs", "detection_rate", "median_latency_s",
              "p95_latency_s", "false_positive_runs", "fp_rate_per_benign_window",
              "false_alert_active_rate", "source_tp", "source_fp", "source_fn")


def traffic(scenario, seed, pps=DEFAULT_PPS):
    """CounterTracker samples for one run of a scenario (t = 1 .. duration); seed None is noise-free."""
    rng = None if seed is None else random.Random(f"{scenario.id}:{seed}")
    tracker = CounterTracker()
    cumulative = dict.fromkeys(scenario.sources, 0)
    tracker.sample(0, [FlowCounter(source, VICTIM, "benchmark", 0, 0) for source in scenario.sources])
    samples = []
    for t_s in range(1, scenario.duration_s + 1):
        offered = scenario.offered(t_s - 1, pps, rng)
        for source in scenario.sources:
            cumulative[source] += offered[source]
        samples.append(tracker.sample(t_s, [
            FlowCounter(source, VICTIM, "benchmark", cumulative[source], cumulative[source] * PACKET_BYTES)
            for source in scenario.sources]))
    return samples


def run_once(detector, scenario, samples, consecutive_windows):
    """Detection-only metrics for one run; mitigation never changes the traffic."""
    expected = frozenset() if scenario.benign else scenario.attackers
    first_attack = None if scenario.benign else scenario.first_attack_s()
    alerts, flagged = [], set()
    latency = None
    false_alerts = false_active = benign_windows = 0
    for t_s, rates in enumerate(samples, start=1):
        alert = detector.observe(rates)
        attack_recent = not scenario.benign and any(
            scenario.is_active(second) for second in range(t_s - consecutive_windows - 1, t_s))
        if alert:
            alerts.append(t_s)
            flagged.update(alert["sources"])
            if attack_recent and latency is None:
                latency = t_s - first_attack
        if detector.alert_active:
            flagged.update(detector.qualifying_sources(rates))
        if not attack_recent:
            benign_windows += 1
            false_alerts += bool(alert)
            false_active += detector.alert_active
    return {
        "alerted": bool(alerts),
        "alert_times_s": alerts,
        "detection_latency_s": latency,
        "false_alert_windows": false_alerts,
        "false_alert_active_windows": false_active,
        "benign_windows": benign_windows,
        "source_tp": len(flagged & expected),
        "source_fp": len(flagged - expected),
        "source_fn": len(expected - flagged),
    }


def _percentile(values, fraction):
    """Nearest-rank percentile of a non-empty list."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def aggregate(runs, scenario):
    """Summary of one detector x scenario cell."""
    latencies = [run["detection_latency_s"] for run in runs if run["detection_latency_s"] is not None]
    benign_windows = sum(run["benign_windows"] for run in runs)
    return {
        "runs": len(runs),
        "benign": scenario.benign,
        "detection_rate": None if scenario.benign else round(len(latencies) / len(runs), 4),
        "median_latency_s": statistics.median(latencies) if latencies else None,
        "p95_latency_s": _percentile(latencies, 0.95) if latencies else None,
        "false_positive_runs": sum(run["false_alert_windows"] > 0 for run in runs),
        "fp_rate_per_benign_window": round(
            sum(run["false_alert_windows"] for run in runs) / benign_windows, 5) if benign_windows else 0.0,
        "false_alert_active_rate": round(
            sum(run["false_alert_active_windows"] for run in runs) / benign_windows, 5) if benign_windows else 0.0,
        "source_tp": sum(run["source_tp"] for run in runs),
        "source_fp": sum(run["source_fp"] for run in runs),
        "source_fn": sum(run["source_fn"] for run in runs),
    }


def _with_override(config, detector, path=None, value=None):
    result = copy.deepcopy(config)
    result["detector"] = detector
    if path is not None:
        target = result
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return validate_config(result)


def _run_config(config, traces):
    """Run one detector configuration over every cached trace."""
    runs = {}
    for (scenario_id, seed), samples in traces.items():
        detector = build_detector(config)
        runs[(scenario_id, seed)] = run_once(detector, SCENARIOS[scenario_id], samples,
                                             config["consecutive_windows"])
    return runs


def run_benchmark(seeds=DEFAULT_SEEDS, seed_base=DEFAULT_SEED_BASE, roc=False, config=None, pps=DEFAULT_PPS):
    """Return the full, JSON-safe benchmark result (deterministic for fixed inputs)."""
    if not isinstance(seeds, int) or seeds < 1:
        raise ValueError("seeds must be a positive integer")
    config = load_config(DEFAULT_CONFIG) if config is None else config
    seed_list = [seed_base + index for index in range(seeds)]
    traces = {(scenario_id, seed): traffic(scenario, seed, pps)
              for scenario_id, scenario in SCENARIOS.items() for seed in seed_list}

    results = {}
    for name in DETECTOR_NAMES:
        runs = _run_config(_with_override(config, name), traces)
        results[name] = {
            scenario_id: {
                **aggregate([runs[(scenario_id, seed)] for seed in seed_list], scenario),
                "per_seed_latency_s": [runs[(scenario_id, seed)]["detection_latency_s"] for seed in seed_list],
            }
            for scenario_id, scenario in SCENARIOS.items()
        }

    output = {
        "provenance": {
            "kind": "simulation",
            "method": PROVENANCE,
            "frames": "the sample at t covers the interval [t - 1, t); latency = first alert t - attack start",
            "false_alert": "an alert in a benign scenario, or with no attack in the past consecutive_windows + 1 s",
            "noise": "each source's per-second rate is a Poisson draw around the scenario's base rate",
            "generator": "experiments/benchmark_detectors.py",
        },
        "parameters": {"seeds": seeds, "seed_base": seed_base, "pps_per_attacker": pps, "roc": bool(roc),
                       "config_digest": config_digest(config)},
        "config": {key: config[key] for key in ("victim_pps", "source_pps", "min_sources",
                                                "consecutive_windows", "protected_sources", "detectors")},
        "scenarios": {
            scenario_id: {"label": scenario.label, "benign": scenario.benign,
                          "attackers": sorted(scenario.attackers),
                          "attack_intervals": [list(item) for item in scenario.attack_intervals],
                          "duration_s": scenario.duration_s}
            for scenario_id, scenario in SCENARIOS.items()
        },
        "detectors": list(DETECTOR_NAMES),
        "results": results,
    }
    if roc:
        output["roc"] = _roc(config, traces)
    return output


def _roc(config, traces):
    """Sweep one knob per detector: FPR over benign runs, TPR over attack runs."""
    curves = {}
    for name, (path, values) in ROC_KNOBS.items():
        points = []
        for value in values:
            runs = _run_config(_with_override(config, name, path, value), traces)
            attack = [run for key, run in runs.items() if not SCENARIOS[key[0]].benign]
            benign = [run for key, run in runs.items() if SCENARIOS[key[0]].benign]
            points.append({
                "value": value,
                "tpr": round(sum(run["detection_latency_s"] is not None for run in attack) / len(attack), 4),
                "fpr": round(sum(run["false_alert_windows"] > 0 for run in benign) / len(benign), 4),
            })
        shipped = config
        for key in path:
            shipped = shipped[key]
        curves[name] = {"knob": ".".join(path), "shipped_value": shipped, "points": points}
    return curves


def render_json(result):
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def render_csv(result):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for detector, scenarios in result["results"].items():
        for scenario_id, cell in scenarios.items():
            writer.writerow({"detector": detector, "scenario": scenario_id,
                             **{field: "" if cell.get(field) is None else cell[field]
                                for field in CSV_FIELDS[2:]}})
    return stream.getvalue()


def _cell(cell):
    if cell["benign"]:
        return f"FP {cell['false_positive_runs']}/{cell['runs']}"
    if cell["median_latency_s"] is None:
        return f"{cell['detection_rate']:.0%}"
    return f"{cell['detection_rate']:.0%} ({cell['median_latency_s']:g} s)"


def _interpretation(result):
    lines = []
    for detector, scenarios in result["results"].items():
        caught = [s for s, c in scenarios.items() if not c["benign"] and c["detection_rate"] >= 0.9]
        missed = [s for s, c in scenarios.items() if not c["benign"] and c["detection_rate"] < 0.5]
        noisy = [f"{s} ({c['false_positive_runs']}/{c['runs']})"
                 for s, c in scenarios.items() if c["benign"] and c["false_positive_runs"]]
        lines.append(f"- **{detector}** detects >=90% of runs in: {', '.join(caught) or 'none'}; "
                     f"misses (<50%): {', '.join(missed) or 'none'}; "
                     f"false-alarm runs on benign scenarios: {', '.join(noisy) or 'none'}.")
    return lines


def render_markdown(result):
    params = result["parameters"]
    detectors = result["detectors"]
    lines = [
        "# Detector benchmark",
        "",
        f"Provenance: {result['provenance']['method']}.",
        f"Seeds {params['seeds']} (base {params['seed_base']}), {params['pps_per_attacker']} pps per "
        f"attacker, configuration digest `{params['config_digest'][:12]}`. "
        "Regenerate with `python3 experiments/benchmark_detectors.py --roc`; "
        "verify with `--check`.",
        "",
        "## Detection rate (median latency) and false-positive runs",
        "",
        "Attack scenarios show the share of runs with an alert during the attack and the median "
        "latency from attack start. Benign scenarios (no alert wanted) show runs with any alert.",
        "",
        "| scenario | " + " | ".join(detectors) + " |",
        "|---|" + "---|" * len(detectors),
    ]
    for scenario_id, info in result["scenarios"].items():
        label = scenario_id + (" (benign)" if info["benign"] else "")
        lines.append(f"| {label} | " + " | ".join(_cell(result["results"][d][scenario_id]) for d in detectors) + " |")
    lines += ["", "## Latency and source attribution", "",
              "| detector | scenario | p95 latency s | FP rate / benign window | alert-active rate (benign) "
              "| source TP | source FP | source FN |",
              "|---|---|---|---|---|---|---|---|"]
    for detector in detectors:
        for scenario_id, cell in result["results"][detector].items():
            p95 = "-" if cell["p95_latency_s"] is None else f"{cell['p95_latency_s']:g}"
            lines.append(f"| {detector} | {scenario_id} | {p95} | {cell['fp_rate_per_benign_window']:.4f} | "
                         f"{cell['false_alert_active_rate']:.4f} | {cell['source_tp']} | {cell['source_fp']} | "
                         f"{cell['source_fn']} |")
    if "roc" in result:
        lines += ["", "## Operating points (one knob per detector)", "",
                  "TPR: attack runs detected. FPR: benign runs (normal, burst, flash-crowd) with any alert.", "",
                  "| detector | knob | value | TPR | FPR |", "|---|---|---|---|---|"]
        for detector, curve in result["roc"].items():
            for point in curve["points"]:
                marker = " (shipped)" if point["value"] == curve["shipped_value"] else ""
                lines.append(f"| {detector} | {curve['knob']} | {point['value']:g}{marker} | "
                             f"{point['tpr']:.3f} | {point['fpr']:.3f} |")
    lines += ["", "## Interpretation", "", *_interpretation(result), "",
              "These figures come from a model: Poisson-noised per-second counters, no queueing, packet "
              "loss or polling jitter, and mitigation disabled so every detector sees the whole attack. "
              "They compare detector logic, not end-to-end lab performance.", ""]
    return "\n".join(lines)


def render_all(result):
    return dict(zip(OUTPUT_NAMES, (render_json(result), render_csv(result), render_markdown(result))))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=DEFAULT_SEEDS)
    parser.add_argument("--seed-base", type=int, default=DEFAULT_SEED_BASE)
    parser.add_argument("--pps", type=int, default=DEFAULT_PPS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--roc", action="store_true", help="also sweep one knob per detector")
    parser.add_argument("--check", action="store_true",
                        help="regenerate with the committed parameters and fail if any output differs")
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else Path.cwd() / args.output

    if args.check:
        path = output / OUTPUT_NAMES[0]
        try:
            params = json.loads(path.read_text(encoding="utf-8"))["parameters"]
        except (OSError, ValueError, KeyError) as exc:
            print(f"cannot read committed benchmark {path}: {exc}", file=sys.stderr)
            return 2
        rendered = render_all(run_benchmark(params["seeds"], params["seed_base"], params["roc"],
                                            pps=params["pps_per_attacker"]))
        stale = [name for name, text in rendered.items()
                 if not (output / name).is_file() or (output / name).read_text(encoding="utf-8") != text]
        if stale:
            print(f"benchmark outputs differ from a fresh run: {', '.join(stale)}", file=sys.stderr)
            return 1
        print(f"benchmark outputs in {output} are up to date")
        return 0

    result = run_benchmark(args.seeds, args.seed_base, args.roc, pps=args.pps)
    output.mkdir(parents=True, exist_ok=True)
    for name, text in render_all(result).items():
        (output / name).write_text(text, encoding="utf-8")
    print(render_markdown(result).split("## Latency")[0].rstrip())
    print(f"\nwrote {', '.join(OUTPUT_NAMES)} to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
