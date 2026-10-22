"""Native presentation demos: real detector, historical SDN data, local UDP.

No virtual machines, elevated privileges, or external network traffic required.
"""

import argparse
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector
from experiments.analyze import compare, summarize_trial


def detector_demo(step=False):
    print("\nDETECTOR WALKTHROUGH — simulated counters, actual detection code", flush=True)
    config = json.loads((ROOT / "config/detector.json").read_text())
    tracker = CounterTracker()
    detector = TwoWindowDetector(config["victim_pps"], config["source_pps"],
                                 config["min_sources"], config["consecutive_windows"],
                                 config["protected_sources"])
    print(f"Victim threshold: >{config['victim_pps']:g} packets/s; source threshold: "
          f">{config['source_pps']:g} packets/s; at least {config['min_sources']} sources "
          f"for {config['consecutive_windows']} consecutive windows.")
    print("Protected client: 10.0.0.11. Each simulated window is one second.")
    sources = ("10.0.0.21", "10.0.0.22", "10.0.0.11")
    totals = dict.fromkeys(sources, 0)

    def counters():
        return [FlowCounter(source, "10.0.0.10", "demo", total, total * 128)
                for source, total in totals.items()]

    tracker.sample(0, counters())
    windows = [
        ("Normal traffic", (2, 2, 10), None),
        ("One-window burst", (70, 70, 10), None),
        ("Traffic returns to normal", (2, 2, 10), None),
        ("Sustained flood: first high window", (600, 600, 10), None),
        ("Sustained flood: second high window", (600, 600, 10), {"10.0.0.21", "10.0.0.22"}),
        ("Counter input after modeled drops", (0, 0, 10), None),
        ("Second flood: first high window", (600, 600, 10), None),
        ("Second flood: detector rearms", (600, 600, 10), {"10.0.0.21", "10.0.0.22"}),
    ]
    for index, (label, increments, expected_sources) in enumerate(windows, 1):
        if step:
            input("\nPress Enter for the next window...")
        for source, count in zip(sources, increments):
            totals[source] += count
        rates = tracker.sample(index, counters())
        alert = detector.observe(rates)
        actual_sources = None if alert is None else set(alert["sources"])
        if actual_sources != expected_sources:
            raise RuntimeError(f"Unexpected detector result at window {index}: {alert}")
        print(f"\n{index}. {label}\n"
              f"   a1={increments[0]}  a2={increments[1]}  client={increments[2]} packets/s\n"
              f"   victim={rates['victim_pps']:.0f} packets/s; "
              f"high-window count={detector.high_windows}; alert={'YES' if alert else 'no'}", flush=True)
        if alert:
            print(f"   Offenders: {', '.join(sorted(alert['sources']))}\n"
                  f"   Controller policy: drop their UDP to 10.0.0.10:9000 for "
                  f"{config['mitigation_hard_timeout_s']} seconds.\n"
                  "   This walkthrough computes decisions; it does not install switch rules.")
    print("\nObserved: a short burst did not alert; sustained traffic alerted; a low window rearmed detection.")


def recorded_demo():
    print("\nRECORDED SDN EXPERIMENT — original raw data from 13 October 2026", flush=True)
    result = compare(ROOT / "results/m6-attack-off", ROOT / "results/m6-attack-on")
    baseline = summarize_trial(ROOT / "results/m4-baseline")
    on, off = result["attack_on"], result["attack_off"]
    print("Two sources at 600 packets/s each; 8-second traffic phase.\n"
          f"Baseline alerts: {baseline['alerts']}\n"
          f"First detection: {on['first_alert_latency_s']:.3f} seconds\n"
          f"First barrier reply (saved as drop_confirmed): {on['first_drop_confirmation_latency_s']:.3f} seconds\n"
          f"Compared victim-received attacker rate with mitigation off: {result['unmitigated_attacker_pps']:.2f} packets/s\n"
          f"Compared victim-received attacker rate with mitigation on:  {result['mitigated_attacker_pps']:.2f} packets/s\n"
          f"Comparison starts {result['comparison_start_s']:.3f} seconds after attack start.\n"
          f"Legitimate probes, off: {off['client']['received']}/{off['client']['sent']}\n"
          f"Legitimate probes, on:  {on['client']['received']}/{on['client']['sent']}\n"
          f"Drop rules remaining after recovery: {on['drop_rules_after_recovery']}\n"
          "These recorded results show filtering in the original lab. Both modes had zero client loss,\n"
          "so they do not establish improved availability under saturation.")
    print("Chart: results/m6-rate-comparison.png\n"
          "Raw evidence: controller.jsonl, victim.jsonl, client.csv, flows-during.txt in each trial folder.")
    trial = ROOT / "results/m6-attack-on"
    print("\nACTUAL SAVED OPENFLOW RULES (historical, not installed by this command):")
    drop_lines = [line.strip() for line in (trial / "flows-during.txt").read_text().splitlines()
                  if "cookie=0xdd05000000000005" in line.lower()]
    for line in drop_lines:
        print("  " + line)
    print("Read one rule: priority 200 overrides forwarding; UDP source + victim + port 9000\n"
          "select the service; actions=drop discards it; hard_timeout=10 removes it after 10s.\n"
          "n_packets is the switch's saved match counter. No client-source drop rule appears.\n"
          "A barrier acknowledges ordering. The saved flow table and victim measurements\n"
          "supply additional evidence of filtering; the barrier alone is insufficient.")
    print("\nSELECTED SAVED CONTROLLER EVENTS:")
    for line in (trial / "controller.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record["type"] in ("alert", "drop_requested", "drop_confirmed"):
            print("  " + line)


BENCHMARK_PATH = ROOT / "results/benchmarks/detector-benchmark.json"
DETECTOR_LABELS = {"threshold": "Two-window threshold", "ewma": "EWMA control chart",
                   "cusum": "CUSUM change detector", "entropy": "Traffic-mix divergence (KL)"}


def _scenario_order(names):
    """Benchmark scenarios in catalogue order (demo/scenarios.py), unknown ones last."""
    try:
        from demo.scenarios import SCENARIOS
        catalogue = list(SCENARIOS)
    except ImportError:
        catalogue = []
    return [name for name in catalogue if name in names] + sorted(set(names) - set(catalogue))


def _benchmark_cell(row):
    if row.get("benign"):
        return f"FP {row['false_positive_runs']}/{row['runs']}"
    rate = row.get("detection_rate") or 0.0
    latency = row.get("median_latency_s")
    return f"{rate * 100:.0f}%" + (f" ({latency:g} s)" if latency is not None else "")


def benchmark_lines(data):
    """Matrix and data-driven interpretation of the committed detector benchmark."""
    detectors = list(data["detectors"])
    results = data["results"]
    parameters = data.get("parameters", {})
    scenarios = _scenario_order({name for detector in detectors for name in results[detector]})
    width = max(len("scenario"), *(len(name) + len(" (benign)") for name in scenarios))
    lines = [f"Seeds: {parameters.get('seeds', '?')} per cell (base {parameters.get('seed_base', '?')}), "
             f"{parameters.get('pps_per_attacker', '?')} packets/s per attacker; "
             f"config digest {str(parameters.get('config_digest', ''))[:12]}.", ""]
    header = "scenario".ljust(width) + "".join(f" | {name:>13}" for name in detectors)
    lines += [header, "-" * len(header)]
    for scenario in scenarios:
        benign = results[detectors[0]][scenario].get("benign")
        label = scenario + (" (benign)" if benign else "")
        lines.append(label.ljust(width) + "".join(
            f" | {_benchmark_cell(results[name][scenario]):>13}" for name in detectors))
    lines += ["", "Read: % = share of seeded runs that alerted during the attack; (n s) = median latency",
              "from attack start. FP a/b = runs with any alert where no alert is wanted.", "", "What it shows:"]
    for scenario in scenarios:
        rows = {name: results[name][scenario] for name in detectors}
        if next(iter(rows.values())).get("benign"):
            noisy = [name for name, row in rows.items() if row["false_positive_runs"]]
            if noisy:
                quiet = [name for name in detectors if name not in noisy]
                lines.append(f"  {scenario}: false alerts from {', '.join(noisy)}"
                             + (f"; only {', '.join(quiet)} stayed quiet." if quiet else "; no detector stayed quiet."))
            continue
        missed = [name for name, row in rows.items() if (row.get("detection_rate") or 0) < 0.5]
        if missed and len(missed) < len(detectors):
            caught = [name for name in detectors if name not in missed]
            lines.append(f"  {scenario}: missed in most runs by {', '.join(missed)}; caught by {', '.join(caught)}.")
        elif missed:
            lines.append(f"  {scenario}: no detector catches it reliably.")
    roc = data.get("roc") or {}
    if roc:
        lines += ["", "One tuning knob per detector (shipped value, true- and false-positive rate):"]
        for name in detectors:
            entry = roc.get(name)
            if not entry:
                continue
            point = next((p for p in entry["points"] if float(p["value"]) == float(entry["shipped_value"])), None)
            detail = f"TPR {point['tpr']:.2f}, FPR {point['fpr']:.2f}" if point else "not swept"
            lines.append(f"  {name:<9} {entry['knob']} = {entry['shipped_value']:g}: {detail}")
    lines += ["", "No single detector wins every row: each choice trades missed attacks against false alerts.",
              "Provenance: " + (data.get("provenance", {}).get("method") or "simulated counters, real detector code") + ".",
              "Regenerate: python3 experiments/benchmark_detectors.py --roc   (verify: --check)"]
    return lines


def benchmark_demo():
    print("\nOFFLINE DETECTOR BENCHMARK — simulated scenarios, real detector code", flush=True)
    data = json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))
    print("\n".join(benchmark_lines(data)), flush=True)


def loopback_demo():
    print("\nLIVE LOCAL UDP — real echo service and probe, no SDN switch or flood", flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="flowguard-demo-") as directory:
        log_path = Path(directory) / "server.log"
        with log_path.open("w+") as log:
            server = subprocess.Popen(
                [sys.executable, "-u", str(ROOT / "traffic/echo_server.py"),
                 "--bind", "127.0.0.1", "--port", str(port)],
                stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 5
                while "UDP echo listening" not in log_path.read_text():
                    if server.poll() is not None:
                        raise RuntimeError("Echo server failed: " + log_path.read_text())
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Echo server did not become ready")
                    time.sleep(0.05)
                result = subprocess.run(
                    [sys.executable, str(ROOT / "traffic/probe.py"), "--target", "127.0.0.1",
                     "--port", str(port), "--count", "10", "--interval-ms", "100"],
                    capture_output=True, text=True, timeout=15,
                )
                print(log_path.read_text().strip())
                print(result.stdout, end="")
                print(result.stderr, end="")
                if result.returncode:
                    raise RuntimeError("The local probe did not receive every echo reply")
            finally:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)
    print("Local networking demo passed; echo service stopped.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("detector", "recorded", "loopback", "bugs", "benchmark", "all"), default="all")
    parser.add_argument("--step", action="store_true", help="Pause between simulated detector windows")
    args = parser.parse_args()
    if args.step and not sys.stdin.isatty():
        parser.error("--step requires an interactive terminal; omit it for an automatic walkthrough")
    if args.scenario in ("detector", "all"):
        detector_demo(args.step)
    if args.scenario in ("recorded", "all"):
        recorded_demo()
    if args.scenario in ("loopback", "all"):
        loopback_demo()
    if args.scenario == "benchmark":
        benchmark_demo()
    if args.scenario == "bugs":
        print("OFFLINE REGRESSION CHECKS — passing tests verify current hardening and experiment integrity", flush=True)
        subprocess.run([sys.executable, str(ROOT / "audit/reproduce.py")], check=True)


if __name__ == "__main__":
    main()
