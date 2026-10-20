"""Show one bounded FlowGuard mitigation trial as a live review timeline."""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from analyze import summarize_trial


ROOT = Path(__file__).resolve().parents[1]


def pending_events(path, offset):
    if not path.exists():
        return [], offset
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read()
    events = []
    for line in data.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            break
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            break
        offset += len(line)
    return events, offset


def show_event(event):
    kind = event.get("type")
    if kind == "alert":
        rates = ", ".join(f"{src}: {rate:.0f} pps" for src, rate in sorted(event["sources"].items()))
        print(f"ALERT  victim {event['victim']} at {event['victim_pps']:.0f} pps; {rates}", flush=True)
    elif kind == "drop_confirmed":
        print(f"BLOCK  switch confirmed rules for {', '.join(event['sources'])}", flush=True)
    elif kind == "drop_removed":
        print(f"EXPIRE rule for {event['source']} removed; {event['packets']} packets blocked", flush=True)


def attack_started(output):
    for host in ("a1", "a2"):
        path = output / f"attack-{host}.jsonl"
        if not path.exists():
            return False
        try:
            first = path.read_text(encoding="utf-8").splitlines()[0]
            if json.loads(first).get("event") != "start":
                return False
        except (IndexError, json.JSONDecodeError):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None,
                        help="new output folder inside this repository")
    parser.add_argument("--pps", type=int, default=600)
    parser.add_argument("--duration-s", type=int, default=8)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root in Ubuntu; Mininet needs network namespaces")
    if not 1 <= args.pps <= 2000 or not 2 <= args.duration_s <= 30:
        parser.error("pps must be 1..2000 and duration-s must be 2..30")
    output = (args.output or ROOT / "results" / f"demo-{datetime.now():%Y%m%d-%H%M%S}").resolve()
    if ROOT not in output.parents or output.exists():
        parser.error("output must be a new subdirectory of this repository")
    output.mkdir(parents=True)

    print("FlowGuard live demo: private Mininet switch, two UDP senders, one legitimate client", flush=True)
    print(f"Attack: {args.pps} packets/s per sender for {args.duration_s} s; victim 10.0.0.10:9000", flush=True)
    print("Starting controller, switch, hosts, and normal connectivity checks...", flush=True)
    command = [sys.executable, "-u", str(ROOT / "experiments" / "run_trial.py"),
               "--mode", "attack-on", "--output", str(output),
               "--pps", str(args.pps), "--duration-s", str(args.duration_s)]
    with (output / "demo-runner.log").open("w", encoding="utf-8") as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        offset = 0
        normal_seen = False
        flood_seen = False
        try:
            while runner.poll() is None:
                if not normal_seen and "20/20 received" in (output / "demo-runner.log").read_text(encoding="utf-8"):
                    print("NORMAL 20/20 host pings succeeded; checking UDP echo flows", flush=True)
                    normal_seen = True
                if not flood_seen and attack_started(output):
                    print("FLOOD  two private sources started; legitimate client continues probing", flush=True)
                    flood_seen = True
                events, offset = pending_events(output / "controller.jsonl", offset)
                for event in events:
                    show_event(event)
                time.sleep(0.2)
            events, offset = pending_events(output / "controller.jsonl", offset)
            for event in events:
                show_event(event)
        except KeyboardInterrupt:
            print("Waiting for the trial to clean up Mininet...", flush=True)
            runner.send_signal(2)
            runner.wait(timeout=15)
            raise SystemExit(130)

    if runner.returncode:
        print(f"Trial failed (exit {runner.returncode}). Inspect {output / 'demo-runner.log'}", file=sys.stderr)
        return runner.returncode
    summary = summarize_trial(output)
    print("\nReview summary")
    print(f"  Host connectivity: {100 - summary['ping_loss_percent']:.0f}%")
    print(f"  Alert latency: {summary['first_alert_latency_s']:.3f} s")
    print(f"  Switch confirmation: {summary['first_drop_confirmation_latency_s']:.3f} s")
    print(f"  Legitimate probes during attack: {summary['client']['received']}/{summary['client']['sent']}")
    print(f"  Legitimate probes after recovery: {summary['recovery_client']['received']}/{summary['recovery_client']['sent']}")
    print(f"  Drop rules after recovery: {summary['drop_rules_after_recovery']}")
    print(f"  Evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
