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


def show_event(event, state):
    kind = event.get("type")
    if kind == "sample":
        sources = event.get("source_pps", {})
        attackers = sum(sources.get(source, 0) for source in ("10.0.0.21", "10.0.0.22"))
        qualifying = sum(rate > state["source_threshold"] for rate in sources.values())
        if (state["flood_seen"] and not state["first_high_seen"]
                and event.get("victim_pps", 0) > state["victim_threshold"]
                and qualifying >= state["min_sources"]):
            print(f"MEASURE first high counter window: victim {event['victim_pps']:.0f} pps; "
                  f"attackers {attackers:.0f} pps combined", flush=True)
            print("        Controller waits for a second qualifying window before alerting.", flush=True)
            state["first_high_seen"] = True
        dropped = sum(event.get("drop_packet_delta", {}).values())
        if (state["block_seen"] and not state["post_block_seen"]
                and dropped > 0 and attackers < 1):
            print(f"VERIFY  switch counters: attackers forwarded {attackers:.0f} pps; "
                  f"drop rules matched {dropped} packets in this poll", flush=True)
            print(f"        Protected client still has a forwarding flow "
                  f"({sources.get('10.0.0.11', 0):.0f} pps); replies are checked below.", flush=True)
            state["post_block_seen"] = True
    elif kind == "alert":
        rates = ", ".join(f"{src}: {rate:.0f} pps" for src, rate in sorted(event["sources"].items()))
        print(f"ALERT   two high windows: victim {event['victim']} at "
              f"{event['victim_pps']:.0f} pps; {rates}", flush=True)
        print("        Both senders exceeded the source threshold; the client is protected.", flush=True)
    elif kind == "drop_requested":
        print(f"RULE    request UDP drop {event['source']} -> "
              f"{event['victim']}:{event['port']} "
              f"for {event['hard_timeout_s']} s", flush=True)
    elif kind == "drop_confirmed":
        print(f"BLOCK   OpenFlow barrier confirms switch rules for "
              f"{', '.join(event['sources'])}", flush=True)
        state["block_seen"] = True
    elif kind == "drop_removed":
        print(f"EXPIRE  rule for {event['source']} removed after timeout; "
              f"{event['packets']} packets blocked", flush=True)


def attack_event_seen(output, wanted):
    for host in ("a1", "a2"):
        path = output / f"attack-{host}.jsonl"
        if not path.exists():
            return False
        try:
            if not any(json.loads(line).get("event") == wanted
                       for line in path.read_text(encoding="utf-8").splitlines() if line):
                return False
        except json.JSONDecodeError:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None,
                        help="new output folder inside this repository")
    parser.add_argument("--pps", type=int, default=600)
    parser.add_argument("--duration-s", type=int, default=8)
    parser.add_argument("--pcap", action="store_true",
                        help="capture four switch ports into a Wireshark pcapng file")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root in Ubuntu; Mininet needs network namespaces")
    if not 1 <= args.pps <= 2000 or not 2 <= args.duration_s <= 30:
        parser.error("pps must be 1..2000 and duration-s must be 2..30")
    output = (args.output or ROOT / "results" / f"demo-{datetime.now():%Y%m%d-%H%M%S}").resolve()
    if ROOT not in output.parents or output.exists():
        parser.error("output must be a new subdirectory of this repository")
    output.mkdir(parents=True)

    config = json.loads((ROOT / "config" / "detector.json").read_text(encoding="utf-8"))
    print("FlowGuard live demo: private Mininet switch, two UDP senders, one legitimate client", flush=True)
    print("Topology: a1 10.0.0.21 + a2 10.0.0.22 -> Open vSwitch s1 "
          "-> victim 10.0.0.10:9000", flush=True)
    print("          protected client 10.0.0.11 uses the same victim service", flush=True)
    print(f"Policy: 1-s counter polls; victim >{config['victim_pps']:g} pps; "
          f"each source >{config['source_pps']:g} pps; "
          f"{config['consecutive_windows']} high windows; "
          f"{config['mitigation_hard_timeout_s']}-s drop timeout", flush=True)
    print(f"Traffic: {args.pps} UDP packets/s from each attacker for {args.duration_s} s; "
          "client probes at 10/s", flush=True)
    print("\n[1/5] BASELINE  starting controller, switch and five hosts...", flush=True)
    command = [sys.executable, "-u", str(ROOT / "experiments" / "run_trial.py"),
               "--mode", "attack-on", "--output", str(output),
               "--pps", str(args.pps), "--duration-s", str(args.duration_s)]
    if args.pcap:
        command.append("--pcap")
    with (output / "demo-runner.log").open("w", encoding="utf-8") as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        offset = 0
        normal_seen = False
        flood_stopped = False
        state = {"flood_seen": False, "first_high_seen": False,
                 "block_seen": False, "post_block_seen": False,
                 "victim_threshold": config["victim_pps"],
                 "source_threshold": config["source_pps"],
                 "min_sources": config["min_sources"]}
        try:
            while runner.poll() is None:
                if not normal_seen and "20/20 received" in (output / "demo-runner.log").read_text(encoding="utf-8"):
                    print("NORMAL  20/20 host pings succeeded; priming the UDP echo flows", flush=True)
                    normal_seen = True
                if not state["flood_seen"] and attack_event_seen(output, "start"):
                    print("\n[2/5] FLOOD     both senders started; the client continues probing", flush=True)
                    state["flood_seen"] = True
                events, offset = pending_events(output / "controller.jsonl", offset)
                for event in events:
                    if event.get("type") == "alert":
                        print("\n[3/5] DETECT AND BLOCK", flush=True)
                    show_event(event, state)
                if state["flood_seen"] and not flood_stopped and attack_event_seen(output, "stop"):
                    print("\n[4/5] RECOVERY  flood ended; waiting for the temporary rules to expire", flush=True)
                    flood_stopped = True
                time.sleep(0.2)
            events, offset = pending_events(output / "controller.jsonl", offset)
            for event in events:
                if event.get("type") == "alert":
                    print("\n[3/5] DETECT AND BLOCK", flush=True)
                show_event(event, state)
        except KeyboardInterrupt:
            print("Waiting for the trial to clean up Mininet...", flush=True)
            runner.send_signal(2)
            runner.wait(timeout=15)
            raise SystemExit(130)

    if runner.returncode:
        print(f"Trial failed (exit {runner.returncode}). Inspect {output / 'demo-runner.log'}", file=sys.stderr)
        return runner.returncode
    summary = summarize_trial(output)
    events, _ = pending_events(output / "controller.jsonl", 0)
    blocked_packets = sum(event["packets"] for event in events if event.get("type") == "drop_removed")
    print("\n[5/5] REVIEW SUMMARY")
    print(f"  Host connectivity: {100 - summary['ping_loss_percent']:.0f}%")
    print(f"  Alert latency: {summary['first_alert_latency_s']:.3f} s")
    print(f"  Switch confirmation: {summary['first_drop_confirmation_latency_s']:.3f} s")
    print(f"  Attacker packets counted by expired drop rules: {blocked_packets}")
    print(f"  Legitimate probes during attack: {summary['client']['received']}/{summary['client']['sent']}")
    print(f"  Legitimate probes after recovery: {summary['recovery_client']['received']}/{summary['recovery_client']['sent']}")
    print(f"  Drop rules after recovery: {summary['drop_rules_after_recovery']}")
    print("  Interpretation: selective filtering is shown; improved availability "
          "needs the separate OFF/ON comparison.")
    print(f"  Evidence: {output.relative_to(ROOT)} (inside this project)")
    if args.pcap:
        capture = json.loads((output / "capture-summary.json").read_text(encoding="utf-8"))
        print(f"  Wireshark file: {output.relative_to(ROOT) / capture['file']}")
        print("  Captured requests by observation point: " + ", ".join(
            f"{name}={count}" for name, count in capture["requests_seen"].items()))
        if capture["truncated"]:
            print("  Capture reached its 64 MiB limit; repeat at a lower rate for a full graph.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
