"""Show one bounded FlowGuard mitigation trial as a live review timeline.

With ``--compare`` it runs the same trial twice, mitigation OFF then ON, and
prints the client-availability comparison from analyze.compare. Add
``--bottleneck`` (0.5 Mbit/s, 50-packet queue on the switch port toward the
victim) so that the flood actually congests the victim link; without it the
client is not congested and both runs normally show no client loss.
"""

import argparse
import errno
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

EXPERIMENTS = str(Path(__file__).resolve().parent)
if EXPERIMENTS not in sys.path:
    sys.path.insert(0, EXPERIMENTS)
from analyze import compare, summarize_trial  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # for controller.config
    sys.path.insert(0, str(ROOT))
from controller.config import DETECTOR_NAMES, MITIGATION_ACTIONS, apply_overrides, load_config  # noqa: E402

# Matches topology/lab_topology.py BOTTLENECK_PRESET (see its sizing notes).
BOTTLENECK_PRESET = {"mbit": 0.5, "queue_packets": 50}
FLOOD_FRAME_BYTES = 170  # 14 Ethernet + 20 IPv4 + 8 UDP + 128 payload

STAGES = {
    "attack-on": {"detect": "\n[3/5] DETECT AND BLOCK",
                  "recovery": "\n[4/5] RECOVERY  flood ended; waiting for the temporary rules to expire"},
    "attack-off": {"detect": "\n[3/5] DETECT    mitigation is OFF: alerts are logged, no switch rules",
                   "recovery": "\n[4/5] RECOVERY  flood ended; waiting for the recovery probe"},
}


def read_text_when_available(path):
    if not path.exists():
        return ""
    for _ in range(3):
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise
            time.sleep(0.05)
    return ""


def pending_events(path, offset):
    if not path.exists():
        return [], offset
    for _ in range(3):
        try:
            with path.open("rb") as stream:
                stream.seek(offset)
                data = stream.read()
            break
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise
            time.sleep(0.05)
    else:
        return [], offset
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


def _sources(event):
    sources = event.get("sources")
    if isinstance(sources, (list, tuple)):
        return ", ".join(str(source) for source in sources)
    return str(event.get("source", "?"))


def _band_drops(event):
    delta = event.get("band_drop_delta", 0)
    if isinstance(delta, dict):
        return sum(value for value in delta.values() if isinstance(value, (int, float)))
    return delta if isinstance(delta, (int, float)) and not isinstance(delta, bool) else 0


def _show_backoff(event):
    offense = event.get("offense_count")
    if isinstance(offense, int) and offense > 1:
        print(f"BACKOFF offense {offense} for {event.get('source', '?')}: "
              f"timeout raised to {event.get('hard_timeout_s', '?')} s", flush=True)


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
        if state.get("mitigation", True):
            print("        Both senders exceeded the source threshold; the client is protected.", flush=True)
        else:
            print("        Mitigation is off, so no rule is requested; the flood keeps its path.", flush=True)
    elif kind == "drop_requested":
        print(f"RULE    request UDP drop {event['source']} -> "
              f"{event['victim']}:{event['port']} "
              f"for {event['hard_timeout_s']} s", flush=True)
        _show_backoff(event)
    elif kind == "drop_confirmed":
        print(f"BLOCK   OpenFlow barrier confirms switch rules for "
              f"{', '.join(event['sources'])}", flush=True)
        state["block_seen"] = True
    elif kind == "drop_removed":
        print(f"EXPIRE  rule for {event['source']} removed after timeout; "
              f"{event['packets']} packets blocked", flush=True)
    elif kind == "ratelimit_requested":
        rate = event.get("rate_pps", event.get("rate_limit_pps", "?"))
        print(f"RATE-LIMIT request meter for {event.get('source', '?')} -> "
              f"{event.get('victim', '10.0.0.10')}:{event.get('port', 9000)} at {rate} pps "
              f"for {event.get('hard_timeout_s', '?')} s", flush=True)
        _show_backoff(event)
    elif kind == "ratelimit_confirmed":
        print(f"RATE-LIMIT OpenFlow barrier confirms meter rules for {_sources(event)}", flush=True)
    elif kind == "ratelimit_failed":
        reason = event.get("reason") or event.get("error") or "meter not supported"
        print(f"METER-FALLBACK meter for {_sources(event)} failed ({reason}); "
              f"falling back to {event.get('fallback', 'drop')}", flush=True)
    elif kind == "ratelimit_removed":
        print(f"EXPIRE  rate-limit rule for {event.get('source', '?')} removed; "
              f"{event.get('packets', '?')} packets matched it", flush=True)
    elif kind == "meter_sample":
        dropped = _band_drops(event)
        if dropped > 0:
            source = f" for {event['source']}" if event.get("source") else ""
            print(f"METER   meter bands dropped {dropped} packets{source} above the rate limit "
                  "in this poll", flush=True)


def attack_event_seen(output, wanted):
    for host in ("a1", "a2"):
        path = output / f"attack-{host}.jsonl"
        if not path.exists():
            return False
        try:
            if not any(json.loads(line).get("event") == wanted
                       for line in read_text_when_available(path).splitlines() if line):
                return False
        except json.JSONDecodeError:
            return False
    return True


def trial_command(output, mode, args):
    command = [sys.executable, "-u", str(ROOT / "experiments" / "run_trial.py"),
               "--mode", mode, "--output", str(output),
               "--pps", str(args.pps), "--duration-s", str(args.duration_s)]
    if args.pcap:
        command.append("--pcap")
    if args.bottleneck:
        command += ["--bottleneck-mbit", str(BOTTLENECK_PRESET["mbit"]),
                    "--queue-packets", str(BOTTLENECK_PRESET["queue_packets"])]
    if args.detector:
        command += ["--detector", args.detector]
    if args.mitigation_action:
        command += ["--mitigation-action", args.mitigation_action]
    if args.backoff is not None:
        command.append("--backoff" if args.backoff else "--no-backoff")
    return command


def run_live(output, mode, args, config):
    """Run one trial in a child process and narrate its controller events.

    run_trial.py refuses an existing output folder, so the runner log is
    written next to it first and moved inside as demo-runner.log afterwards.
    """
    stages = STAGES[mode]
    print("\n[1/5] BASELINE  starting controller, switch and five hosts...", flush=True)
    runner_log = output.parent / f".{output.name}.demo-runner.log"
    with runner_log.open("w", encoding="utf-8") as log:
        runner = subprocess.Popen(trial_command(output, mode, args), cwd=ROOT,
                                  stdout=log, stderr=subprocess.STDOUT)
        offset = 0
        normal_seen = False
        flood_stopped = False
        state = {"flood_seen": False, "first_high_seen": False,
                 "block_seen": False, "post_block_seen": False,
                 "mitigation": mode == "attack-on",
                 "victim_threshold": config["victim_pps"],
                 "source_threshold": config["source_pps"],
                 "min_sources": config["min_sources"]}
        try:
            while runner.poll() is None:
                if not normal_seen and "20/20 received" in read_text_when_available(runner_log):
                    print("NORMAL  20/20 host pings succeeded; priming the UDP echo flows", flush=True)
                    normal_seen = True
                if not state["flood_seen"] and attack_event_seen(output, "start"):
                    print("\n[2/5] FLOOD     both senders started; the client continues probing", flush=True)
                    state["flood_seen"] = True
                events, offset = pending_events(output / "controller.jsonl", offset)
                for event in events:
                    if event.get("type") == "alert":
                        print(stages["detect"], flush=True)
                    show_event(event, state)
                if state["flood_seen"] and not flood_stopped and attack_event_seen(output, "stop"):
                    print(stages["recovery"], flush=True)
                    flood_stopped = True
                time.sleep(0.2)
            events, offset = pending_events(output / "controller.jsonl", offset)
            for event in events:
                if event.get("type") == "alert":
                    print(stages["detect"], flush=True)
                show_event(event, state)
        except KeyboardInterrupt:
            print("Waiting for the trial to clean up Mininet...", flush=True)
            runner.send_signal(2)
            runner.wait(timeout=15)
            raise SystemExit(130)
        except BaseException:
            if runner.poll() is None:
                runner.send_signal(2)
                try:
                    runner.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    runner.kill()
                    runner.wait(timeout=5)
            raise
        finally:
            log.close()
            if output.is_dir():
                runner_log.replace(output / "demo-runner.log")
    final_log = output / "demo-runner.log" if output.is_dir() else runner_log
    if runner.returncode:
        print(f"Trial failed (exit {runner.returncode}). Inspect {final_log}", file=sys.stderr)
    return runner.returncode


def seconds(value):
    return "none" if value is None else f"{value:.3f} s"


def review(output, args, mode, extended):
    summary = summarize_trial(output)
    events, _ = pending_events(output / "controller.jsonl", 0)
    print(f"  Host connectivity: {100 - summary['ping_loss_percent']:.0f}%")
    print(f"  Alert latency: {seconds(summary['first_alert_latency_s'])}")
    if mode == "attack-on":
        blocked_packets = sum(event["packets"] for event in events if event.get("type") == "drop_removed")
        print(f"  Switch confirmation: {seconds(summary['first_drop_confirmation_latency_s'])}")
        print(f"  Attacker packets counted by expired drop rules: {blocked_packets}")
    else:
        print("  Switch rules: none requested (mitigation off)")
    print(f"  Legitimate probes during attack: {summary['client']['received']}/{summary['client']['sent']}")
    print(f"  Legitimate probes after recovery: {summary['recovery_client']['received']}/{summary['recovery_client']['sent']}")
    print(f"  Drop rules after recovery: {summary['drop_rules_after_recovery']}")
    if extended:
        metrics = summary.get("client_metrics") or {}
        p95 = (metrics.get("rtt_ms") or {}).get("p95")
        print(f"  Client probe loss: {metrics.get('loss_percent', 0):.1f}%; RTT p95: "
              + ("n/a" if p95 is None else f"{p95:.1f} ms"))
        if summary["ratelimit_requests"] or summary["ratelimit_fallbacks"]:
            print(f"  Rate-limit requests: {summary['ratelimit_requests']}; meter fallbacks to drop: "
                  f"{summary['ratelimit_fallbacks']}; meter band drops: {summary['meter_band_drops']}")
        qdisc = summary.get("qdisc")
        if qdisc and qdisc.get("drops") is not None:
            print(f"  Bottleneck queue (s1-eth1): {qdisc['drops']} packets dropped; "
                  f"max backlog {qdisc['max_backlog_bytes']} bytes / {qdisc['max_qlen']} packets")
    return summary


def show_capture(output):
    capture = json.loads((output / "capture-summary.json").read_text(encoding="utf-8"))
    print(f"  Wireshark file: {output.relative_to(ROOT) / capture['file']}")
    print("  Captured UDP packets by observation point: " + ", ".join(
        f"{name}={count}" for name, count in capture["packets_seen"].items()))
    if capture["truncated"]:
        print("  Capture reached its 64 MiB limit; repeat at a lower rate for a full graph.")


def number(value, suffix="", digits=1):
    return "n/a" if value is None else f"{value:.{digits}f}{suffix}"


def show_availability(off, on):
    try:
        result = compare(off, on)
    except ValueError as exc:
        print(f"  Comparison not valid: {exc}")
        print("  Interpretation: no availability claim; inspect both trial folders.")
        return None
    table = result["availability"]
    rows = (("Client probe loss during attack", number(table["off_client_loss_percent"], "%"),
             number(table["on_client_loss_percent"], "%")),
            ("Client RTT p95", number(table["off_rtt_p95_ms"], " ms"), number(table["on_rtt_p95_ms"], " ms")),
            ("Bottleneck queue drops", number(table["off_qdisc_drops"], digits=0),
             number(table["on_qdisc_drops"], digits=0)),
            ("Attacker pps reaching the victim", number(result["unmitigated_attacker_pps"], digits=0),
             number(result["mitigated_attacker_pps"], digits=0)))
    print(f"  {'':34} {'OFF':>12} {'ON':>12}")
    for label, off_value, on_value in rows:
        print(f"  {label:34} {off_value:>12} {on_value:>12}")
    print(f"  Loss reduction: {table['loss_reduction_points']:.1f} percentage points "
          f"(attacker rate compared from {result['comparison_start_s']:.2f} s after attack start)")
    if table["improved"]:
        print("  Interpretation: availability improvement measured: mitigation reduced client loss "
              f"by {table['loss_reduction_points']:.1f} points under the same bottleneck and configuration.")
    else:
        print("  Interpretation: selective filtering is shown; no availability improvement was measured "
              "(client loss fell by less than 10 points).")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None,
                        help="new output folder inside this repository")
    parser.add_argument("--pps", type=int, default=600)
    parser.add_argument("--duration-s", type=int, default=8)
    parser.add_argument("--pcap", action="store_true",
                        help="capture requests and client replies into a Wireshark pcapng file")
    parser.add_argument("--bottleneck", action="store_true",
                        help="shape the switch port toward the victim to 0.5 Mbit/s with a 50-packet queue")
    parser.add_argument("--compare", action="store_true",
                        help="run mitigation OFF then ON into <output>/off and <output>/on and compare")
    parser.add_argument("--detector", choices=DETECTOR_NAMES, default=None)
    parser.add_argument("--mitigation-action", choices=MITIGATION_ACTIONS, default=None)
    parser.add_argument("--backoff", action=argparse.BooleanOptionalAction, default=None,
                        help="enable (or --no-backoff disable) repeat-offender timeout back-off")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root in Ubuntu; Mininet needs network namespaces")
    if not 1 <= args.pps <= 2000 or not 2 <= args.duration_s <= 30:
        parser.error("pps must be 1..2000 and duration-s must be 2..30")
    try:
        config = apply_overrides(load_config(ROOT / "config" / "detector.json"), detector=args.detector,
                                 action=args.mitigation_action, backoff=args.backoff)
    except ValueError as exc:
        parser.error(str(exc))
    output = (args.output or ROOT / "results" / f"demo-{datetime.now():%Y%m%d-%H%M%S}").resolve()
    if ROOT not in output.parents or output.exists():
        parser.error("output must be a new subdirectory of this repository")
    # run_trial.py creates the trial folder itself and refuses an existing one.
    if args.compare:
        output.mkdir(parents=True)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
    extended = any((args.bottleneck, args.compare, args.detector, args.mitigation_action,
                    args.backoff is not None))

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
    if extended:
        backoff = "on" if config["mitigation"]["backoff"]["enabled"] else "off"
        print(f"Detector: {config['detector']}; response: {config['mitigation']['action']}; "
              f"back-off: {backoff}", flush=True)
    if args.bottleneck:
        capacity = BOTTLENECK_PRESET["mbit"] * 1e6 / (FLOOD_FRAME_BYTES * 8)
        offered = 2 * args.pps * FLOOD_FRAME_BYTES * 8 / 1e6
        print(f"Bottleneck: s1-eth1 -> victim shaped to {BOTTLENECK_PRESET['mbit']:g} Mbit/s "
              f"(about {capacity:.0f} flood packets/s) with a {BOTTLENECK_PRESET['queue_packets']}-packet "
              f"queue; the flood offers {offered:.2f} Mbit/s", flush=True)
    elif args.compare:
        print("Note: without --bottleneck the victim link is not congested, so both runs are "
              "expected to keep the client at (near) zero loss.", flush=True)

    if not args.compare:
        returncode = run_live(output, "attack-on", args, config)
        if returncode:
            return returncode
        print("\n[5/5] REVIEW SUMMARY")
        review(output, args, "attack-on", extended)
        print("  Interpretation: selective filtering is shown; improved availability "
              "needs the separate OFF/ON comparison.")
        print(f"  Evidence: {output.relative_to(ROOT)} (inside this project)")
        if args.pcap:
            show_capture(output)
        return 0

    runs = (("off", "attack-off", "RUN 1 of 2: mitigation OFF (detection only)"),
            ("on", "attack-on", "RUN 2 of 2: mitigation ON"))
    for folder, mode, title in runs:
        print(f"\n=== {title} ===", flush=True)
        returncode = run_live(output / folder, mode, args, config)
        if returncode:
            return returncode
        print("\n[5/5] REVIEW SUMMARY")
        review(output / folder, args, mode, extended)
        if args.pcap:
            show_capture(output / folder)
    print("\nAVAILABILITY COMPARISON (analyze.compare: same config, bottleneck, rate and duration)")
    show_availability(output / "off", output / "on")
    print(f"  Evidence: {output.relative_to(ROOT)} (off/ and on/ inside this project)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
