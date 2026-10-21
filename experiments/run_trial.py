"""Run one isolated, logged FlowGuard trial in Ubuntu WSL2 as root."""

import argparse
import csv
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

EXPERIMENTS = str(Path(__file__).resolve().parent)
if EXPERIMENTS not in sys.path:  # also importable as experiments.run_trial (tests)
    sys.path.insert(0, EXPERIMENTS)
from packet_capture import PacketCapture, save_summary, switch_ports  # noqa: E402
from qdisc_monitor import QdiscMonitor, read_qdiscs, root_qdisc  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "topology"))
from lab_topology import (BOTTLENECK_MBIT_RANGE, QUEUE_PACKETS_RANGE,  # noqa: E402
                          VICTIM_SWITCH_INTF, DDoSTopo)

if str(Path(__file__).resolve().parents[1]) not in sys.path:  # for controller.config
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller.config import (DETECTOR_NAMES, MITIGATION_ACTIONS,  # noqa: E402
                               apply_overrides, config_digest, load_config)


ROOT = Path(__file__).resolve().parents[1]
MODES = ("detection", "mitigation", "mitigation-repeat", "baseline", "attack-off", "attack-on")
PROBE_COLUMNS = ("timestamp_utc", "sequence", "status", "rtt_ms")
PROBE_FORMATS = ("binary", "text")
SUMMARY_LINE = re.compile(r"^(sent=\d+ received=\d+ loss=|metrics )")
DEFAULT_QUEUE_PACKETS = 50
QDISC_INTERVAL_S = 0.5


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=4)


def metrics_path(output):
    """client.csv -> client.metrics.json (probe.py --metrics-json summary)."""
    output = Path(output)
    return output.with_name(output.stem + ".metrics.json")


def probe(host, output, count, interval_ms, probe_format="binary"):
    stream = open(output, "w", encoding="utf-8")
    process = host.popen(
        [sys.executable, "-u", str(ROOT / "traffic" / "probe.py"),
         "--count", str(count), "--interval-ms", str(interval_ms),
         "--format", probe_format, "--metrics-json", str(metrics_path(output))],
        stdout=stream, stderr=subprocess.STDOUT,
    )
    return process, stream


def probe_measurement(path, expected_count, returncode):
    """Validate a complete probe CSV while retaining packet loss as data."""
    if not isinstance(expected_count, int) or expected_count < 1:
        raise ValueError("expected probe count must be a positive integer")
    try:
        with Path(path).open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != PROBE_COLUMNS:
                raise ValueError("unexpected probe CSV header")
            rows = list(reader)
    except (OSError, csv.Error) as exc:
        raise ValueError(f"cannot read probe output at {path}: {exc}") from exc
    # probe.py writes its summary ("sent=N received=N loss=X%", optionally
    # followed by a "metrics ..." line) to stderr, which shares this file.
    while rows and SUMMARY_LINE.match(rows[-1].get("timestamp_utc") or ""):
        rows.pop()
    if len(rows) != expected_count:
        raise ValueError(f"probe output at {path} contains {len(rows)} of {expected_count} samples")

    received = 0
    for sequence, row in enumerate(rows, start=1):
        if (None in row or any(row.get(column) is None for column in PROBE_COLUMNS)
                or row.get("timestamp_utc") == "" or row.get("sequence") != str(sequence)):
            raise ValueError(f"probe output at {path} has an invalid sequence at row {sequence}")
        status = row.get("status")
        if status == "ok":
            try:
                rtt = float(row.get("rtt_ms", ""))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"probe output at {path} has an invalid RTT at row {sequence}") from exc
            if not math.isfinite(rtt) or rtt < 0:
                raise ValueError(f"probe output at {path} has an invalid RTT at row {sequence}")
            received += 1
        elif status == "timeout":
            if row.get("rtt_ms") not in (None, ""):
                raise ValueError(f"probe output at {path} has an RTT for a timeout at row {sequence}")
        else:
            raise ValueError(f"probe output at {path} has an invalid status at row {sequence}")

    expected_returncode = 0 if received == expected_count else 1
    if returncode != expected_returncode:
        raise ValueError(f"probe process exit {returncode} disagrees with {received}/{expected_count} replies")
    return {"sent": expected_count, "received": received,
            "loss_percent": 100 * (expected_count - received) / expected_count,
            "process_exit": returncode}


def successful_probe(measurement, expected_count):
    """Acceptance probes require every measured packet to succeed."""
    return measurement["sent"] == expected_count and measurement["received"] == expected_count \
        and measurement["process_exit"] == 0


def set_check(metadata, name, passed, **details):
    metadata["validation"]["checks"][name] = {
        "status": "passed" if passed else "failed", **details,
    }


def dump_flows(output):
    output.write_text(subprocess.check_output(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"], text=True
    ), encoding="utf-8")


def bottleneck_problems(qdiscs, bottleneck):
    """Compare a parsed ``tc -j qdisc show`` list with the requested TCLink tree."""
    problems = []
    root = root_qdisc(qdiscs)
    if root is None or root.get("kind") != "htb":
        problems.append("root qdisc is %s, expected htb" % (root.get("kind") if root else "missing"))
    netem = [entry for entry in qdiscs if entry.get("kind") == "netem"]
    if not netem:
        problems.append("no netem queue below the htb class")
    elif netem[0].get("limit") not in (None, bottleneck["queue_packets"]):
        problems.append(f"netem limit is {netem[0].get('limit')}, expected {bottleneck['queue_packets']}")
    if bottleneck["qdisc"] == "red" and not any(entry.get("kind") == "red" for entry in qdiscs):
        problems.append("red qdisc requested but not installed")
    return problems


def qdisc_snapshot(dev, path, bottleneck):
    """Read the device's qdiscs once, save them as JSON and return the problems found."""
    raw, qdiscs = read_qdiscs(dev, subprocess.check_output)
    problems = bottleneck_problems(qdiscs, bottleneck)
    Path(path).write_text(json.dumps({"dev": dev, "time_utc": utc_now(),
                                      "monotonic_s": time.monotonic(), "requested": bottleneck,
                                      "qdiscs": qdiscs, "problems": problems,
                                      "tc_json": json.loads(raw)}, indent=2) + "\n",
                          encoding="utf-8")
    return qdiscs, problems


def repository_path(parser, value, label):
    path = Path(value).resolve()
    if ROOT not in path.parents:
        parser.error(f"{label} must be inside this repository")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pps", type=int, default=600)
    parser.add_argument("--duration-s", type=int, default=8)
    parser.add_argument("--pcap", action="store_true",
                        help="save requests and client replies in a Wireshark pcapng")
    parser.add_argument("--bottleneck-mbit", type=float, default=None,
                        help="shape s1-eth1 (toward the victim) with HTB at this rate, 0.05..100")
    parser.add_argument("--queue-packets", type=int, default=None,
                        help=f"bottleneck queue length in packets, 5..1000 (default {DEFAULT_QUEUE_PACKETS})")
    parser.add_argument("--qdisc", choices=("fifo", "red"), default=None,
                        help="bottleneck queue: netem tail-drop fifo (default) or Mininet's RED")
    parser.add_argument("--config", type=Path, default=ROOT / "config" / "detector.json",
                        help="detector configuration inside this repository")
    parser.add_argument("--detector", choices=DETECTOR_NAMES, default=None)
    parser.add_argument("--mitigation-action", choices=MITIGATION_ACTIONS, default=None)
    parser.add_argument("--backoff", action=argparse.BooleanOptionalAction, default=None,
                        help="enable (or --no-backoff disable) repeat-offender timeout back-off")
    parser.add_argument("--probe-format", choices=PROBE_FORMATS, default="binary",
                        help="probe payload passed to traffic/probe.py --format")
    args = parser.parse_args()
    if not 1 <= args.pps <= 2000 or not 2 <= args.duration_s <= 30:
        parser.error("pps must be 1..2000 and duration-s must be 2..30")
    bottleneck = None
    if args.bottleneck_mbit is None:
        if args.queue_packets is not None or args.qdisc is not None:
            parser.error("--queue-packets and --qdisc require --bottleneck-mbit")
    else:
        queue_packets = DEFAULT_QUEUE_PACKETS if args.queue_packets is None else args.queue_packets
        if not (math.isfinite(args.bottleneck_mbit)
                and BOTTLENECK_MBIT_RANGE[0] <= args.bottleneck_mbit <= BOTTLENECK_MBIT_RANGE[1]):
            parser.error("bottleneck-mbit must be 0.05..100")
        if not QUEUE_PACKETS_RANGE[0] <= queue_packets <= QUEUE_PACKETS_RANGE[1]:
            parser.error("queue-packets must be 5..1000")
        bottleneck = {"device": VICTIM_SWITCH_INTF, "mbit": args.bottleneck_mbit,
                      "queue_packets": queue_packets, "qdisc": args.qdisc or "fifo"}
    config_path = repository_path(parser, args.config, "config")
    try:
        effective = apply_overrides(load_config(config_path), detector=args.detector,
                                    action=args.mitigation_action, backoff=args.backoff)
    except ValueError as exc:
        parser.error(str(exc))
    output = args.output.resolve()
    if ROOT not in output.parents or output == ROOT:
        parser.error("output must be a subdirectory of this repository")
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error(f"output directory already exists; choose a fresh path: {output}")
    except OSError as exc:
        parser.error(f"cannot create output directory {output}: {exc}")
    mitigation = args.mode in ("mitigation", "mitigation-repeat", "attack-on", "baseline")
    # The controller reads exactly the configuration recorded in metadata.json.
    config = output / "effective-config.json"
    config.write_text(json.dumps(effective, indent=2) + "\n", encoding="utf-8")
    controller_log = open(output / "controller.log", "w", encoding="utf-8")
    server_log = open(output / "server.log", "w", encoding="utf-8")
    env = os.environ.copy()
    env.update({"FLOWGUARD_CONFIG": str(config), "FLOWGUARD_EVENTS": str(output / "controller.jsonl"),
                "FLOWGUARD_MITIGATION": "1" if mitigation else "0"})
    controller = subprocess.Popen(
        [sys.executable, "-u", str(ROOT / "controller" / "run.py")],
        cwd=ROOT, env=env, stdout=controller_log, stderr=subprocess.STDOUT,
    )
    if bottleneck is None:
        topo = DDoSTopo()
    else:
        topo = DDoSTopo(bottleneck={"mbit": bottleneck["mbit"], "queue_packets": bottleneck["queue_packets"],
                                    "red": bottleneck["qdisc"] == "red"})
    # Per-link cls=TCLink in the topology is honoured by Mininet.addLink.
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    server = None
    capture = None
    qdisc_monitor = None
    children = []
    streams = []
    metadata = {"mode": args.mode, "started_utc": utc_now(), "pps_per_attacker": args.pps,
                "duration_s": 300 if args.mode == "baseline" else args.duration_s,
                "mitigation_enabled": mitigation, "config": effective,
                "config_digest": config_digest(effective),
                "config_source": str(config_path.relative_to(ROOT)),
                "bottleneck": bottleneck, "probe_format": args.probe_format,
                "execution_status": "running", "validation": {"status": "pending", "checks": {}},
                "measurements": {}}
    exit_status = 0

    def start_probe(host, path, count, interval_ms):
        return probe(host, path, count, interval_ms, args.probe_format)

    def stop_qdisc_monitor():
        if qdisc_monitor is not None and qdisc_monitor.active:
            metadata["qdisc_monitor"] = qdisc_monitor.stop()

    try:
        time.sleep(1)
        if controller.poll() is not None:
            raise RuntimeError("controller exited; inspect controller.log")
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
        net.start()
        if not net.waitConnected(timeout=10):
            raise RuntimeError("switch did not connect")
        if bottleneck is not None:
            try:
                qdiscs, problems = qdisc_snapshot(bottleneck["device"], output / "qdisc-config.json",
                                                  bottleneck)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                qdiscs, problems = [], [f"cannot read qdiscs with tc: {exc}"]
            set_check(metadata, "bottleneck_qdisc", not problems, problems=problems,
                      kinds=[entry.get("kind") for entry in qdiscs])
            if problems:
                raise RuntimeError(f"bottleneck requested but {bottleneck['device']} is not shaped: "
                                   + "; ".join(problems)
                                   + " (does this kernel provide sch_htb and sch_netem?)")
        metadata["ping_loss_percent"] = net.pingAll()
        baseline_passed = metadata["ping_loss_percent"] == 0
        set_check(metadata, "baseline_connectivity", baseline_passed,
                  ping_loss_percent=metadata["ping_loss_percent"])
        if not baseline_passed:
            raise RuntimeError("baseline ping failed")
        server = net.get("victim").popen(
            [sys.executable, "-u", str(ROOT / "traffic" / "echo_server.py"),
             "--stats-jsonl", str(output / "victim.jsonl")],
            stdout=server_log, stderr=subprocess.STDOUT,
        )
        time.sleep(0.4)
        if server.poll() is not None:
            raise RuntimeError("echo server exited; inspect server.log")
        for host_name in ("client", "a1", "a2"):
            process, stream = start_probe(net.get(host_name), output / f"prime-{host_name}.csv", 3, 100)
            process.wait(timeout=10)
            stream.close()
            measurement = probe_measurement(output / f"prime-{host_name}.csv", 3, process.returncode)
            metadata["measurements"][f"prime_{host_name}"] = measurement
            set_check(metadata, f"prime_{host_name}", successful_probe(measurement, 3),
                      measurement=measurement)
            if not successful_probe(measurement, 3):
                raise RuntimeError(f"prime probe failed from {host_name}")
        time.sleep(2.2)
        dump_flows(output / "flows-before.txt")
        if args.pcap:
            capture = PacketCapture(output / "flowguard.pcapng", switch_ports(net)).start()
        if bottleneck is not None:
            qdisc_monitor = QdiscMonitor(bottleneck["device"], output / "qdisc.jsonl",
                                         interval=QDISC_INTERVAL_S, runner=subprocess.check_output).start()
        metadata["phase_start_monotonic_s"] = time.monotonic()
        metadata["phase_start_utc"] = utc_now()
        if args.mode == "baseline":
            normal_probes = {}
            for host_name in ("client", "a1"):
                process, stream = start_probe(net.get(host_name), output / f"normal-{host_name}.csv", 600, 500)
                children.append((host_name, process))
                streams.append(stream)
                normal_probes[host_name] = (process, stream)
            time.sleep(150)
            # A short two-source benign burst should not meet the two-window condition.
            burst = []
            for host_name in ("a1", "a2"):
                stream = open(output / f"burst-{host_name}.jsonl", "w", encoding="utf-8")
                process = net.get(host_name).popen(
                    [sys.executable, "-u", str(ROOT / "traffic" / "flood.py"),
                     "--pps", "70", "--duration-s", "0.6"], stdout=stream, stderr=subprocess.STDOUT,
                )
                burst.append((host_name, process))
                streams.append(stream)
            for _, process in burst:
                process.wait(timeout=5)
            for host_name, process in children:
                process.wait(timeout=170)
                stream = normal_probes[host_name][1]
                stream.close()
                measurement = probe_measurement(output / f"normal-{host_name}.csv", 600,
                                                process.returncode)
                metadata["measurements"][f"normal_{host_name}"] = measurement
            metadata["burst_duration_s"] = 0.6
            metadata["burst_pps_per_source"] = 70
            metadata["validation"]["checks"]["recovery_probe"] = {"status": "not_applicable"}
        elif args.mode == "mitigation-repeat":
            metadata["waves"] = []
            for wave in (1, 2):
                wave_start = time.monotonic()
                client_probe_path = output / f"client-wave{wave}.csv"
                process, client_stream = start_probe(net.get("client"), client_probe_path,
                                                     args.duration_s * 10, 100)
                children.append(("client", process))
                streams.append(client_stream)
                wave_children = [("client", process)]
                for host_name in ("a1", "a2"):
                    stream = open(output / f"attack-{host_name}-wave{wave}.jsonl", "w", encoding="utf-8")
                    process = net.get(host_name).popen(
                        [sys.executable, "-u", str(ROOT / "traffic" / "flood.py"),
                         "--pps", str(args.pps), "--duration-s", str(args.duration_s)],
                        stdout=stream, stderr=subprocess.STDOUT,
                    )
                    children.append((host_name, process))
                    wave_children.append((host_name, process))
                    streams.append(stream)
                time.sleep(min(5, args.duration_s / 2))
                dump_flows(output / f"flows-during-wave{wave}.txt")
                for host_name, process in wave_children:
                    process.wait(timeout=args.duration_s + 10)
                    if process.returncode != 0 and host_name != "client":
                        raise RuntimeError(f"wave {wave} flood process failed: {host_name}")
                client_stream.close()
                client_measurement = probe_measurement(client_probe_path, args.duration_s * 10,
                                                       wave_children[0][1].returncode)
                metadata["measurements"][f"client_wave{wave}"] = client_measurement
                metadata["waves"].append({"number": wave, "started_monotonic_s": wave_start,
                                          "ended_monotonic_s": time.monotonic()})
                time.sleep(12)
                dump_flows(output / f"flows-after-wave{wave}.txt")
            process, stream = start_probe(net.get("client"), output / "recovery-client.csv", 10, 100)
            process.wait(timeout=10)
            stream.close()
            metadata["recovery_probe_exit"] = process.returncode
            recovery_measurement = probe_measurement(output / "recovery-client.csv", 10,
                                                     process.returncode)
            metadata["measurements"]["recovery_client"] = recovery_measurement
            set_check(metadata, "recovery_probe", successful_probe(recovery_measurement, 10),
                      measurement=recovery_measurement)
        else:
            client_count = args.duration_s * 10
            client_probe_path = output / "client.csv"
            client_process, client_stream = start_probe(net.get("client"), client_probe_path,
                                                        client_count, 100)
            children.append(("client", client_process))
            streams.append(client_stream)
            for host_name in ("a1", "a2"):
                stream = open(output / f"attack-{host_name}.jsonl", "w", encoding="utf-8")
                process = net.get(host_name).popen(
                    [sys.executable, "-u", str(ROOT / "traffic" / "flood.py"),
                     "--pps", str(args.pps), "--duration-s", str(args.duration_s)],
                    stdout=stream, stderr=subprocess.STDOUT,
                )
                children.append((host_name, process))
                streams.append(stream)
            time.sleep(min(5, args.duration_s / 2))
            dump_flows(output / "flows-during.txt")
            for host_name, process in children:
                process.wait(timeout=args.duration_s + 10)
                if process.returncode != 0 and host_name != "client":
                    raise RuntimeError(f"flood process failed: {host_name}")
            client_stream.close()
            client_measurement = probe_measurement(client_probe_path, client_count,
                                                   client_process.returncode)
            metadata["measurements"]["client"] = client_measurement
            metadata["attack_end_monotonic_s"] = time.monotonic()
            metadata["attack_end_utc"] = utc_now()
            dump_flows(output / "flows-after-attack.txt")
            time.sleep(12)
            dump_flows(output / "flows-after-recovery.txt")
            process, stream = start_probe(net.get("client"), output / "recovery-client.csv", 10, 100)
            process.wait(timeout=10)
            stream.close()
            metadata["recovery_probe_exit"] = process.returncode
            recovery_measurement = probe_measurement(output / "recovery-client.csv", 10,
                                                     process.returncode)
            metadata["measurements"]["recovery_client"] = recovery_measurement
            set_check(metadata, "recovery_probe", successful_probe(recovery_measurement, 10),
                      measurement=recovery_measurement)
        if capture is not None:
            metadata["packet_capture"] = capture.stop()
            save_summary(output / "capture-summary.json", metadata["packet_capture"])
        if bottleneck is not None:
            stop_qdisc_monitor()
            try:
                qdiscs, problems = qdisc_snapshot(bottleneck["device"], output / "qdisc-after.json",
                                                  bottleneck)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                qdiscs, problems = [], [f"cannot read qdiscs with tc: {exc}"]
            set_check(metadata, "bottleneck_qdisc_after", not problems, problems=problems,
                      root=root_qdisc(qdiscs))
        metadata["finished_utc"] = utc_now()
        metadata["finished_monotonic_s"] = time.monotonic()
        required_checks = [metadata["validation"]["checks"].get("baseline_connectivity")]
        required_checks.extend(metadata["validation"]["checks"].get(f"prime_{host}")
                               for host in ("client", "a1", "a2"))
        if bottleneck is not None:
            required_checks.extend(metadata["validation"]["checks"].get(name)
                                   for name in ("bottleneck_qdisc", "bottleneck_qdisc_after"))
        recovery_check = metadata["validation"]["checks"].get("recovery_probe")
        if recovery_check and recovery_check["status"] != "not_applicable":
            required_checks.append(recovery_check)
        validation_passed = all(check and check["status"] == "passed" for check in required_checks)
        metadata["execution_status"] = "completed"
        metadata["validation"]["status"] = "passed" if validation_passed else "failed"
        metadata["status"] = "completed" if validation_passed else "failed"
        if not validation_passed:
            metadata["validation"]["error"] = (
                "one or more baseline, prime, or recovery checks failed" if bottleneck is None
                else "one or more baseline, prime, bottleneck, or recovery checks failed")
            metadata["error"] = metadata["validation"]["error"]
            exit_status = 1
        print(json.dumps(metadata, indent=2), flush=True)
    except BaseException as exc:
        metadata["status"] = "failed"
        metadata["execution_status"] = "failed"
        metadata["validation"]["status"] = "failed"
        metadata["validation"]["error"] = str(exc)
        metadata["error"] = str(exc)
        raise
    finally:
        try:
            for _, process in children:
                stop(process)
            stop_qdisc_monitor()
            if capture is not None and capture.active:
                metadata["packet_capture"] = capture.stop()
                save_summary(output / "capture-summary.json", metadata["packet_capture"])
        finally:
            stop(server)
            net.stop()
            stop(controller)
            for stream in streams:
                stream.close()
            controller_log.close()
            server_log.close()
            (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return exit_status


if __name__ == "__main__":
    sys.exit(main())
