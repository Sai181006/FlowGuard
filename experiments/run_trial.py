"""Run one isolated, logged FlowGuard trial in Ubuntu WSL2 as root."""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "topology"))
from lab_topology import DDoSTopo  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
MODES = ("detection", "mitigation", "mitigation-repeat", "baseline", "attack-off", "attack-on")


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


def probe(host, output, count, interval_ms):
    stream = open(output, "w", encoding="utf-8")
    process = host.popen(
        [sys.executable, "-u", str(ROOT / "traffic" / "probe.py"),
         "--count", str(count), "--interval-ms", str(interval_ms)],
        stdout=stream, stderr=subprocess.STDOUT,
    )
    return process, stream


def dump_flows(output):
    output.write_text(subprocess.check_output(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"], text=True
    ), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pps", type=int, default=600)
    parser.add_argument("--duration-s", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.pps <= 2000 or not 2 <= args.duration_s <= 30:
        parser.error("pps must be 1..2000 and duration-s must be 2..30")
    output = args.output.resolve()
    if ROOT not in output.parents or output == ROOT:
        parser.error("output must be a subdirectory of this repository")
    output.mkdir(parents=True, exist_ok=True)
    mitigation = args.mode in ("mitigation", "mitigation-repeat", "attack-on", "baseline")
    config = ROOT / "config" / "detector.json"
    controller_log = open(output / "controller.log", "w", encoding="utf-8")
    server_log = open(output / "server.log", "w", encoding="utf-8")
    env = os.environ.copy()
    env.update({"FLOWGUARD_CONFIG": str(config), "FLOWGUARD_EVENTS": str(output / "controller.jsonl"),
                "FLOWGUARD_MITIGATION": "1" if mitigation else "0"})
    controller = subprocess.Popen(
        [sys.executable, "-u", str(ROOT / "controller" / "run.py")],
        cwd=ROOT, env=env, stdout=controller_log, stderr=subprocess.STDOUT,
    )
    net = Mininet(topo=DDoSTopo(), controller=None, switch=OVSSwitch)
    server = None
    children = []
    streams = []
    metadata = {"mode": args.mode, "started_utc": utc_now(), "pps_per_attacker": args.pps,
                "duration_s": 300 if args.mode == "baseline" else args.duration_s,
                "mitigation_enabled": mitigation, "config": json.loads(config.read_text())}
    try:
        time.sleep(1)
        if controller.poll() is not None:
            raise RuntimeError("controller exited; inspect controller.log")
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
        net.start()
        if not net.waitConnected(timeout=10):
            raise RuntimeError("switch did not connect")
        metadata["ping_loss_percent"] = net.pingAll()
        if metadata["ping_loss_percent"] != 0:
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
            process, stream = probe(net.get(host_name), output / f"prime-{host_name}.csv", 3, 100)
            process.wait(timeout=10)
            stream.close()
            if process.returncode:
                raise RuntimeError(f"prime probe failed from {host_name}")
        time.sleep(2.2)
        dump_flows(output / "flows-before.txt")
        metadata["phase_start_monotonic_s"] = time.monotonic()
        metadata["phase_start_utc"] = utc_now()
        if args.mode == "baseline":
            for host_name in ("client", "a1"):
                process, stream = probe(net.get(host_name), output / f"normal-{host_name}.csv", 600, 500)
                children.append((host_name, process))
                streams.append(stream)
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
            for _, process in children:
                process.wait(timeout=170)
            metadata["burst_duration_s"] = 0.6
            metadata["burst_pps_per_source"] = 70
        elif args.mode == "mitigation-repeat":
            metadata["waves"] = []
            for wave in (1, 2):
                wave_start = time.monotonic()
                process, stream = probe(net.get("client"), output / f"client-wave{wave}.csv",
                                        args.duration_s * 10, 100)
                children.append(("client", process))
                streams.append(stream)
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
                metadata["waves"].append({"number": wave, "started_monotonic_s": wave_start,
                                          "ended_monotonic_s": time.monotonic()})
                time.sleep(12)
                dump_flows(output / f"flows-after-wave{wave}.txt")
            process, stream = probe(net.get("client"), output / "recovery-client.csv", 10, 100)
            process.wait(timeout=10)
            stream.close()
            metadata["recovery_probe_exit"] = process.returncode
        else:
            client_count = args.duration_s * 10
            process, stream = probe(net.get("client"), output / "client.csv", client_count, 100)
            children.append(("client", process))
            streams.append(stream)
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
            metadata["attack_end_monotonic_s"] = time.monotonic()
            metadata["attack_end_utc"] = utc_now()
            dump_flows(output / "flows-after-attack.txt")
            time.sleep(12)
            dump_flows(output / "flows-after-recovery.txt")
            process, stream = probe(net.get("client"), output / "recovery-client.csv", 10, 100)
            process.wait(timeout=10)
            stream.close()
            metadata["recovery_probe_exit"] = process.returncode
        metadata["finished_utc"] = utc_now()
        metadata["finished_monotonic_s"] = time.monotonic()
        metadata["status"] = "completed"
        print(json.dumps(metadata, indent=2), flush=True)
    except BaseException as exc:
        metadata["status"] = "failed"
        metadata["error"] = str(exc)
        raise
    finally:
        for _, process in children:
            stop(process)
        stop(server)
        net.stop()
        stop(controller)
        for stream in streams:
            stream.close()
        controller_log.close()
        server_log.close()
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
