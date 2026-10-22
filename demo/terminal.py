"""One-command, standard-library FlowGuard terminal presentation."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.live_lab import PORTS
from demo.run import benchmark_demo, detector_demo, recorded_demo

ADVANCED_FILES = (
    "traffic/probe_protocol.py", "demo/scenarios.py", "demo/queueing.py",
    "controller/config.py", "controller/detectors.py", "controller/mitigation.py", "controller/meters.py",
    "wireshark/flowguard.lua", "results/benchmarks/detector-benchmark.json",
)
BOTTLENECK_ARGS = ("--bottleneck-pps", "300", "--queue-packets", "50", "--mitigation", "compare")


def bottleneck_command():
    """The native-lab run for the bottleneck section (demo/live_lab.py flags)."""
    return [sys.executable, str(ROOT / "demo/live_lab.py"), *BOTTLENECK_ARGS]


def live_lab_supports_bottleneck():
    """Whether this checkout's live lab understands the bottleneck flags."""
    try:
        result = subprocess.run([sys.executable, str(ROOT / "demo/live_lab.py"), "--help"],
                                capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and all(flag in result.stdout for flag in ("--bottleneck-pps", "--queue-packets"))


def doctor(check_ports=True):
    checks = []

    def check(label, passed, detail):
        checks.append({"check": label, "passed": passed, "detail": detail})
        print(f"  {'PASS' if passed else 'FAIL'} | {label}: {detail}", flush=True)

    print(f"\nFLOWGUARD PREFLIGHT | {platform.system()} {platform.machine()}")
    check("Python", sys.version_info >= (3, 12), sys.version.split()[0] + " (3.12+ required)")
    assets = ["dashboard/index.html", "dashboard/styles.css", "dashboard/app.js", "dashboard/vendor/d3.min.js",
              "dashboard/assets/fonts/fonts.css", "traffic/echo_server.py", "traffic/probe.py"]
    assets.extend(f"dashboard/assets/fonts/font-{i}.ttf" for i in range(8))
    missing = [p for p in assets if not (ROOT / p).is_file()]
    check("Offline files", not missing, ", ".join(missing) if missing else "dashboard, fonts, D3 and traffic scripts present")
    try:
        from demo.engine import recorded_data, simulate
        result = recorded_data()
        simulate("sustained", mitigation=True)
        check("Detector and recorded data", True, f"{len(result['trials'])} historical trials load; model computes")
    except (OSError, ValueError, KeyError) as exc:
        check("Detector and recorded data", False, str(exc))
    missing_advanced = [p for p in ADVANCED_FILES if not (ROOT / p).is_file()]
    check("Advanced modules", not missing_advanced,
          ", ".join(missing_advanced) if missing_advanced
          else "detectors, mitigation, queue model, scenarios, probe protocol, dissector, benchmark present")
    if not missing_advanced:
        try:
            from demo.engine import DETECTOR_NAMES, benchmark_data, simulate
            for name in DETECTOR_NAMES:
                simulate("sustained", mitigation=True, detector=name, action="graduated", queue_packets=50)
            benchmark = benchmark_data()["benchmark"]
            check("Detectors, response and queue model", True,
                  f"{len(DETECTOR_NAMES)} detectors run in the model; benchmark covers "
                  f"{len(benchmark['scenarios'])} scenarios")
        except (ImportError, OSError, ValueError, KeyError) as exc:
            check("Detectors, response and queue model", False, str(exc))
    if check_ports:
        occupied = []
        sockets = []
        try:
            for name, port in PORTS.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError:
                    occupied.append(f"{name}:{port}")
        finally:
            for sock in sockets:
                sock.close()
        check("Live UDP ports", not occupied, ", ".join(occupied) if occupied else "19000/19001/19002/19011/19021/19022 available")
    capture = shutil.which("dumpcap") or shutil.which("tshark")
    if sys.platform == "win32" and not capture:
        import os
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark/dumpcap.exe"
        capture = str(candidate) if candidate.is_file() else None
    print(f"  INFO | Capture tool: {capture or 'not found; optional for the terminal lab'}")
    print("  INFO | Packet capture requires a separate capture tool and its driver/permissions.\n"
          "  INFO | No Linux, WSL, VM, drivers or Python packages are installed by this check.\n"
          "  INFO | Native enforcement uses Python; original OpenFlow requires an existing SDN lab.")
    return {"platform": platform.platform(), "python": sys.version.split()[0],
            "checks": checks, "passed": all(item["passed"] for item in checks),
            "capture_tool": capture}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", choices=("all", "doctor", "detector", "recorded", "live", "detectors", "bottleneck"),
                        default="all",
                        help="all = doctor, detector, recorded, live, then detectors and bottleneck")
    parser.add_argument("--doctor", action="store_true", help="Alias for --section doctor")
    parser.add_argument("--step", action="store_true", help="Pause before each presentation section")
    parser.add_argument("--report", type=Path, help="Write preflight JSON (doctor only)")
    args = parser.parse_args()
    if args.step and not sys.stdin.isatty():
        parser.error("--step needs an interactive terminal")
    section = "doctor" if args.doctor else args.section
    if section in ("doctor", "all", "live", "bottleneck"):
        report = doctor()
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if not report["passed"]:
            return 1

    def pause(label):
        print(f"\n{'=' * 68}\n{label}\n{'=' * 68}", flush=True)
        if args.step:
            input("Press Enter when you are ready...")

    if section in ("all", "detector"):
        pause("1 | WHY TWO WINDOWS? Actual detector with explained counter inputs")
        detector_demo(args.step)
    if section in ("all", "recorded"):
        pause("2 | ORIGINAL SDN EVIDENCE: Recalculate the saved experiment")
        recorded_demo()
    if section in ("all", "live"):
        pause("3 | REAL LOCALHOST PACKETS: Start your Wireshark capture now")
        result = subprocess.run([sys.executable, str(ROOT / "demo/live_lab.py")])
        if result.returncode:
            return result.returncode
        print("\nExplain: ingress continued, the gateway discarded offender datagrams,\n"
              "the echo service replied to the protected client, then expired rules allowed recovery.\n"
              "Open events.jsonl, packets.csv and summary.json in the printed evidence folder.\n"
              "For full OpenFlow execution, follow WINDOWS_DEMO.md using an existing Linux lab.")
    if section in ("all", "detectors"):
        pause("4 | WHICH DETECTOR? Offline benchmark of the real detector classes")
        try:
            benchmark_demo()
        except (OSError, ValueError, KeyError) as exc:
            print(f"The committed benchmark could not be read: {exc}\n"
                  "Regenerate it with: python3 experiments/benchmark_detectors.py --roc", file=sys.stderr)
            return 1
    if section in ("all", "bottleneck"):
        pause("5 | A REAL BOTTLENECK: Does mitigation restore the client's replies?")
        if not live_lab_supports_bottleneck():
            print("This checkout's demo/live_lab.py has no --bottleneck-pps option; skipping.", file=sys.stderr)
            return 1
        print("Running: python " + " ".join(["demo/live_lab.py", *BOTTLENECK_ARGS]), flush=True)
        result = subprocess.run(bottleneck_command())
        if result.returncode:
            return result.returncode
        print("\nExplain: the gateway's link to the victim is an emulated 300 packets/s link with a\n"
              "50-packet FIFO queue. With mitigation OFF the flood fills the queue, so the protected\n"
              "client's probes are dropped or delayed. With mitigation ON the offenders are filtered\n"
              "before the queue and the client's replies return. The queue is a userspace model in the\n"
              "Python gateway, not a kernel qdisc; loss before detection is expected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
