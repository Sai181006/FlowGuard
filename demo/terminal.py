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
from demo.run import detector_demo, recorded_demo


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
    parser.add_argument("--section", choices=("all", "doctor", "detector", "recorded", "live"), default="all")
    parser.add_argument("--doctor", action="store_true", help="Alias for --section doctor")
    parser.add_argument("--step", action="store_true", help="Pause before each presentation section")
    parser.add_argument("--report", type=Path, help="Write preflight JSON (doctor only)")
    args = parser.parse_args()
    if args.step and not sys.stdin.isatty():
        parser.error("--step needs an interactive terminal")
    section = "doctor" if args.doctor else args.section
    if section in ("doctor", "all", "live"):
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
