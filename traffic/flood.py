"""Bounded UDP traffic to the fixed victim inside the private Mininet lab."""

import argparse
import json
import secrets
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traffic.probe_protocol import FLOOD, encode


TARGET = ("10.0.0.10", 9000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pps", type=int, required=True)
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--size", type=int, default=128)
    parser.add_argument("--format", choices=("text", "binary"), default="text",
                        help="text FLOWGUARD-LAB-ONLY padding (default) or FGPB flood headers")
    args = parser.parse_args()
    if not 1 <= args.pps <= 2000:
        parser.error("pps must be between 1 and 2000")
    if not 0.2 <= args.duration_s <= 30:
        parser.error("duration-s must be between 0.2 and 30")
    if not 64 <= args.size <= 512:
        parser.error("size must be between 64 and 512 bytes")
    payload = b"FLOWGUARD-LAB-ONLY:".ljust(args.size, b"X")
    session_id = secrets.randbits(32)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        started = time.monotonic()
        print(json.dumps({"event": "start", "time_utc": datetime.now(timezone.utc).isoformat(),
                          "monotonic_s": started, "target": list(TARGET), "pps": args.pps,
                          "duration_s": args.duration_s, "size": args.size,
                          "format": args.format}), flush=True)
        sent = 0
        deadline = started + args.duration_s
        while time.monotonic() < deadline:
            if args.format == "binary":
                payload = encode(sent + 1, session_id, time.time_ns(), FLOOD, args.size)
            sock.sendto(payload, TARGET)
            sent += 1
            next_at = started + sent / args.pps
            remaining = next_at - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
        print(json.dumps({"event": "stop", "time_utc": datetime.now(timezone.utc).isoformat(),
                          "monotonic_s": time.monotonic(), "sent": sent}), flush=True)


if __name__ == "__main__":
    main()
