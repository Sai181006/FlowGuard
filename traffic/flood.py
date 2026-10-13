"""Bounded UDP traffic to the fixed victim inside the private Mininet lab."""

import argparse
import json
import socket
import time
from datetime import datetime, timezone


TARGET = ("10.0.0.10", 9000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pps", type=int, required=True)
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--size", type=int, default=128)
    args = parser.parse_args()
    if not 1 <= args.pps <= 2000:
        parser.error("pps must be between 1 and 2000")
    if not 0.2 <= args.duration_s <= 30:
        parser.error("duration-s must be between 0.2 and 30")
    if not 64 <= args.size <= 512:
        parser.error("size must be between 64 and 512 bytes")
    payload = b"FLOWGUARD-LAB-ONLY:".ljust(args.size, b"X")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        started = time.monotonic()
        print(json.dumps({"event": "start", "time_utc": datetime.now(timezone.utc).isoformat(),
                          "monotonic_s": started, "target": list(TARGET), "pps": args.pps,
                          "duration_s": args.duration_s, "size": args.size}), flush=True)
        sent = 0
        deadline = started + args.duration_s
        while time.monotonic() < deadline:
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
