"""Send low-rate UDP echo probes to the lab victim and record outcomes."""

import argparse
import ipaddress
import socket
import sys
import time
from datetime import datetime, timezone


LAB_NETWORK = ipaddress.ip_network("10.0.0.0/24")


def lab_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid IP address") from exc
    if address not in LAB_NETWORK and address != ipaddress.ip_address("127.0.0.1"):
        raise argparse.ArgumentTypeError("target must be in 10.0.0.0/24 or 127.0.0.1")
    return str(address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=lab_address, default="10.0.0.10")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--timeout-ms", type=int, default=500)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not 1 <= args.count <= 1000:
        parser.error("count must be between 1 and 1000")
    if not 50 <= args.interval_ms <= 60000:
        parser.error("interval-ms must be between 50 and 60000")
    if not 1 <= args.timeout_ms <= 10000:
        parser.error("timeout-ms must be between 1 and 10000")

    received = 0
    print("timestamp_utc,sequence,status,rtt_ms", flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for sequence in range(1, args.count + 1):
            started = time.monotonic()
            timestamp = datetime.now(timezone.utc).isoformat()
            payload = f"ddos-probe:{sequence}:{time.time_ns()}".encode("ascii")
            sock.sendto(payload, (args.target, args.port))
            deadline = started + args.timeout_ms / 1000
            rtt_ms = None
            while time.monotonic() < deadline:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                try:
                    reply, peer = sock.recvfrom(2048)
                except socket.timeout:
                    break
                if peer == (args.target, args.port) and reply == payload:
                    rtt_ms = (time.monotonic() - started) * 1000
                    received += 1
                    break
            if rtt_ms is None:
                print(f"{timestamp},{sequence},timeout,", flush=True)
            else:
                print(f"{timestamp},{sequence},ok,{rtt_ms:.3f}", flush=True)
            time.sleep(max(0, args.interval_ms / 1000 - (time.monotonic() - started)))

    print(f"sent={args.count} received={received} loss={100 * (args.count - received) / args.count:.1f}%", file=sys.stderr)
    return 0 if received == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
