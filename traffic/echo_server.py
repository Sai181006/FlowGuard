"""Small UDP echo service for the private Mininet lab."""

import argparse
import ipaddress
import json
import signal
import socket
import time
from datetime import datetime, timezone


LAB_NETWORK = ipaddress.ip_network("10.0.0.0/24")
STOP = False


def lab_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid IP address") from exc
    if address not in LAB_NETWORK and address != ipaddress.ip_address("127.0.0.1"):
        raise argparse.ArgumentTypeError("address must be in 10.0.0.0/24 or 127.0.0.1")
    return str(address)


def request_stop(_signum, _frame):
    global STOP
    STOP = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", type=lab_address, default="10.0.0.10")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--stats-jsonl", help="Write victim receive counts per monotonic second")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.bind, args.port))
        sock.settimeout(0.2)
        print(f"UDP echo listening on {args.bind}:{args.port}", flush=True)
        started = time.monotonic()
        window_start = started
        counts = {}
        total = 0
        while not STOP:
            now = time.monotonic()
            if now - window_start >= 1:
                if args.stats_jsonl:
                    with open(args.stats_jsonl, "a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"time_utc": datetime.now(timezone.utc).isoformat(),
                                                 "monotonic_s": now, "window_start_s": window_start,
                                                 "elapsed_s": now - window_start, "by_source": counts,
                                                 "packets": sum(counts.values()), "total_packets": total}) + "\n")
                window_start, counts = now, {}
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            counts[peer[0]] = counts.get(peer[0], 0) + 1
            total += 1
            sock.sendto(data, peer)
        if args.stats_jsonl:
            now = time.monotonic()
            with open(args.stats_jsonl, "a", encoding="utf-8") as stream:
                stream.write(json.dumps({"time_utc": datetime.now(timezone.utc).isoformat(),
                                         "monotonic_s": now, "window_start_s": window_start,
                                         "elapsed_s": now - window_start, "by_source": counts,
                                         "packets": sum(counts.values()), "total_packets": total}) + "\n")


if __name__ == "__main__":
    main()
