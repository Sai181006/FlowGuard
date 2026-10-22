"""Send low-rate UDP echo probes to the lab victim and record outcomes."""

import argparse
import ipaddress
import json
import secrets
import selectors
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traffic.probe_protocol import HEADER_LEN, ProbeStats, encode


LAB_NETWORK = ipaddress.ip_network("10.0.0.0/24")
CSV_HEADER = "timestamp_utc,sequence,status,rtt_ms"
MAX_PAYLOAD_BYTES = 512


def lab_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid IP address") from exc
    if address not in LAB_NETWORK and address != ipaddress.ip_address("127.0.0.1"):
        raise argparse.ArgumentTypeError("target must be in 10.0.0.0/24 or 127.0.0.1")
    return str(address)


def build_payload(fmt, sequence, session_id=0, payload_bytes=64, tx_time_ns=None):
    """Return the probe datagram: legacy ``ddos-probe:SEQ:NS`` text or an FGPB binary header."""
    tx_time_ns = time.time_ns() if tx_time_ns is None else tx_time_ns
    if fmt == "text":
        return f"ddos-probe:{sequence}:{tx_time_ns}".encode("ascii")
    return encode(sequence, session_id, tx_time_ns, total_bytes=payload_bytes)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def emit(timestamp, sequence, rtt_ms):
    if rtt_ms is None:
        print(f"{timestamp},{sequence},timeout,", flush=True)
    else:
        print(f"{timestamp},{sequence},ok,{rtt_ms:.3f}", flush=True)


def run_stopwait(sock, args, stats, make_payload):
    """One probe at a time; replies for older sequences are late and never complete the current one."""
    target = (args.target, args.port)
    sent_payloads = {}
    for sequence in range(1, args.count + 1):
        started = time.monotonic()
        started_ns = time.monotonic_ns()
        timestamp = utc_now()
        payload = make_payload(sequence)
        sent_payloads[payload] = sequence
        stats.on_send(sequence, started_ns)
        sock.sendto(payload, target)
        deadline = started + args.timeout_ms / 1000
        rtt_ms = None
        while time.monotonic() < deadline:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                reply, peer = sock.recvfrom(2048)
            except socket.timeout:
                break
            except (ConnectionResetError, ConnectionRefusedError):
                continue  # ICMP unreachable surfaced on the socket; keep waiting
            received_ns = time.monotonic_ns()
            if peer != target or reply not in sent_payloads:
                continue
            matched = sent_payloads[reply]
            if matched == sequence and stats.on_reply(sequence, received_ns) == "ok":
                rtt_ms = (received_ns - started_ns) / 1e6
                break
            if matched != sequence:
                stats.on_reply(matched, received_ns, deadline_passed=True)
        emit(timestamp, sequence, rtt_ms)
        time.sleep(max(0, args.interval_ms / 1000 - (time.monotonic() - started)))


def run_stream(sock, args, stats, make_payload):
    """Send on a fixed schedule and resolve each sequence on reply or after timeout-ms."""
    target = (args.target, args.port)
    interval_ns = args.interval_ms * 1_000_000
    timeout_ns = args.timeout_ms * 1_000_000
    sent_payloads = {}
    pending = {}
    resolved = {}
    next_seq = next_print = 1
    sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    start_ns = time.monotonic_ns()
    try:
        while next_print <= args.count:
            now = time.monotonic_ns()
            if next_seq <= args.count and now >= start_ns + (next_seq - 1) * interval_ns:
                payload = make_payload(next_seq)
                sent_payloads[payload] = next_seq
                pending[next_seq] = (utc_now(), now)
                stats.on_send(next_seq, now)
                sock.sendto(payload, target)
                next_seq += 1
                continue
            wake = [entry[1] + timeout_ns for entry in pending.values()]
            if next_seq <= args.count:
                wake.append(start_ns + (next_seq - 1) * interval_ns)
            wait_s = max(0, min(wake) - now) / 1e9 if wake else 0
            if selector.select(timeout=wait_s):
                while True:
                    try:
                        reply, peer = sock.recvfrom(2048)
                    except (BlockingIOError, InterruptedError):
                        break
                    except (ConnectionResetError, ConnectionRefusedError):
                        continue
                    received_ns = time.monotonic_ns()
                    if peer != target or reply not in sent_payloads:
                        continue
                    sequence = sent_payloads[reply]
                    entry = pending.get(sequence)
                    on_time = entry is not None and received_ns <= entry[1] + timeout_ns
                    status = stats.on_reply(sequence, received_ns, deadline_passed=not on_time)
                    if on_time and status == "ok":
                        resolved[sequence] = (entry[0], (received_ns - entry[1]) / 1e6)
                        del pending[sequence]
            now = time.monotonic_ns()
            for sequence in [seq for seq, entry in pending.items() if now > entry[1] + timeout_ns]:
                resolved[sequence] = (pending.pop(sequence)[0], None)
            while next_print in resolved:
                timestamp, rtt_ms = resolved.pop(next_print)
                emit(timestamp, next_print, rtt_ms)
                next_print += 1
    finally:
        selector.close()


def format_ms(value):
    return "na" if value is None else f"{value:.3f}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=lab_address, default="10.0.0.10")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--source-port", type=int, default=0,
                        help="Optional fixed local UDP port for packet-capture demonstrations")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--timeout-ms", type=int, default=500)
    parser.add_argument("--format", choices=("binary", "text"), default="binary",
                        help="binary FGPB header (default) or legacy ddos-probe text payload")
    parser.add_argument("--mode", choices=("stopwait", "stream"), default="stopwait",
                        help="stopwait waits for each reply; stream sends on a fixed schedule")
    parser.add_argument("--metrics-json", help="Write loss, ordering, RTT percentile, and jitter summary")
    parser.add_argument("--session-id", type=int, help="FGPB session id (default: random u32)")
    parser.add_argument("--payload-bytes", type=int, default=None,
                        help=f"Binary datagram size, {HEADER_LEN}..{MAX_PAYLOAD_BYTES} (default 64)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not 0 <= args.source_port <= 65535:
        parser.error("source-port must be between 0 and 65535")
    if not 1 <= args.count <= 1000:
        parser.error("count must be between 1 and 1000")
    if not 50 <= args.interval_ms <= 60000:
        parser.error("interval-ms must be between 50 and 60000")
    if not 1 <= args.timeout_ms <= 10000:
        parser.error("timeout-ms must be between 1 and 10000")
    if args.session_id is not None and not 0 <= args.session_id <= 0xFFFFFFFF:
        parser.error("session-id must be between 0 and 4294967295")
    if args.payload_bytes is not None:
        if args.format == "text":
            parser.error("payload-bytes applies only to --format binary")
        if not HEADER_LEN <= args.payload_bytes <= MAX_PAYLOAD_BYTES:
            parser.error(f"payload-bytes must be between {HEADER_LEN} and {MAX_PAYLOAD_BYTES}")
    payload_bytes = args.payload_bytes or 64
    session_id = secrets.randbits(32) if args.session_id is None else args.session_id

    def make_payload(sequence):
        return build_payload(args.format, sequence, session_id, payload_bytes)

    stats = ProbeStats()
    print(CSV_HEADER, flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if args.source_port:
            sock.bind(("0.0.0.0", args.source_port))
        (run_stream if args.mode == "stream" else run_stopwait)(sock, args, stats, make_payload)

    summary = stats.summary()
    received = summary["received"]
    rtt = summary["rtt_ms"]
    print(f"sent={args.count} received={received} loss={100 * (args.count - received) / args.count:.1f}%", file=sys.stderr)
    print(f"metrics p50={format_ms(rtt['p50'])} p95={format_ms(rtt['p95'])} p99={format_ms(rtt['p99'])} "
          f"jitter={format_ms(summary['jitter_ms_rfc3550'])}", file=sys.stderr)
    if args.metrics_json:
        report = {"format": args.format, "mode": args.mode,
                  "session_id": session_id if args.format == "binary" else None, **summary}
        Path(args.metrics_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if received == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
