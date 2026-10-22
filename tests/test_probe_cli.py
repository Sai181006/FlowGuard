import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traffic.probe import CSV_HEADER, build_payload
from traffic.probe_protocol import decode

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "traffic/probe.py"
ECHO = ROOT / "traffic/echo_server.py"
METRICS_LINE = re.compile(r"^metrics p50=(na|\d+\.\d{3}) p95=(na|\d+\.\d{3}) "
                          r"p99=(na|\d+\.\d{3}) jitter=(na|\d+\.\d{3})$")


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_echo_server():
    """Start traffic/echo_server.py on an ephemeral port, retrying if the port is taken."""
    for _ in range(5):
        port = free_udp_port()
        server = subprocess.Popen([sys.executable, "-u", str(ECHO), "--bind", "127.0.0.1", "--port", str(port)],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if "UDP echo listening" in (server.stdout.readline() or ""):
            return server, port
        stop(server)
    raise RuntimeError("echo server did not start")


def stop(server):
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)
    if server.stdout:
        server.stdout.close()


class MisbehavingEcho:
    """Hold reply 1 until request 2 arrives, then send reply 1, reply 2, and reply 2 again."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        held = None
        count = 0
        while not self.stopping.is_set():
            try:
                data, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            count += 1
            if count == 1:
                held = data
                continue
            if count == 2:
                self.sock.sendto(held, peer)
                self.sock.sendto(data, peer)
            self.sock.sendto(data, peer)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stopping.set()
        self.thread.join(timeout=3)
        self.sock.close()


def run_probe(port, *extra, timeout=30):
    return subprocess.run([sys.executable, str(PROBE), "--target", "127.0.0.1", "--port", str(port), *extra],
                          capture_output=True, text=True, timeout=timeout, check=False)


class PayloadTests(unittest.TestCase):
    def test_text_payload_matches_legacy_bytes(self):
        self.assertEqual(build_payload("text", 7, tx_time_ns=1_700_000_000_000_000_123),
                         b"ddos-probe:7:1700000000000000123")

    def test_binary_payload_is_fgpb(self):
        payload = build_payload("binary", 9, session_id=0xCAFE, payload_bytes=100, tx_time_ns=5)
        header = decode(payload)
        self.assertEqual(len(payload), 100)
        self.assertEqual((header.seq, header.session_id, header.tx_time_ns, header.crc_ok), (9, 0xCAFE, 5, True))


class ProbeCliTests(unittest.TestCase):
    def check_output(self, result, count, ok_rows):
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], CSV_HEADER)
        rows = [line.split(",") for line in lines[1:]]
        self.assertEqual([int(row[1]) for row in rows], list(range(1, count + 1)))
        self.assertEqual(sum(row[2] == "ok" for row in rows), ok_rows)
        for row in rows:
            self.assertEqual(len(row), 4)
            if row[2] == "ok":
                self.assertGreaterEqual(float(row[3]), 0)
            else:
                self.assertEqual((row[2], row[3]), ("timeout", ""))
        stderr = result.stderr.strip().splitlines()
        loss = 100 * (count - ok_rows) / count
        self.assertEqual(stderr[-2], f"sent={count} received={ok_rows} loss={loss:.1f}%")
        self.assertRegex(stderr[-1], METRICS_LINE)
        return rows

    def test_formats_and_modes_against_echo_server(self):
        server, port = start_echo_server()
        try:
            with tempfile.TemporaryDirectory() as directory:
                for fmt in ("binary", "text"):
                    for mode in ("stopwait", "stream"):
                        with self.subTest(format=fmt, mode=mode):
                            metrics = Path(directory) / f"{fmt}-{mode}.json"
                            result = run_probe(port, "--count", "5", "--interval-ms", "50", "--format", fmt,
                                               "--mode", mode, "--session-id", "305419896",
                                               "--metrics-json", str(metrics))
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.check_output(result, 5, 5)
                            report = json.loads(metrics.read_text(encoding="utf-8"))
                            self.assertEqual((report["format"], report["mode"]), (fmt, mode))
                            self.assertEqual(report["session_id"], 305419896 if fmt == "binary" else None)
                            self.assertEqual((report["sent"], report["received"], report["loss_percent"]),
                                             (5, 5, 0.0))
                            self.assertEqual((report["late"], report["duplicates"], report["reordered"],
                                              report["max_consecutive_loss"]), (0, 0, 0, 0))
                            rtt = report["rtt_ms"]
                            self.assertLessEqual(rtt["min"], rtt["p50"])
                            self.assertLessEqual(rtt["p50"], rtt["p95"])
                            self.assertLessEqual(rtt["p95"], rtt["p99"])
                            self.assertLessEqual(rtt["p99"], rtt["max"])
                            self.assertGreaterEqual(report["jitter_ms_rfc3550"], 0)
        finally:
            stop(server)

    def test_silent_target_times_out(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            port = silent.getsockname()[1]
            for mode in ("stopwait", "stream"):
                with self.subTest(mode=mode):
                    result = run_probe(port, "--count", "2", "--interval-ms", "50", "--timeout-ms", "20",
                                       "--mode", mode)
                    self.assertEqual(result.returncode, 1)
                    self.check_output(result, 2, 0)
                    self.assertEqual(result.stderr.strip().splitlines()[-1],
                                     "metrics p50=na p95=na p99=na jitter=na")

    def test_late_and_duplicate_replies_are_classified(self):
        for mode in ("stopwait", "stream"):
            with self.subTest(mode=mode), MisbehavingEcho() as echo, tempfile.TemporaryDirectory() as directory:
                metrics = Path(directory) / "metrics.json"
                result = run_probe(echo.port, "--count", "3", "--interval-ms", "300", "--timeout-ms", "150",
                                   "--mode", mode, "--metrics-json", str(metrics))
                self.assertEqual(result.returncode, 1, result.stderr)
                rows = self.check_output(result, 3, 2)
                self.assertEqual([row[2] for row in rows], ["timeout", "ok", "ok"])
                report = json.loads(metrics.read_text(encoding="utf-8"))
                self.assertEqual((report["late"], report["duplicates"], report["reordered"]), (1, 1, 0))
                self.assertEqual(report["max_consecutive_loss"], 1)

    def test_flood_formats(self):
        # Redirect the fixed lab TARGET to a local socket so nothing leaves 127.0.0.1.
        script = ("import sys, traffic.flood as f; f.TARGET = ('127.0.0.1', int(sys.argv[1])); "
                  "sys.argv = ['flood.py'] + sys.argv[2:]; f.main()")
        for fmt in ("text", "binary"):
            with self.subTest(format=fmt), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
                sink.bind(("127.0.0.1", 0))
                sink.settimeout(0.5)
                result = subprocess.run([sys.executable, "-c", script, str(sink.getsockname()[1]), "--pps", "50",
                                         "--duration-s", "0.2", "--size", "100", "--format", fmt],
                                        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                sent = json.loads(result.stdout.splitlines()[-1])["sent"]
                packets = [sink.recvfrom(2048)[0] for _ in range(sent)]
                if fmt == "text":
                    self.assertEqual(set(packets), {b"FLOWGUARD-LAB-ONLY:".ljust(100, b"X")})
                    continue
                headers = [decode(packet) for packet in packets]
                self.assertEqual([header.seq for header in headers], list(range(1, sent + 1)))
                self.assertTrue(all(header.msg_type == 3 and header.crc_ok and len(packet) == 100
                                    for header, packet in zip(headers, packets)))
                self.assertEqual(len({header.session_id for header in headers}), 1)

    def test_argument_validation(self):
        for extra in (["--payload-bytes", "31"], ["--payload-bytes", "513"],
                      ["--format", "text", "--payload-bytes", "64"], ["--session-id", "-1"],
                      ["--mode", "burst"], ["--interval-ms", "10"]):
            with self.subTest(extra=extra):
                result = run_probe(9, *extra)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
