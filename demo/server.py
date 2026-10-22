"""Serve the native FlowGuard dashboard on loopback using only the stdlib."""

from __future__ import annotations

import argparse
import csv
import io
import json
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo import engine


MAX_POST_BYTES = 4096
MIN_QUEUE_PACKETS = 5
MAX_QUEUE_PACKETS = 10_000
MAX_RATE_LIMIT_PPS = 100_000
DASHBOARD_ROOT = ROOT / "dashboard"
STATIC_FILES = {
    "/": (ROOT / "dashboard/index.html", "text/html; charset=utf-8"),
    "/index.html": (ROOT / "dashboard/index.html", "text/html; charset=utf-8"),
    "/app.js": (ROOT / "dashboard/app.js", "text/javascript; charset=utf-8"),
    "/styles.css": (ROOT / "dashboard/styles.css", "text/css; charset=utf-8"),
}
STATIC_MIME_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
}
STATIC_PREFIXES = ("/assets/", "/vendor/")


def static_asset(url_path: str):
    """Return a safe dashboard asset mapping without exposing other project files."""
    try:
        decoded = unquote(url_path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None

    # Keep the original fixed routes and allow their percent-encoded forms.
    if decoded in STATIC_FILES:
        return STATIC_FILES[decoded]

    prefix = next((value for value in STATIC_PREFIXES if decoded.startswith(value)), None)
    if prefix is None or "\\" in decoded or "\x00" in decoded or "%" in decoded:
        return None

    relative_name = prefix[1:] + decoded[len(prefix):]
    pieces = relative_name.split("/")
    if not relative_name or any(piece in {"", ".", ".."} for piece in pieces):
        return None

    try:
        dashboard_root = DASHBOARD_ROOT.resolve()
        candidate = (dashboard_root / relative_name).resolve()
        candidate.relative_to(dashboard_root)
    except (OSError, RuntimeError, ValueError):
        return None
    content_type = STATIC_MIME_TYPES.get(candidate.suffix.lower())
    if content_type is None or not candidate.is_file():
        return None
    return candidate, content_type


def _single_query(query: dict[str, list[str]], key: str, default=None):
    values = query.get(key)
    if not values:
        return default
    if len(values) != 1:
        raise ValueError(f"{key} may be provided only once")
    return values[0]


def _int_param(query, key, default, minimum, maximum):
    raw = _single_query(query, key, default)
    if isinstance(raw, int):
        value = raw
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")
    return value


def _float_param(query, key, default, minimum=0.0, maximum=1_000_000.0):
    raw = _single_query(query, key, default)
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum:g} and {maximum:g}")
    return value


def _choice_param(query, key, allowed):
    """An optional value that must be one of the allow-listed names."""
    raw = _single_query(query, key, None)
    if raw is None:
        return None
    if raw not in allowed:
        raise ValueError(f"{key} must be one of: {', '.join(allowed)}")
    return raw


def _bool_param(query, key, default):
    raw = str(_single_query(query, key, default)).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{key} must be 1 or 0")


class FlowGuardHandler(BaseHTTPRequestHandler):
    server_version = "FlowGuardDashboard/1.0"
    protocol_version = "HTTP/1.1"

    def _allowed_hosts(self):
        port = self.server.server_port
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _valid_host(self):
        return self.headers.get("Host", "") in self._allowed_hosts()

    def _valid_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return False
        try:
            parsed = urlsplit(origin)
        except ValueError:
            return False
        return (
            parsed.scheme == "http"
            and parsed.netloc in self._allowed_hosts()
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
            and not parsed.username
            and not parsed.password
        )

    def _send_bytes(self, payload: bytes, content_type: str, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, value, status=200):
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(payload, "application/json; charset=utf-8", status)

    def _error(self, message, status=400):
        self._json({"error": message}, status)

    def _host_guard(self):
        if not self._valid_host():
            self._error("This server accepts requests addressed to localhost only.", 403)
            return False
        return True

    def do_GET(self):
        if not self._host_guard():
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        asset = static_asset(path)
        if asset is not None:
            source, content_type = asset
            try:
                payload = source.read_bytes()
            except OSError:
                self._error("Dashboard asset is not available yet.", 404)
                return
            self._send_bytes(payload, content_type)
            return

        if path == "/api/bootstrap":
            self._json(engine.bootstrap_data(self.server.csrf_token))
            return
        if path == "/api/simulation":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                scenario = _single_query(query, "scenario", "sustained")
                mitigation = _bool_param(query, "mitigation", "1")
                pps = _int_param(query, "pps", 600, 1, 100_000)
                capacity = _int_param(query, "capacity", 1000, 1, 1_000_000)
                victim_pps = _float_param(query, "victim_pps", None)
                source_pps = _float_param(query, "source_pps", None)
                min_sources = _int_param(query, "min_sources", engine.detector_config()["min_sources"], 1, 10)
                consecutive = _int_param(
                    query,
                    "consecutive_windows",
                    engine.detector_config()["consecutive_windows"],
                    1,
                    10,
                )
                detector = _choice_param(query, "detector", engine.DETECTOR_NAMES)
                action = _choice_param(query, "action", engine.MITIGATION_ACTIONS)
                backoff = _bool_param(query, "backoff", None) if "backoff" in query else None
                rate_limit = (_int_param(query, "rate_limit", None, 1, MAX_RATE_LIMIT_PPS)
                              if "rate_limit" in query else None)
                queue = _int_param(query, "queue", 0, 0, MAX_QUEUE_PACKETS) if "queue" in query else 0
                if 0 < queue < MIN_QUEUE_PACKETS:
                    raise ValueError(f"queue must be 0 (off) or between {MIN_QUEUE_PACKETS} and {MAX_QUEUE_PACKETS}")
                result = engine.simulate(
                    scenario=scenario,
                    mitigation=mitigation,
                    pps=pps,
                    capacity=capacity,
                    victim_pps=victim_pps,
                    source_pps=source_pps,
                    min_sources=min_sources,
                    consecutive_windows=consecutive,
                    detector=detector,
                    action=action,
                    backoff=backoff,
                    rate_limit_pps=rate_limit,
                    queue_packets=queue or None,
                )
            except (ValueError, TypeError) as exc:
                self._error(str(exc), 400)
                return
            self._json(result)
            return

        if path == "/api/benchmark":
            try:
                self._json(engine.benchmark_data())
            except FileNotFoundError:
                self._error("The offline detector benchmark has not been generated.", 404)
            except (OSError, ValueError) as exc:
                self._error(f"Could not load the offline detector benchmark: {exc}", 500)
            return

        if path == "/api/recorded":
            try:
                self._json(engine.recorded_data())
            except (OSError, ValueError, KeyError, csv.Error) as exc:
                self._error(f"Could not load the saved recorded experiment: {exc}", 500)
            return

        self._error("Not found.", 404)

    def do_POST(self):
        if not self._host_guard():
            return
        if not self._valid_origin():
            self._error("A same-origin localhost request is required.", 403)
            return
        if self.headers.get("X-FlowGuard-CSRF") != self.server.csrf_token:
            self._error("Missing or invalid local request token.", 403)
            return
        if urlsplit(self.path).path != "/api/probe":
            self._error("Not found.", 404)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error("Invalid content length.", 400)
            return
        if content_length < 0 or content_length > MAX_POST_BYTES:
            self._error("Request body is too large.", 413)
            return
        body = self.rfile.read(content_length) if content_length else b""
        if body:
            try:
                decoded = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._error("Expected a JSON object.", 400)
                return
            if not isinstance(decoded, dict):
                self._error("Expected a JSON object.", 400)
                return
        try:
            self._json(run_local_probe())
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            self._error(f"Local UDP probe failed: {exc}", 500)

    def log_message(self, format_string, *args):
        # Keep the local server quiet for presentation use.
        return


def run_local_probe() -> dict:
    """Run exactly five echo probes to a temporary 127.0.0.1 UDP service."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    echo_path = ROOT / "traffic/echo_server.py"
    probe_path = ROOT / "traffic/probe.py"
    with tempfile.TemporaryDirectory(prefix="flowguard-local-probe-") as directory:
        log_path = Path(directory) / "echo.log"
        server = None
        try:
            with log_path.open("w+", encoding="utf-8") as log:
                server = subprocess.Popen(
                    [sys.executable, "-u", str(echo_path), "--bind", "127.0.0.1", "--port", str(port)],
                    cwd=ROOT,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                deadline = time.monotonic() + 5
                while "UDP echo listening" not in log_path.read_text(encoding="utf-8", errors="replace"):
                    if server.poll() is not None:
                        raise RuntimeError("local echo server exited before becoming ready")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("local echo server did not become ready")
                    time.sleep(0.05)
                probe = subprocess.run(
                    [
                        sys.executable,
                        str(probe_path),
                        "--target",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--count",
                        "5",
                        "--interval-ms",
                        "100",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
        finally:
            if server is not None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)

    rows = list(csv.DictReader(io.StringIO(probe.stdout)))
    if len(rows) != 5:
        raise RuntimeError("the probe script returned an unexpected number of rows")
    parsed_rows = []
    for row in rows:
        parsed_rows.append({
            "timestamp_utc": row["timestamp_utc"],
            "sequence": int(row["sequence"]),
            "status": row["status"],
            "rtt_ms": float(row["rtt_ms"]) if row["rtt_ms"] else None,
        })
    received = sum(row["status"] == "ok" for row in parsed_rows)
    rtts = [row["rtt_ms"] for row in parsed_rows if row["rtt_ms"] is not None]
    return {
        "mode": "live_udp",
        "provenance": {
            "kind": "live_udp",
            "label": "Five real UDP echo probes to a temporary service bound only to 127.0.0.1.",
        },
        "target": "127.0.0.1",
        "csv": probe.stdout,
        "rows": parsed_rows,
        "summary": {
            "sent": len(parsed_rows),
            "received": received,
            "loss_percent": 100.0 * (len(parsed_rows) - received) / len(parsed_rows),
            "mean_rtt_ms": sum(rtts) / len(rtts) if rtts else None,
        },
    }


def serve(port=8765):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), FlowGuardHandler)
    httpd.daemon_threads = True
    httpd.csrf_token = secrets.token_urlsafe(32)
    print(f"FlowGuard dashboard: http://127.0.0.1:{httpd.server_port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765, help="localhost HTTP port (default: 8765)")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    serve(args.port)


if __name__ == "__main__":
    main()
