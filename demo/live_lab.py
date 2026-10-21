"""Real, bounded localhost UDP filtering demo for Windows and macOS.

Uses the original detector, echo server and probe. The enforcement point is a
Python userspace gateway, not Open vSwitch. Only 127.0.0.1 is used on the wire.
"""

from __future__ import annotations

import argparse
import csv
import json
import selectors
import socket
import subprocess
import sys
import time
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.detection import CounterTracker, FlowCounter, TwoWindowDetector

ADDRESS = "127.0.0.1"
PORTS = {"victim": 19000, "gateway": 19001, "backend": 19002,
         "client": 19011, "a1": 19021, "a2": 19022}
IDENTITIES = {"client": "10.0.0.11", "a1": "10.0.0.21", "a2": "10.0.0.22"}
SOURCE_BY_PORT = {PORTS[name]: identity for name, identity in IDENTITIES.items()}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def bound_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # SO_REUSEADDR is intentionally absent: a concurrent demo must fail closed.
        sock.bind((ADDRESS, port))
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise


class LivePolicy:
    """Actual received/forwarded counts feeding the project's unchanged detector."""

    def __init__(self, config, mitigation, started, event):
        self.config, self.mitigation, self.event = config, mitigation, event
        self.tracker = CounterTracker()
        self.detector = TwoWindowDetector(
            config["victim_pps"], config["source_pps"], config["min_sources"],
            config["consecutive_windows"], config["protected_sources"])
        self.offered, self.forwarded, self.dropped = Counter(), Counter(), Counter()
        self.forwarded_bytes = Counter()
        self.rules = {}
        self.alerts = 0
        self.first_alert_s = None
        self.started = started
        self.tracker.sample(started, self.counters())

    def counters(self):
        return [FlowCounter(source, "10.0.0.10", "native-gateway", self.forwarded[source],
                            self.forwarded_bytes[source]) for source in IDENTITIES.values()]

    def expire(self, now):
        for source, deadline in list(self.rules.items()):
            if now >= deadline:
                del self.rules[source]
                self.event("rule_expired", source=source)

    def receive(self, source, size, now):
        self.expire(now)
        self.offered[source] += 1
        if source in self.rules and source not in self.detector.protected_sources:
            self.dropped[source] += 1
            return False
        return True

    def forwarded_packet(self, source, size):
        self.forwarded[source] += 1
        self.forwarded_bytes[source] += size

    def sample(self, now):
        self.expire(now)
        rates = self.tracker.sample(now, self.counters())
        alert = self.detector.observe(rates)
        if alert:
            self.alerts += 1
            if self.first_alert_s is None:
                self.first_alert_s = now - self.started
            self.event("alert", sources=alert["sources"], victim_pps=alert["victim_pps"])
        if self.mitigation and self.detector.alert_active:
            for source in self.detector.qualifying_sources(rates):
                if source not in self.rules:
                    self.rules[source] = now + self.config["mitigation_hard_timeout_s"]
                    self.event("gateway_drop_installed", source=source,
                               timeout_s=self.config["mitigation_hard_timeout_s"],
                               enforcement="Python userspace UDP gateway")
        return rates


class Gateway:
    def __init__(self, frontend, backend, policy, packet_log, started, victim_port=19000):
        self.frontend, self.backend, self.policy = frontend, backend, policy
        self.packet_log, self.started, self.victim_port = packet_log, started, victim_port
        self.pending = {}
        self.echoes = Counter()
        self.phase_echoes = Counter()
        self.phase_forwarded = Counter()
        self.errors = Counter()

    def incoming(self, now, phase):
        data, peer = self.frontend.recvfrom(2048)
        source = SOURCE_BY_PORT.get(peer[1]) if peer[0] == ADDRESS else None
        if source is None:
            self.errors["unknown_source"] += 1
            return
        permitted = self.policy.receive(source, len(data), now)
        decision = "DROP"
        if permitted:
            if len(self.pending) >= 20000 or data in self.pending:
                self.errors["pending_limit_or_duplicate"] += 1
                decision = "ERROR"
            else:
                self.backend.sendto(data, (ADDRESS, self.victim_port))
                self.policy.forwarded_packet(source, len(data))
                self.phase_forwarded[(phase, source)] += 1
                self.pending[data] = (peer, source, now, phase)
                decision = "FORWARD"
        self.packet_log.writerow([utc_now(), f"{now - self.started:.6f}", phase, source,
                                  peer[0], peer[1], PORTS["gateway"], len(data), decision,
                                  data[:64].decode("ascii", errors="replace")])

    def reply(self):
        data, peer = self.backend.recvfrom(2048)
        if peer != (ADDRESS, self.victim_port):
            self.errors["unexpected_echo_peer"] += 1
            return
        pending = self.pending.pop(data, None)
        if pending:
            client_peer, source, _, phase = pending
            self.frontend.sendto(data, client_peer)
            self.echoes[source] += 1
            self.phase_echoes[(phase, source)] += 1

    def expire_pending(self, now):
        for data, (_, _, sent, _) in list(self.pending.items()):
            if now - sent > 2:
                self.pending.pop(data)
                self.errors["echo_timeout"] += 1


def phase_at(elapsed, duration, hold):
    if elapsed < 2:
        return "baseline"
    if elapsed < 2 + duration:
        return "attack"
    if elapsed < 2 + duration + hold:
        return "expiry-wait"
    return "recovery"


def run_trial(output, mitigation, pps=600, duration=8):
    """Run real datagrams; retain an incomplete marker if any process fails."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    config = json.loads((ROOT / "config/detector.json").read_text(encoding="utf-8"))
    hold = config["mitigation_hard_timeout_s"] + 1
    total_s = 2 + duration + hold + 2
    metadata = {"execution_status": "running", "started_utc": utc_now(),
                "provenance": "Real localhost UDP; Python gateway enforcement, not OpenFlow",
                "mitigation": mitigation, "pps_per_source": pps, "attack_duration_s": duration,
                "config": config, "ports": PORTS, "logical_identity_mapping": IDENTITIES,
                "on_wire_address": ADDRESS, "platform": sys.platform}
    server = client = None
    try:
        with ExitStack() as stack:
            event_stream = stack.enter_context((output / "events.jsonl").open("w", encoding="utf-8"))
            packet_stream = stack.enter_context((output / "packets.csv").open("w", newline="", encoding="utf-8"))
            packets = csv.writer(packet_stream)
            packets.writerow(["timestamp_utc", "t_s", "phase", "logical_source", "wire_ip",
                              "source_port", "gateway_port", "payload_bytes", "gateway_decision", "payload_prefix"])
            started = time.monotonic()

            def event(kind, **details):
                record = {"timestamp_utc": utc_now(), "t_s": round(time.monotonic() - started, 6),
                          "type": kind, **details}
                event_stream.write(json.dumps(record) + "\n")
                event_stream.flush()
                if kind != "sample":
                    print(f"  [{record['t_s']:6.2f}s] {kind}: {json.dumps(details)}", flush=True)

            policy = LivePolicy(config, mitigation, started, event)
            selector = stack.enter_context(selectors.DefaultSelector())
            frontend = stack.enter_context(bound_socket(PORTS["gateway"]))
            backend = stack.enter_context(bound_socket(PORTS["backend"]))
            # Check fixed ports before starting children. All sockets close on any error.
            for name in ("victim", "client"):
                with bound_socket(PORTS[name]):
                    pass
            sources = {name: stack.enter_context(bound_socket(PORTS[name])) for name in ("a1", "a2")}
            gateway = Gateway(frontend, backend, policy, packets, started, PORTS["victim"])
            selector.register(frontend, selectors.EVENT_READ, "incoming")
            selector.register(backend, selectors.EVENT_READ, "reply")
            for name, sock in sources.items():
                selector.register(sock, selectors.EVENT_READ, name)
            server_log = stack.enter_context((output / "server.log").open("w", encoding="utf-8"))
            server = subprocess.Popen(
                [sys.executable, "-u", str(ROOT / "traffic/echo_server.py"), "--bind", ADDRESS,
                 "--port", str(PORTS["victim"]), "--stats-jsonl", str(output / "victim.jsonl")],
                stdout=server_log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 5
            while "UDP echo listening" not in (output / "server.log").read_text(encoding="utf-8"):
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Echo server failed to become ready; inspect server.log")
                time.sleep(0.03)
            client_csv = stack.enter_context((output / "client.csv").open("w", encoding="utf-8", newline=""))
            client_log = stack.enter_context((output / "client.log").open("w", encoding="utf-8"))
            # Start measurement only after sockets and echo service are ready.
            started = time.monotonic()
            gateway.started = policy.started = started
            policy.tracker.reset()
            policy.tracker.sample(started, policy.counters())
            metadata["measurement_started_utc"] = utc_now()
            client_count = int(total_s * 10)
            client = subprocess.Popen(
                [sys.executable, "-u", str(ROOT / "traffic/probe.py"), "--target", ADDRESS,
                 "--port", str(PORTS["gateway"]), "--source-port", str(PORTS["client"]),
                 "--count", str(client_count), "--interval-ms", "100"],
                stdout=client_csv, stderr=client_log)
            next_sample = started + config["poll_interval_s"]
            next_send = dict.fromkeys(sources, started)
            sequence = Counter()
            previous_phase = None
            print("       time   phase         forwarded/s  dropped total  active rules", flush=True)
            # Keep servicing sockets until the probe process finishes. Windows
            # scheduling can make its nominal 100 ms intervals run slightly late.
            # The extra deadline bounds cleanup if a child stalls or loses replies.
            while time.monotonic() - started < total_s + 8:
                now = time.monotonic()
                elapsed = now - started
                phase = phase_at(elapsed, duration, hold)
                if phase != previous_phase:
                    event("phase", name=phase)
                    previous_phase = phase
                    next_send = dict.fromkeys(sources, now)
                if server.poll() is not None:
                    raise RuntimeError("Echo server exited during trial")
                if client.poll() is not None and client.returncode not in (0, 1):
                    raise RuntimeError("Probe process failed; inspect client.log")
                if elapsed >= total_s + 0.2 and client.poll() is not None and not gateway.pending:
                    break
                for name, sock in sources.items():
                    rate = pps if phase == "attack" else (2 if phase in ("baseline", "recovery") and elapsed < total_s else 0)
                    if rate:
                        # Pace by real time; cap catch-up to avoid long scheduler stalls creating bursts.
                        next_send[name] = max(next_send[name], now - 0.02)
                        while next_send[name] <= now:
                            sequence[name] += 1
                            payload = f"flowguard:{name}:{phase}:{sequence[name]}:{time.time_ns()}".encode("ascii").ljust(128, b".")
                            sock.sendto(payload, (ADDRESS, PORTS["gateway"]))
                            next_send[name] += 1 / rate
                policy.expire(now)
                if now >= next_sample:
                    rates = policy.sample(now)
                    event("sample", rates=rates, offered=dict(policy.offered),
                          forwarded=dict(policy.forwarded), dropped=dict(policy.dropped),
                          active_rules=dict(policy.rules))
                    print(f"  {elapsed:8.2f}   {phase:12} {rates['victim_pps']:11.1f}  "
                          f"{sum(policy.dropped.values()):13}  {len(policy.rules):12}", flush=True)
                    next_sample = now + config["poll_interval_s"]
                    gateway.expire_pending(now)
                # Windows selectors operate on sockets; no pipes or Unix-only calls are used.
                for key, _ in selector.select(timeout=0.001):
                    for _ in range(128):
                        try:
                            if key.data == "incoming":
                                gateway.incoming(time.monotonic(), phase)
                            elif key.data == "reply":
                                gateway.reply()
                            else:
                                key.fileobj.recvfrom(2048)
                        except BlockingIOError:
                            break
            client.wait(timeout=5)
            client_csv.flush()
            with (output / "client.csv").open(newline="", encoding="utf-8") as client_input:
                rows = list(csv.DictReader(client_input))
            replies = [row for row in rows if row["status"] == "ok"]
            source_summary = {name: {"logical_ip": identity, "offered": policy.offered[identity],
                                    "forwarded": policy.forwarded[identity], "dropped": policy.dropped[identity],
                                    "victim_echo_replies": gateway.echoes[identity],
                                    "recovery_echo_replies": gateway.phase_echoes[("recovery", identity)]}
                              for name, identity in IDENTITIES.items()}
            checks = {"complete_client_csv": len(rows) == client_count,
                      "protected_client_all_replied": len(replies) == client_count and client.returncode == 0,
                      "two_source_alert": policy.alerts > 0,
                      "expected_filtering": (all(source_summary[n]["dropped"] > 0 for n in sources)
                                              if mitigation else not any(policy.dropped.values())),
                      "protected_client_never_dropped": source_summary["client"]["dropped"] == 0,
                      "rules_expired": not policy.rules,
                      "source_recovery": all(source_summary[n]["recovery_echo_replies"] > 0 for n in sources),
                      "no_gateway_errors": not gateway.errors,
                      "every_forward_received_echo": all(s["forwarded"] == s["victim_echo_replies"]
                                                          for s in source_summary.values())}
            metadata.update(execution_status="completed", finished_utc=utc_now(), sources=source_summary,
                            first_alert_s=policy.first_alert_s, alerts=policy.alerts,
                            client={"sent": len(rows), "expected": client_count, "received": len(replies),
                                    "mean_rtt_ms": (sum(float(r["rtt_ms"]) for r in replies) / len(replies)) if replies else None},
                            gateway_errors=dict(gateway.errors), checks=checks,
                            validation_status="passed" if all(checks.values()) else "failed")
            event("finished", validation_status=metadata["validation_status"], checks=checks)
    except BaseException as exc:
        metadata.update(execution_status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
                        validation_status="failed", error=str(exc) or type(exc).__name__)
        raise
    finally:
        stop(client)
        stop(server)
        (output / "summary.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"\n  {metadata['validation_status'].upper()}: client {len(replies)}/{client_count}; "
          f"observed gateway drops {sum(policy.dropped.values()):,}; evidence: {output}", flush=True)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mitigation", choices=("on", "off", "compare"), default="compare")
    parser.add_argument("--pps", type=int, default=600, help="Per-source localhost rate (100..2000)")
    parser.add_argument("--duration-s", type=int, default=8, help="Attack phase length (4..30 seconds)")
    parser.add_argument("--output", type=Path, help="Fresh evidence directory; existing paths are rejected")
    args = parser.parse_args()
    if not 100 <= args.pps <= 2000 or not 4 <= args.duration_s <= 30:
        parser.error("pps must be 100..2000 and duration-s must be 4..30")
    output = args.output or ROOT / "artifacts" / "terminal-runs" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    if output.exists():
        parser.error("output already exists; choose a fresh directory")
    print("\nFLOWGUARD | LIVE LOCALHOST LAB\n"
          "Real UDP sockets + original detector, echo server and probe.\n"
          "Enforcement: Python gateway. This run does not install OpenFlow rules.\n"
          "Wire: 127.0.0.1 only. Logical host identities are mapped from source ports.\n"
          "client :19011 -> gateway :19001 -> backend :19002 -> victim :19000\n"
          "a1     :19021 -^   a2 :19022 -^\n"
          "Phases: 2s normal -> bounded attack -> rule-expiry wait -> 2s recovery.\n"
          "A local PCAP requires Wireshark/Npcap or another real capture tool.\n", flush=True)
    results = {}
    try:
        for mode in (("off", "on") if args.mitigation == "compare" else (args.mitigation,)):
            print(f"\n=== MITIGATION {mode.upper()} ===", flush=True)
            results[mode] = run_trial(output / mode, mode == "on", args.pps, args.duration_s)
        if len(results) == 2:
            print("\nCOMPARISON | real received datagrams, entire trial")
            for mode, result in results.items():
                sources = result["sources"]
                offered = sum(sources[n]["offered"] for n in ("a1", "a2"))
                echoed = sum(sources[n]["victim_echo_replies"] for n in ("a1", "a2"))
                dropped = sum(sources[n]["dropped"] for n in ("a1", "a2"))
                print(f"  {mode.upper():3} | attacker ingress {offered:6,} | victim echoes {echoed:6,} | "
                      f"gateway drops {dropped:6,} | client {result['client']['received']}/{result['client']['sent']}")
            print("Rates are configured equally; actual counts vary with OS scheduling.\n"
                  "Both clients may have zero loss. This shows filtering, not proven saturation protection.")
        (output / "comparison.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        return 0 if all(r["validation_status"] == "passed" for r in results.values()) else 1
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"\nDemo failed: {exc}\nCheck {output}. Close other terminal labs and run doctor again.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nDemo stopped; child services closed. Partial evidence is marked interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
