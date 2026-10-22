"""Real, bounded localhost UDP filtering demo for Windows and macOS.

Uses the original detector, echo server and probe. The enforcement point is a
Python userspace gateway, not Open vSwitch. Only 127.0.0.1 is used on the wire.

Optionally (--bottleneck-pps) the gateway's link to the victim is an emulated
constant-rate queue (demo/queueing.py, FIFO or RED). The flood then congests
that link, and the protected client's loss and delay show whether mitigation
restores availability. The queue is a userspace model, not a kernel qdisc.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import selectors
import socket
import subprocess
import sys
import time
from collections import Counter, namedtuple
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.config import DETECTOR_NAMES, MITIGATION_ACTIONS, apply_overrides, effective_config, load_config
from controller.detection import CounterTracker, FlowCounter
from controller.detectors import build_detector
from controller.mitigation import OffenderHistory, TokenBucket, choose_action
from demo.queueing import DISCIPLINES, BottleneckQueue, red_defaults

try:  # Payload descriptions and probe metrics; optional so older checkouts still run.
    from traffic import probe_protocol
except ImportError:  # pragma: no cover - depends on the checkout
    probe_protocol = None

ADDRESS = "127.0.0.1"
DEFAULT_PORTS_BASE = 19000
PORT_OFFSETS = {"victim": 0, "gateway": 1, "backend": 2, "client": 11, "a1": 21, "a2": 22}
PORTS = {name: DEFAULT_PORTS_BASE + offset for name, offset in PORT_OFFSETS.items()}
IDENTITIES = {"client": "10.0.0.11", "a1": "10.0.0.21", "a2": "10.0.0.22"}
SOURCE_BY_PORT = {PORTS[name]: identity for name, identity in IDENTITIES.items()}
ATTACKERS = ("a1", "a2")
WAVE_GAP_S = 6
PASSING = ("FORWARD", "RL_PASS")
Rule = namedtuple("Rule", "deadline action bucket")


def set_ports(base):
    """Move the fixed port layout (tests and parallel checks only); updates maps in place."""
    for name in IDENTITIES:
        SOURCE_BY_PORT.pop(PORTS[name], None)
    PORTS.update({name: base + offset for name, offset in PORT_OFFSETS.items()})
    SOURCE_BY_PORT.update({PORTS[name]: identity for name, identity in IDENTITIES.items()})


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


def describe_payload(data):
    if probe_protocol is not None:
        return probe_protocol.describe(data)
    return data[:64].decode("ascii", errors="replace")


class LivePolicy:
    """Actual received/forwarded counts feeding the project's detector and response policy.

    `forwarded` counts packets that passed the policy, like an OpenFlow flow
    counter at the switch; with a bottleneck some of them may still be lost
    in the egress queue afterwards.
    """

    def __init__(self, config, mitigation, started, event):
        self.config = effective_config(config)
        self.mitigation, self.event = mitigation, event
        self.tracker = CounterTracker()
        self.protected = frozenset(self.config["protected_sources"])
        self.detector = build_detector(self.config, self.config["protected_sources"])
        self.history = OffenderHistory.from_config(self.config)
        self.response = self.config["mitigation"]
        self.offered, self.forwarded, self.dropped = Counter(), Counter(), Counter()
        self.rl_passed, self.rl_dropped = Counter(), Counter()
        self.forwarded_bytes = Counter()
        self.rules = {}  # source -> Rule(deadline, "drop" | "rate_limit", TokenBucket | None)
        self.alerts = 0
        self.first_alert_s = None
        self.started = started
        self.tracker.sample(started, self.counters())

    def counters(self):
        return [FlowCounter(source, "10.0.0.10", "native-gateway", self.forwarded[source],
                            self.forwarded_bytes[source]) for source in IDENTITIES.values()]

    def rule(self, source):
        rule = self.rules.get(source)
        if rule is None or isinstance(rule, Rule):
            return rule
        return Rule(rule, "drop", None)  # A bare deadline is a drop rule.

    def expire(self, now):
        for source in list(self.rules):
            rule = self.rule(source)
            if now >= rule.deadline:
                del self.rules[source]
                self.event("rule_expired", source=source, action=rule.action,
                           offense_count=self.history.offense_count(source))

    def classify(self, source, size, now):
        """Return FORWARD, DROP, RL_PASS or RL_DROP for one received datagram."""
        self.expire(now)
        self.offered[source] += 1
        rule = self.rule(source)
        if rule is None or source in self.protected:
            return "FORWARD"
        if rule.action == "rate_limit":
            if rule.bucket.allow(now):
                self.rl_passed[source] += 1
                return "RL_PASS"
            self.rl_dropped[source] += 1
            self.dropped[source] += 1
            return "RL_DROP"
        self.dropped[source] += 1
        return "DROP"

    def receive(self, source, size, now):
        return self.classify(source, size, now) in PASSING

    def forwarded_packet(self, source, size):
        self.forwarded[source] += 1
        self.forwarded_bytes[source] += size

    def install(self, source, now):
        offense, timeout = self.history.next_offense(source, now)
        action = choose_action(self.response["action"], offense, self.response["graduated_drop_after"])
        if action == "rate_limit":
            rate, burst = self.response["rate_limit_pps"], self.response["rate_limit_burst_packets"]
            self.rules[source] = Rule(now + timeout, "rate_limit", TokenBucket(rate, burst, now))
            self.event("gateway_ratelimit_installed", source=source, rate_pps=rate, burst=burst,
                       timeout_s=timeout, offense_count=offense,
                       enforcement="Python userspace UDP gateway token bucket")
        else:
            self.rules[source] = Rule(now + timeout, "drop", None)
            self.event("gateway_drop_installed", source=source, timeout_s=timeout,
                       enforcement="Python userspace UDP gateway", offense_count=offense)

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
                if source not in self.rules and source not in self.protected:
                    self.install(source, now)
        return rates

    def active_rules(self):
        """JSON-safe view: {source: deadline} plus {source: action}."""
        rules = {source: self.rule(source) for source in self.rules}
        return ({source: rule.deadline for source, rule in rules.items()},
                {source: rule.action for source, rule in rules.items()})


class Gateway:
    def __init__(self, frontend, backend, policy, packet_log, started, victim_port=19000, queue=None):
        self.frontend, self.backend, self.policy = frontend, backend, policy
        self.packet_log, self.started, self.victim_port = packet_log, started, victim_port
        self.queue = queue
        self.pending = {}
        self.echoes = Counter()
        self.delivered = Counter()  # datagrams actually sent to the victim
        self.queue_drops = Counter()
        self.phase_echoes = Counter()
        self.phase_forwarded = Counter()
        self.phase_queue_delays = {}
        self.errors = Counter()

    @property
    def queue_depth(self):
        return 0 if self.queue is None else self.queue.depth

    def _send(self, data, peer, source, phase, now):
        self.backend.sendto(data, (ADDRESS, self.victim_port))
        self.delivered[source] += 1
        self.phase_forwarded[(phase, source)] += 1
        self.pending[data] = (peer, source, now, phase)

    def incoming(self, now, phase):
        data, peer = self.frontend.recvfrom(2048)
        source = SOURCE_BY_PORT.get(peer[1]) if peer[0] == ADDRESS else None
        if source is None:
            self.errors["unknown_source"] += 1
            return
        decision = self.policy.classify(source, len(data), now)
        depth = ""
        if decision in PASSING:
            if len(self.pending) >= 20000 or data in self.pending:
                self.errors["pending_limit_or_duplicate"] += 1
                decision = "ERROR"
            elif self.queue is None:
                self._send(data, peer, source, phase, now)
                self.policy.forwarded_packet(source, len(data))
            else:
                # Counted like a switch flow counter, before the egress queue.
                self.policy.forwarded_packet(source, len(data))
                outcome = self.queue.offer((data, peer, source, phase), now)
                if outcome != "enqueued":
                    self.queue_drops[source] += 1
                    decision = "QUEUE_TAIL_DROP" if outcome == "tail_drop" else "QUEUE_RED_DROP"
                depth = self.queue.depth
        self.packet_log.writerow([utc_now(), f"{now - self.started:.6f}", phase, source,
                                  peer[0], peer[1], PORTS["gateway"], len(data), decision,
                                  describe_payload(data), depth])

    def service(self, now):
        """Transmit queued datagrams whose emulated link departure time has come."""
        if self.queue is None:
            return 0
        released = self.queue.due(now)
        for (data, peer, source, phase), delay in released:
            if data in self.pending:
                self.errors["pending_limit_or_duplicate"] += 1
                continue
            self._send(data, peer, source, phase, now)
            delays = self.phase_queue_delays.setdefault(phase, [])
            if len(delays) < 100_000:
                delays.append(delay)
        return len(released)

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


def phase_plan(duration, hold, waves=1, gap=WAVE_GAP_S, baseline=2):
    """[(name, start_s, end_s, wave)]: baseline, attack waves split by gaps, expiry wait, recovery."""
    plan, t = [("baseline", 0.0, float(baseline), 0)], float(baseline)
    for wave in range(1, waves + 1):
        plan.append(("attack", t, t + duration, wave))
        t += duration
        if wave < waves:
            plan.append(("gap", t, t + gap, wave))
            t += gap
    plan.append(("expiry-wait", t, t + hold, 0))
    plan.append(("recovery", t + hold, math.inf, 0))
    return plan


def phase_at(elapsed, duration, hold, waves=1, gap=WAVE_GAP_S, baseline=2):
    return wave_phase(elapsed, duration, hold, waves, gap, baseline)[0]


def wave_phase(elapsed, duration, hold, waves=1, gap=WAVE_GAP_S, baseline=2):
    for name, start, end, wave in phase_plan(duration, hold, waves, gap, baseline):
        if elapsed < end:
            return name, wave
    return "recovery", 0


def expiry_hold(config, waves):
    """Rule-expiry wait: the longest timeout one offense per wave can earn, plus 1 s."""
    base = config["mitigation_hard_timeout_s"]
    backoff = config["mitigation"]["backoff"]
    if backoff["enabled"]:
        base = min(backoff["max_timeout_s"], round(base * backoff["factor"] ** (waves - 1)))
    return int(base) + 1


def baseline_seconds(config):
    """Normal-traffic lead-in: 2 s, or long enough for an adaptive detector's warm-up.

    Warm-up windows learn unconditionally, so an attack that starts during
    warm-up would be learned as normal; two warm windows of normal traffic follow.
    """
    name = config["detector"]
    if name == "threshold":
        return 2
    warmup = config["detectors"][name]["warmup_windows"]
    return max(2, math.ceil((warmup + 2) * config["poll_interval_s"]))


def trial_seconds(config, duration, waves):
    """(baseline_s, hold_s, total_s) for one trial."""
    baseline, hold = baseline_seconds(config), expiry_hold(config, waves)
    return baseline, hold, baseline + waves * duration + (waves - 1) * WAVE_GAP_S + hold + 2


def _percentile(values, p):
    ordered = sorted(values)
    if not ordered:
        return None
    return ordered[max(1, math.ceil(round(p * len(ordered) / 100, 9))) - 1]


def probe_metrics(rows):
    """Loss, RTT percentiles and RFC 3550 jitter (consecutive RTT differences) for probe rows."""
    rows = sorted(rows, key=lambda row: int(row["sequence"]))
    rtts = []
    for row in rows:
        if (row.get("status") or "").strip() == "ok":
            try:
                rtts.append(float(row["rtt_ms"]))
            except (TypeError, ValueError):
                pass
    jitter = 0.0
    for previous, current in zip(rtts, rtts[1:]):
        jitter += (abs(current - previous) - jitter) / 16
    sent = len(rows)
    rounded = (lambda v: None if v is None else round(v, 3))
    return {"sent": sent, "received": len(rtts),
            "loss_percent": round(100 * (sent - len(rtts)) / sent, 3) if sent else None,
            "rtt_ms": {"p50": rounded(_percentile(rtts, 50)), "p95": rounded(_percentile(rtts, 95)),
                       "max": rounded(max(rtts) if rtts else None)},
            "jitter_ms_rfc3550": round(jitter, 3) if len(rtts) >= 2 else None}


def client_phase_metrics(rows, started_wall, duration, hold, waves, baseline=2):
    """Group probe rows by the phase in which each probe was sent (timestamp_utc = send time).

    With several waves, "attack" covers all of them and "attack-waveN" each one.
    """
    groups = {}
    for row in rows:
        try:
            int(row["sequence"])
            sent_at = datetime.fromisoformat(row["timestamp_utc"])
        except (KeyError, TypeError, ValueError):
            continue
        phase, wave = wave_phase((sent_at - started_wall).total_seconds(), duration, hold, waves,
                                 baseline=baseline)
        groups.setdefault(phase, []).append(row)
        if waves > 1 and phase == "attack":
            groups.setdefault(f"attack-wave{wave}", []).append(row)
    return {phase: probe_metrics(group) for phase, group in groups.items()}


def probe_supports_stream():
    """True if traffic/probe.py offers --mode stream (fixed-schedule probing)."""
    try:
        result = subprocess.run([sys.executable, str(ROOT / "traffic/probe.py"), "--help"],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return "--mode" in result.stdout and "stream" in result.stdout


def run_trial(output, mitigation, pps=600, duration=8, config=None, bottleneck=None, waves=1):
    """Run real datagrams; retain an incomplete marker if any process fails.

    `bottleneck` is None (direct forwarding, the original lab) or
    {"service_pps", "queue_packets", "discipline", "red"} for an emulated link.
    """
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    if config is None:
        config = json.loads((ROOT / "config/detector.json").read_text(encoding="utf-8"))
    config = effective_config(config)
    baseline, hold, total_s = trial_seconds(config, duration, waves)
    queue = None
    if bottleneck:
        queue = BottleneckQueue(bottleneck["service_pps"], bottleneck["queue_packets"],
                                bottleneck["discipline"], bottleneck.get("red"), seed=0)
    # Stop-and-wait probing slows down while replies are lost (each loss waits 500 ms),
    # which would undersample the congested phase; a fixed schedule samples it evenly.
    probe_mode = "stream" if queue is not None and probe_supports_stream() else "stopwait"
    metadata = {"execution_status": "running", "started_utc": utc_now(),
                "provenance": "Real localhost UDP; Python gateway enforcement, not OpenFlow",
                "mitigation": mitigation, "pps_per_source": pps, "attack_duration_s": duration,
                "config": config, "ports": dict(PORTS), "logical_identity_mapping": IDENTITIES,
                "on_wire_address": ADDRESS, "platform": sys.platform,
                "detector": config["detector"], "response_action": config["mitigation"]["action"],
                "backoff_enabled": config["mitigation"]["backoff"]["enabled"],
                "waves": waves, "wave_gap_s": WAVE_GAP_S if waves > 1 else None, "baseline_s": baseline,
                "phase_plan": [{"phase": n, "start_s": s, "end_s": None if math.isinf(e) else e, "wave": w}
                               for n, s, e, w in phase_plan(duration, hold, waves, baseline=baseline)],
                "probe_mode": probe_mode,
                "bottleneck": None if queue is None else {
                    "model": "emulated D/1 egress link in the Python gateway (userspace, not a kernel qdisc)",
                    "service_pps": queue.service_pps, "queue_packets": queue.capacity,
                    "discipline": queue.discipline, "red": queue.red,
                    "max_catch_up_s": queue.max_catch_up_s}}
    server = client = None
    replies, client_count, policy, gateway = [], 0, None, None
    try:
        with ExitStack() as stack:
            event_stream = stack.enter_context((output / "events.jsonl").open("w", encoding="utf-8"))
            packet_stream = stack.enter_context((output / "packets.csv").open("w", newline="", encoding="utf-8"))
            packets = csv.writer(packet_stream)
            packets.writerow(["timestamp_utc", "t_s", "phase", "logical_source", "wire_ip",
                              "source_port", "gateway_port", "payload_bytes", "gateway_decision",
                              "payload_prefix", "queue_depth"])
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
            sources = {name: stack.enter_context(bound_socket(PORTS[name])) for name in ATTACKERS}
            gateway = Gateway(frontend, backend, policy, packets, started, PORTS["victim"], queue)
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
            started_wall = datetime.now(timezone.utc)
            gateway.started = policy.started = started
            policy.tracker.reset()
            policy.tracker.sample(started, policy.counters())
            metadata["measurement_started_utc"] = started_wall.isoformat()
            client_count = int(total_s * 10)
            probe_command = [sys.executable, "-u", str(ROOT / "traffic/probe.py"), "--target", ADDRESS,
                             "--port", str(PORTS["gateway"]), "--source-port", str(PORTS["client"]),
                             "--count", str(client_count), "--interval-ms", "100"]
            if probe_mode == "stream":
                probe_command += ["--mode", "stream"]
            client = subprocess.Popen(probe_command, stdout=client_csv, stderr=client_log)
            next_sample = started + config["poll_interval_s"]
            next_send = dict.fromkeys(sources, started)
            sequence = Counter()
            previous_phase = None
            # A stop-and-wait probe falls behind while its replies are lost; allow for that.
            slack_s = 8 + (0.5 * waves * duration if queue is not None and probe_mode == "stopwait" else 0)
            print("       time   phase         forwarded/s  dropped total  active rules"
                  + ("  queue" if queue is not None else ""), flush=True)
            # Keep servicing sockets until the probe process finishes. Windows
            # scheduling can make its nominal 100 ms intervals run slightly late.
            # The extra deadline bounds cleanup if a child stalls or loses replies.
            while time.monotonic() - started < total_s + slack_s:
                now = time.monotonic()
                elapsed = now - started
                phase, wave = wave_phase(elapsed, duration, hold, waves, baseline=baseline)
                if (phase, wave) != previous_phase:
                    if waves > 1 and phase in ("attack", "gap"):
                        event("phase", name=phase, wave=wave)
                    else:
                        event("phase", name=phase)
                    previous_phase = (phase, wave)
                    next_send = dict.fromkeys(sources, now)
                if server.poll() is not None:
                    raise RuntimeError("Echo server exited during trial")
                if client.poll() is not None and client.returncode not in (0, 1):
                    raise RuntimeError("Probe process failed; inspect client.log")
                if (elapsed >= total_s + 0.2 and client.poll() is not None and not gateway.pending
                        and not gateway.queue_depth):
                    break
                for name, sock in sources.items():
                    rate = pps if phase == "attack" else (
                        2 if phase in ("baseline", "gap", "recovery") and elapsed < total_s else 0)
                    if rate:
                        # Pace by real time; cap catch-up to avoid long scheduler stalls creating bursts.
                        next_send[name] = max(next_send[name], now - 0.02)
                        while next_send[name] <= now:
                            sequence[name] += 1
                            payload = f"flowguard:{name}:{phase}:{sequence[name]}:{time.time_ns()}".encode("ascii").ljust(128, b".")
                            sock.sendto(payload, (ADDRESS, PORTS["gateway"]))
                            next_send[name] += 1 / rate
                policy.expire(now)
                gateway.service(now)
                if now >= next_sample:
                    rates = policy.sample(now)
                    deadlines, actions = policy.active_rules()
                    details = {}
                    if queue is not None:
                        details = {"queue_depth": queue.depth, "queue_drops": dict(gateway.queue_drops)}
                    event("sample", rates=rates, offered=dict(policy.offered),
                          forwarded=dict(policy.forwarded), dropped=dict(policy.dropped),
                          active_rules=deadlines, rule_actions=actions, **details)
                    print(f"  {elapsed:8.2f}   {phase:12} {rates['victim_pps']:11.1f}  "
                          f"{sum(policy.dropped.values()):13}  {len(policy.rules):12}"
                          + (f"  {queue.depth:5}" if queue is not None else ""), flush=True)
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
                                     "rate_limit_passed": policy.rl_passed[identity],
                                     "rate_limit_dropped": policy.rl_dropped[identity],
                                     "queue_dropped": gateway.queue_drops[identity],
                                     "delivered_to_victim": gateway.delivered[identity],
                                     "offenses": policy.history.offense_count(identity),
                                     "victim_echo_replies": gateway.echoes[identity],
                                     "recovery_echo_replies": gateway.phase_echoes[("recovery", identity)]}
                              for name, identity in IDENTITIES.items()}
            phases = client_phase_metrics(rows, started_wall, duration, hold, waves, baseline)
            action = config["mitigation"]["action"]
            if not mitigation:
                filtering = not any(policy.dropped.values())
            elif action == "rate_limit":
                filtering = all(source_summary[n]["rate_limit_dropped"] > 0 for n in sources)
            else:
                filtering = all(source_summary[n]["dropped"] > 0 for n in sources)
            checks = {"complete_client_csv": len(rows) == client_count}
            if queue is None:
                checks["protected_client_all_replied"] = len(replies) == client_count and client.returncode == 0
            else:
                # Under congestion client loss is the measurement, not a failure.
                if not mitigation:
                    checks["bottleneck_congested"] = queue.tail_drops + queue.red_drops > 0
                checks["client_loss_measured"] = bool(phases.get("attack", {}).get("sent"))
                checks["client_recovery_all_replied"] = (
                    bool(phases.get("recovery", {}).get("sent")) and phases["recovery"]["loss_percent"] == 0)
            checks.update({
                "two_source_alert": policy.alerts > 0,
                "expected_filtering": filtering,
                "protected_client_never_dropped": source_summary["client"]["dropped"] == 0,
                "rules_expired": not policy.rules,
                "source_recovery": all(source_summary[n]["recovery_echo_replies"] > 0 for n in sources),
                "no_gateway_errors": not gateway.errors,
                "every_forward_received_echo": all(s["delivered_to_victim"] == s["victim_echo_replies"]
                                                   for s in source_summary.values())})
            client_metrics = None
            if probe_protocol is not None:
                client_metrics = probe_protocol.ProbeStats.from_csv(output / "client.csv").summary()
            queue_summary = None
            if queue is not None:
                attack_delays = gateway.phase_queue_delays.get("attack", [])
                queue_summary = {**queue.stats(), "drops_by_source": dict(gateway.queue_drops),
                                 "attack_delay_ms": {
                                     "p50": None if not attack_delays else round(1000 * _percentile(attack_delays, 50), 3),
                                     "p95": None if not attack_delays else round(1000 * _percentile(attack_delays, 95), 3)}}
            metadata.update(execution_status="completed", finished_utc=utc_now(), sources=source_summary,
                            first_alert_s=policy.first_alert_s, alerts=policy.alerts,
                            client={"sent": len(rows), "expected": client_count, "received": len(replies),
                                    "mean_rtt_ms": (sum(float(r["rtt_ms"]) for r in replies) / len(replies)) if replies else None,
                                    "metrics": client_metrics, "phases": phases},
                            queue=queue_summary,
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
    queue_note = "" if queue is None else f"; queue drops {queue.tail_drops + queue.red_drops:,}"
    print(f"\n  {metadata['validation_status'].upper()}: client {len(replies)}/{client_count}; "
          f"observed gateway drops {sum(policy.dropped.values()):,}{queue_note}; evidence: {output}", flush=True)
    return metadata


def attack_view(result):
    """The attack-phase numbers compared between OFF and ON."""
    attack = result["client"]["phases"].get("attack") or {}
    queue = result.get("queue") or {}
    return {"client_loss_percent": attack.get("loss_percent"),
            "client_probes": attack.get("sent"),
            "rtt_p95_ms": (attack.get("rtt_ms") or {}).get("p95"),
            "jitter_ms_rfc3550": attack.get("jitter_ms_rfc3550"),
            "queue_drops": (queue.get("tail_drops", 0) + queue.get("red_drops", 0)) if queue else None,
            "queue_delay_p95_ms": (queue.get("attack_delay_ms") or {}).get("p95") if queue else None,
            "gateway_drops": sum(result["sources"][n]["dropped"] for n in ATTACKERS)}


def compare(results, bottleneck):
    views = {mode: attack_view(result) for mode, result in results.items()}
    off, on = views["off"]["client_loss_percent"], views["on"]["client_loss_percent"]
    if not bottleneck:
        improved, reason = None, "not applicable: no bottleneck, so the flood cannot congest the client path"
    elif off is None or on is None:
        improved, reason = False, "attack-phase client loss could not be measured"
    else:
        improved = on <= off - 10
        reason = (f"ON attack-phase client loss {on:.1f}% vs OFF {off:.1f}% "
                  f"(needs at least 10 percentage points lower)")
    return {"attack_phase": views, "availability_improved": improved, "reason": reason}


def print_comparison(results, comparison, bottleneck):
    print("\nCOMPARISON | real received datagrams, entire trial")
    for mode, result in results.items():
        sources = result["sources"]
        offered = sum(sources[n]["offered"] for n in ATTACKERS)
        echoed = sum(sources[n]["victim_echo_replies"] for n in ATTACKERS)
        dropped = sum(sources[n]["dropped"] for n in ATTACKERS)
        print(f"  {mode.upper():3} | attacker ingress {offered:6,} | victim echoes {echoed:6,} | "
              f"gateway drops {dropped:6,} | client {result['client']['received']}/{result['client']['sent']}")

    def cell(value, digits=1):
        if value is None:
            return f"{'n/a':>10}"
        return f"{value:10,.{digits}f}" if isinstance(value, float) else f"{value:10,}"

    views = comparison["attack_phase"]
    print("\nATTACK PHASE | protected client probes sent during the attack")
    print(f"  {'':28}{'OFF':>10}{'ON':>10}")
    for label, key, digits in (("client loss %", "client_loss_percent", 1),
                               ("client probes", "client_probes", 0),
                               ("p95 RTT ms", "rtt_p95_ms", 1),
                               ("jitter ms (RFC 3550)", "jitter_ms_rfc3550", 2),
                               ("queue drops (whole trial)", "queue_drops", 0),
                               ("queue delay p95 ms", "queue_delay_p95_ms", 1),
                               ("gateway drops (whole trial)", "gateway_drops", 0)):
        print(f"  {label:28}{cell(views['off'][key], digits)}{cell(views['on'][key], digits)}")
    if comparison["availability_improved"] is None:
        print(f"  availability_improved: n/a ({comparison['reason']})")
    else:
        print(f"  availability_improved: {'YES' if comparison['availability_improved'] else 'NO'} "
              f"({comparison['reason']})")
    print("Rates are configured equally; actual counts vary with OS scheduling.")
    if bottleneck:
        print(f"The bottleneck is an emulated {bottleneck['service_pps']:g} packets/s, "
              f"{bottleneck['queue_packets']}-packet {bottleneck['discipline'].upper()} queue inside the "
              "Python gateway, not a kernel or NIC queue.\n"
              "Client loss before mitigation is expected: detection needs whole sampling windows.")
    else:
        print("Both clients may have zero loss. This shows filtering, not proven saturation protection.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mitigation", choices=("on", "off", "compare"), default="compare")
    parser.add_argument("--pps", type=int, default=600, help="Per-source localhost rate (100..2000)")
    parser.add_argument("--duration-s", type=int, default=8, help="Attack phase length (4..30 seconds)")
    parser.add_argument("--output", type=Path, help="Fresh evidence directory; existing paths are rejected")
    parser.add_argument("--bottleneck-pps", type=int, default=0,
                        help="Emulated gateway-to-victim link rate in packets/s (0 = off, else 50..100000)")
    parser.add_argument("--queue-packets", type=int, help="Bottleneck queue capacity, 5..10000 (default 50)")
    parser.add_argument("--queue-discipline", choices=DISCIPLINES, help="Bottleneck queue: fifo (default) or red")
    parser.add_argument("--detector", choices=DETECTOR_NAMES, help="Override the configured detector")
    parser.add_argument("--action", choices=MITIGATION_ACTIONS, help="Override the configured response")
    parser.add_argument("--rate-limit-pps", type=int, help="Token-bucket rate for rate_limit/graduated")
    parser.add_argument("--backoff", action="store_true", default=None,
                        help="Enable exponential rule-timeout back-off for repeat offenders")
    parser.add_argument("--config", type=Path, help="Detector configuration JSON inside this repository")
    parser.add_argument("--waves", type=int, default=1,
                        help=f"Attack waves, 1..3, separated by {WAVE_GAP_S} s gaps (shows back-off)")
    parser.add_argument("--ports-base", type=int, default=DEFAULT_PORTS_BASE, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not 100 <= args.pps <= 2000 or not 4 <= args.duration_s <= 30:
        parser.error("pps must be 100..2000 and duration-s must be 4..30")
    if args.bottleneck_pps and not 50 <= args.bottleneck_pps <= 100_000:
        parser.error("bottleneck-pps must be 0 (off) or 50..100000")
    if not args.bottleneck_pps and (args.queue_packets is not None or args.queue_discipline is not None):
        parser.error("queue-packets and queue-discipline require --bottleneck-pps")
    queue_packets = 50 if args.queue_packets is None else args.queue_packets
    if not 5 <= queue_packets <= 10_000:
        parser.error("queue-packets must be 5..10000")
    if not 1 <= args.waves <= 3:
        parser.error("waves must be 1..3")
    if not 1024 <= args.ports_base <= 65535 - max(PORT_OFFSETS.values()):
        parser.error("ports-base must leave room for the port layout")
    config_path = (args.config or ROOT / "config/detector.json").resolve()
    if ROOT.resolve() not in config_path.parents:
        parser.error("config must be a file inside this repository")
    try:
        config = apply_overrides(load_config(config_path), detector=args.detector, action=args.action,
                                 backoff=args.backoff, rate_limit_pps=args.rate_limit_pps)
        build_detector(config, config["protected_sources"])
    except ValueError as exc:
        parser.error(str(exc))
    baseline, _, total_s = trial_seconds(config, args.duration_s, args.waves)
    if total_s * 10 > 1000:
        parser.error(f"trial would last {total_s} s; the probe allows at most 100 s (fewer waves or shorter attack)")
    bottleneck = None
    if args.bottleneck_pps:
        discipline = args.queue_discipline or "fifo"
        bottleneck = {"service_pps": args.bottleneck_pps, "queue_packets": queue_packets,
                      "discipline": discipline,
                      "red": red_defaults(queue_packets) if discipline == "red" else None}
    if args.ports_base != DEFAULT_PORTS_BASE:
        set_ports(args.ports_base)
    output = args.output or ROOT / "artifacts" / "terminal-runs" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    if output.exists():
        parser.error("output already exists; choose a fresh directory")
    response = config["mitigation"]
    print("\nFLOWGUARD | LIVE LOCALHOST LAB\n"
          "Real UDP sockets + original detector, echo server and probe.\n"
          "Enforcement: Python gateway. This run does not install OpenFlow rules.\n"
          "Wire: 127.0.0.1 only. Logical host identities are mapped from source ports.\n"
          f"client :{PORTS['client']} -> gateway :{PORTS['gateway']} -> backend :{PORTS['backend']} "
          f"-> victim :{PORTS['victim']}\n"
          f"a1     :{PORTS['a1']} -^   a2 :{PORTS['a2']} -^\n"
          f"Phases: {baseline}s normal -> bounded attack -> rule-expiry wait -> 2s recovery.\n"
          "A local PCAP requires Wireshark/Npcap or another real capture tool.", flush=True)
    print(f"Detector: {config['detector']} | response: {response['action']}"
          + (f" ({response['rate_limit_pps']} pps token bucket)" if response["action"] != "drop" else "")
          + f" | back-off: {'on' if response['backoff']['enabled'] else 'off'}"
          + (f" | waves: {args.waves} x {args.duration_s}s, {WAVE_GAP_S}s gaps" if args.waves > 1 else ""))
    if bottleneck:
        print(f"Bottleneck: gateway -> victim link emulated at {args.bottleneck_pps} packets/s with a "
              f"{queue_packets}-packet {bottleneck['discipline'].upper()} queue (userspace model).")
    print(flush=True)
    results = {}
    try:
        for mode in (("off", "on") if args.mitigation == "compare" else (args.mitigation,)):
            print(f"\n=== MITIGATION {mode.upper()} ===", flush=True)
            results[mode] = run_trial(output / mode, mode == "on", args.pps, args.duration_s,
                                      config, bottleneck, args.waves)
        document = dict(results)
        passed = all(r["validation_status"] == "passed" for r in results.values())
        if len(results) == 2:
            comparison = compare(results, bottleneck)
            print_comparison(results, comparison, bottleneck)
            document["comparison"] = comparison
            if bottleneck and not comparison["availability_improved"]:
                passed = False
            print()
        (output / "comparison.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        return 0 if passed else 1
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"\nDemo failed: {exc}\nCheck {output}. Close other terminal labs and run doctor again.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nDemo stopped; child services closed. Partial evidence is marked interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
