"""Sample Linux qdisc counters of the bottleneck port during a FlowGuard trial.

``tc -s -j qdisc show dev s1-eth1`` is run in the root network namespace,
where Open vSwitch's ports (and therefore the TCLink qdiscs built by Mininet)
live, so run_trial calls it directly rather than through a Mininet host.

With the TCLink tree (``htb 5:`` root, ``netem 10:`` leaf, optional ``red 6:``
between them) the *root* HTB counters are the totals: HTB counts a drop on
itself whenever a child drops on enqueue, and its ``backlog``/``qlen`` include
the packets waiting in the netem leaf. Use the root entry for totals and the
leaf for the configured ``limit``.

A tc failure never aborts the trial: the sample is written with an ``error``
field and an empty ``qdiscs`` list.
"""

import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


TC_TIMEOUT_S = 5
STAT_KEYS = ("packets", "bytes", "drops", "overlimits", "requeues")


def tc_command(dev):
    return ["tc", "-s", "-j", "qdisc", "show", "dev", str(dev)]


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def parse_tc_json(text):
    """Normalise ``tc -s -j qdisc show`` output into a list of flat dicts.

    Each entry has kind, handle, parent ("root" for the root qdisc), packets,
    bytes, drops, overlimits, requeues, backlog_bytes, qlen and, when tc
    reports one, the qdisc's configured ``limit``.
    """
    data = json.loads(text) if text and text.strip() else []
    if not isinstance(data, list):
        raise ValueError("tc JSON output must be a list of qdiscs")
    result = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("tc JSON qdisc entries must be objects")
        options = item.get("options") if isinstance(item.get("options"), dict) else {}
        entry = {"kind": item.get("kind"), "handle": item.get("handle"),
                 "parent": "root" if item.get("root") else item.get("parent")}
        entry.update({key: _count(item.get(key)) for key in STAT_KEYS})
        entry["backlog_bytes"] = _count(item.get("backlog"))
        entry["qlen"] = _count(item.get("qlen"))
        if isinstance(options.get("limit"), int):
            entry["limit"] = options["limit"]
        result.append(entry)
    return result


def root_qdisc(qdiscs):
    """Return the root qdisc entry of a parsed list, or None."""
    return next((entry for entry in qdiscs if entry.get("parent") == "root"), None)


def read_qdiscs(dev, runner=None):
    """Run tc once and return (raw JSON text, parsed list). Raises on failure."""
    runner = subprocess.check_output if runner is None else runner
    raw = runner(tc_command(dev), text=True, timeout=TC_TIMEOUT_S)
    return raw, parse_tc_json(raw)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class QdiscMonitor:
    """Append one JSONL sample of the device's qdiscs every ``interval`` seconds."""

    def __init__(self, dev, path, interval=0.5, runner=None, clock=time.monotonic):
        if interval <= 0:
            raise ValueError("interval must be positive")
        self.dev = dev
        self.path = Path(path)
        self.interval = interval
        self.runner = runner
        self.clock = clock
        self.samples = 0
        self.errors = 0
        self._stop = threading.Event()
        self._thread = None
        self._file = None

    def sample(self):
        record = {"monotonic_s": self.clock(), "time_utc": utc_now(), "dev": self.dev}
        try:
            _, record["qdiscs"] = read_qdiscs(self.dev, self.runner)
        except Exception as exc:  # tc missing, timeout, bad JSON: keep the trial running
            record["qdiscs"] = []
            record["error"] = f"{type(exc).__name__}: {exc}"
            self.errors += 1
        self.samples += 1
        return record

    def _write(self, record):
        self._file.write(json.dumps(record, sort_keys=True) + "\n")
        self._file.flush()

    def _run(self):
        while True:
            try:
                self._write(self.sample())
            except Exception:  # a write failure must not kill the trial either
                self.errors += 1
            if self._stop.wait(self.interval):
                return

    def start(self):
        if self._thread is not None:
            raise RuntimeError("qdisc monitor already started")
        self._file = self.path.open("a", encoding="utf-8")
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="flowguard-qdisc-monitor", daemon=True)
        self._thread.start()
        return self

    @property
    def active(self):
        return self._thread is not None

    def stop(self):
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=self.interval + TC_TIMEOUT_S + 1)
            self._thread = None
        if self._file is not None:
            self._file.close()
            self._file = None
        return {"file": self.path.name, "dev": self.dev, "interval_s": self.interval,
                "samples": self.samples, "errors": self.errors}
