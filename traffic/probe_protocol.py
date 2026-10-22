"""FlowGuard probe (FGPB) wire format, payload descriptions, and probe metrics.

Stdlib only: the offline dashboard imports this module under ``python -S``.

FGPB header, 32 bytes, network byte order (``HEADER = "!4sBBHIIQHHI"``)::

    off  field        type  value
    0    magic        4s    b"FGPB"
    4    version      u8    1
    5    msg_type     u8    1=probe request, 2=probe reply (reserved), 3=flood
    6    header_len   u16   32
    8    session_id   u32   random per run
    12   seq          u32   starts at 1
    16   tx_time_ns   u64   sender wall clock (display only)
    24   payload_len  u16   padding bytes after the header
    26   flags        u16   bit0 = padded
    28   crc32        u32   zlib.crc32(bytes[0:28] + bytes[32:])

The echo server returns requests unchanged, so a reply carries msg_type 1.
"""

import csv
import math
import re
import struct
import zlib
from dataclasses import dataclass


HEADER = struct.Struct("!4sBBHIIQHHI")
HEADER_LEN = HEADER.size
MAGIC = b"FGPB"
VERSION = 1
PROBE_REQUEST = 1
PROBE_REPLY = 2
FLOOD = 3
FLAG_PADDED = 0x0001
MAX_TOTAL_BYTES = 65507
TYPE_NAMES = {PROBE_REQUEST: "probe", PROBE_REPLY: "probe-reply", FLOOD: "flood"}

_CRC_OFFSET = 28
_LEGACY_PROBE = re.compile(rb"ddos-probe:(\d+):(\d+)")
_MININET_FLOOD = b"FLOWGUARD-LAB-ONLY:"
_NATIVE_LAB = re.compile(rb"flowguard:([A-Za-z0-9_-]+):([A-Za-z0-9_-]+):(\d+):(\d+)\.*")


def _checksum(data):
    return zlib.crc32(data[:_CRC_OFFSET] + data[HEADER_LEN:]) & 0xFFFFFFFF


def encode(seq, session_id, tx_time_ns, msg_type=PROBE_REQUEST, total_bytes=64):
    """Return one FGPB datagram of exactly ``total_bytes`` bytes."""
    if not HEADER_LEN <= total_bytes <= MAX_TOTAL_BYTES:
        raise ValueError(f"total_bytes must be between {HEADER_LEN} and {MAX_TOTAL_BYTES}")
    if msg_type not in TYPE_NAMES:
        raise ValueError("unknown msg_type")
    pad_len = total_bytes - HEADER_LEN
    padding = bytes(index & 0xFF for index in range(pad_len))
    flags = FLAG_PADDED if pad_len else 0
    header = HEADER.pack(MAGIC, VERSION, msg_type, HEADER_LEN, session_id & 0xFFFFFFFF,
                         seq & 0xFFFFFFFF, tx_time_ns & 0xFFFFFFFFFFFFFFFF, pad_len, flags, 0)
    crc = _checksum(header + padding)
    return header[:_CRC_OFFSET] + struct.pack("!I", crc) + padding


@dataclass(frozen=True)
class ProbeHeader:
    """Decoded FGPB header; ``crc_ok`` is False when the checksum mismatches."""
    magic: bytes
    version: int
    msg_type: int
    header_len: int
    session_id: int
    seq: int
    tx_time_ns: int
    payload_len: int
    flags: int
    crc32: int
    crc_ok: bool


def decode(data):
    """Decode an FGPB datagram, or return None if it is not a consistent FGPB v1 packet."""
    data = bytes(data)
    if len(data) < HEADER_LEN or data[:4] != MAGIC:
        return None
    fields = HEADER.unpack_from(data)
    magic, version, msg_type, header_len, session_id, seq, tx_time_ns, payload_len, flags, crc = fields
    if version != VERSION or header_len != HEADER_LEN or len(data) != HEADER_LEN + payload_len:
        return None
    return ProbeHeader(magic, version, msg_type, header_len, session_id, seq, tx_time_ns,
                       payload_len, flags, crc, crc == _checksum(data))


def _ascii_prefix(data, limit=64):
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data[:limit])


def describe(data):
    """Return a one-line human description of a FlowGuard lab UDP payload."""
    data = bytes(data)
    if not data:
        return "(empty)"
    if data[:4] == MAGIC:
        header = decode(data)
        if header is None:
            return f"FGPB malformed ({len(data)} bytes)"
        kind = TYPE_NAMES.get(header.msg_type, f"type{header.msg_type}")
        return (f"FGPB {kind} seq={header.seq} session=0x{header.session_id:08x} "
                f"len={len(data)} crc={'ok' if header.crc_ok else 'BAD'}")
    match = _LEGACY_PROBE.fullmatch(data)
    if match:
        return f"legacy text probe seq={int(match.group(1))} tx_ns={int(match.group(2))}"
    if data.startswith(_MININET_FLOOD):
        return f"Mininet lab flood ({len(data)} bytes)"
    match = _NATIVE_LAB.fullmatch(data)
    if match:
        source, phase, seq, _ = (group.decode("ascii") for group in match.groups())
        return f"native lab {source} phase={phase} seq={seq} ({len(data)} bytes)"
    return _ascii_prefix(data)


def percentile(values, p):
    """Nearest-rank percentile: the value at rank ceil(p*n/100), p in (0, 100]; None if empty."""
    if not 0 < p <= 100:
        raise ValueError("p must be in (0, 100]")
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, math.ceil(round(p * len(ordered) / 100, 9)))
    return ordered[rank - 1]


class JitterEstimator:
    """Incremental RFC 3550 section 6.4.1 interarrival jitter.

    Feed ``update(send_ns, recv_ns)`` in arrival order. For consecutive packets
    D = (R_i - R_{i-1}) - (S_i - S_{i-1}) and J += (|D| - J) / 16. When send and
    receive stamps come from the same host clock (probe send and echo reply
    receive), the transit R - S is the RTT, so D is the RTT difference.
    """

    def __init__(self):
        self._previous_transit = None
        self.jitter_ns = 0.0
        self.samples = 0

    def update(self, send_ns, recv_ns):
        transit = recv_ns - send_ns
        if self._previous_transit is not None:
            delta = transit - self._previous_transit
            self.jitter_ns += (abs(delta) - self.jitter_ns) / 16
        self._previous_transit = transit
        self.samples += 1
        return self.jitter_ns

    @property
    def jitter_ms(self):
        """Jitter in milliseconds, or None before two samples exist."""
        return self.jitter_ns / 1e6 if self.samples >= 2 else None


def rfc3550_jitter(transit_pairs):
    """Return RFC 3550 jitter (ms) for ``(send_ns, recv_ns)`` pairs in arrival order, or None."""
    estimator = JitterEstimator()
    for send_ns, recv_ns in transit_pairs:
        estimator.update(send_ns, recv_ns)
    return estimator.jitter_ms


def _round(value):
    return None if value is None else round(value, 3)


class ProbeStats:
    """Classify probe replies and summarize loss, ordering, RTT, and jitter.

    Loss counts sent probes without an on-time reply. Reordering follows RFC 4737:
    a first arrival whose seq is below the highest seq already received.
    """

    def __init__(self):
        self.sent_ns = {}
        self.rtt_ns = {}
        self.seen = set()
        self.late = 0
        self.duplicates = 0
        self.reordered = 0
        self.highest = 0
        self.jitter = JitterEstimator()
        self._retroactive = False

    def on_send(self, seq, t_ns):
        self.sent_ns[seq] = t_ns

    def on_reply(self, seq, t_ns, deadline_passed=False):
        """Record a reply; return "ok", "late", "duplicate", or "unknown"."""
        if seq not in self.sent_ns:
            return "unknown"
        if seq in self.seen:
            self.duplicates += 1
            return "duplicate"
        self.seen.add(seq)
        if seq < self.highest:
            self.reordered += 1
        self.highest = max(self.highest, seq)
        if deadline_passed:
            self.late += 1
            return "late"
        self.rtt_ns[seq] = t_ns - self.sent_ns[seq]
        self.jitter.update(self.sent_ns[seq], t_ns)
        return "ok"

    def max_consecutive_loss(self):
        longest = run = 0
        for seq in sorted(self.sent_ns):
            run = 0 if seq in self.rtt_ns else run + 1
            longest = max(longest, run)
        return longest

    def summary(self):
        sent = len(self.sent_ns)
        received = len(self.rtt_ns)
        rtts = [value / 1e6 for value in self.rtt_ns.values()]
        unknown = self._retroactive
        return {
            "sent": sent,
            "received": received,
            "loss_percent": round(100 * (sent - received) / sent, 3) if sent else 0.0,
            "late": None if unknown else self.late,
            "duplicates": None if unknown else self.duplicates,
            "reordered": None if unknown else self.reordered,
            "max_consecutive_loss": self.max_consecutive_loss(),
            "rtt_ms": {
                "min": _round(min(rtts)) if rtts else None,
                "mean": _round(sum(rtts) / len(rtts)) if rtts else None,
                "p50": _round(percentile(rtts, 50)),
                "p95": _round(percentile(rtts, 95)),
                "p99": _round(percentile(rtts, 99)),
                "max": _round(max(rtts)) if rtts else None,
            },
            "jitter_ms_rfc3550": _round(self.jitter.jitter_ms),
        }

    @classmethod
    def from_csv(cls, path):
        """Rebuild metrics from a probe CSV (timestamp_utc,sequence,status,rtt_ms).

        Non-numeric rows such as trailing ``sent=...`` or ``metrics ...`` lines are
        ignored. Late, duplicate, and reordered counts are None because the CSV
        cannot show them; jitter uses consecutive RTT differences of ok rows.
        """
        stats = cls()
        stats._retroactive = True
        with open(path, newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                try:
                    seq = int((row.get("sequence") or "").strip())
                except ValueError:
                    continue
                if seq in stats.sent_ns:
                    continue
                base = seq * 10**12
                stats.on_send(seq, base)
                if (row.get("status") or "").strip() != "ok":
                    continue
                try:
                    rtt_ms = float(row.get("rtt_ms") or "")
                except ValueError:
                    continue
                stats.on_reply(seq, base + round(rtt_ms * 1e6))
        return stats
