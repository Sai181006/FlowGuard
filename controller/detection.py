"""Reset-safe OpenFlow counter rates and two-window flood detection."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowCounter:
    source: str
    destination: str
    identity: str
    packets: int
    bytes: int


class CounterTracker:
    def __init__(self):
        self.previous = {}
        self.previous_time = None

    def reset(self):
        self.previous.clear()
        self.previous_time = None

    def sample(self, now, counters):
        current = {(f.source, f.destination, f.identity): f for f in counters}
        elapsed = None if self.previous_time is None else now - self.previous_time
        packet_rates = {}
        byte_rates = {}
        resets = []
        if elapsed is not None and elapsed > 0:
            for key, flow in current.items():
                old = self.previous.get(key)
                if old is None:
                    continue
                packet_delta = flow.packets - old.packets
                byte_delta = flow.bytes - old.bytes
                if packet_delta < 0 or byte_delta < 0:
                    resets.append(flow.source)
                    continue
                packet_rates[flow.source] = packet_rates.get(flow.source, 0.0) + packet_delta / elapsed
                byte_rates[flow.source] = byte_rates.get(flow.source, 0.0) + byte_delta / elapsed
        self.previous = current
        self.previous_time = now
        return {
            "elapsed_s": elapsed,
            "source_pps": packet_rates,
            "source_bytes_per_s": byte_rates,
            "victim_pps": sum(packet_rates.values()),
            "counter_resets": sorted(set(resets)),
        }


class TwoWindowDetector:
    """Fixed thresholds: victim rate and per-source rate high for N consecutive windows."""

    name = "threshold"

    def __init__(self, victim_pps, source_pps, min_sources=2, consecutive_windows=2, protected_sources=()):
        self.victim_pps = victim_pps
        self.source_pps = source_pps
        self.min_sources = min_sources
        self.consecutive_windows = consecutive_windows
        self.protected_sources = frozenset(protected_sources)
        self.high_windows = 0
        self.alert_active = False

    def reset(self):
        self.high_windows = 0
        self.alert_active = False

    def state(self):
        """JSON-safe diagnostics for logs and the dashboard."""
        return {"detector": self.name, "high_windows": self.high_windows,
                "alert_active": self.alert_active}

    def qualifying_sources(self, rates):
        """Return current sources over threshold, excluding protected hosts."""
        return {
            source: rate for source, rate in rates["source_pps"].items()
            if source not in self.protected_sources and rate > self.source_pps
        }

    def observe(self, rates):
        sources = self.qualifying_sources(rates)
        high = rates["victim_pps"] > self.victim_pps and len(sources) >= self.min_sources
        if not high:
            self.reset()
            return None
        self.high_windows += 1
        if self.alert_active or self.high_windows < self.consecutive_windows:
            return None
        self.alert_active = True
        return {"victim_pps": rates["victim_pps"], "sources": sources}
