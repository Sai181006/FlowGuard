"""Pluggable flood detectors that consume CounterTracker samples.

Every detector exposes the same interface as the original TwoWindowDetector:
    name, protected_sources, alert_active, high_windows,
    observe(rates) -> alert dict | None, qualifying_sources(rates), reset(), state()
`rates` is the dict returned by CounterTracker.sample(). An alert dict holds
at least {"victim_pps": float, "sources": {source: pps}}; adaptive detectors
add "detector" and "scores".
"""

from controller.detection import TwoWindowDetector


DETECTOR_NAMES = ("threshold", "ewma", "cusum", "entropy")


def build_detector(config, protected_sources=None):
    """Create the detector selected by an effective configuration.

    `protected_sources` defaults to the configured list; callers such as the
    controller may add the victim and client addresses.
    """
    name = config.get("detector", "threshold")
    protected = config["protected_sources"] if protected_sources is None else protected_sources
    if name == "threshold":
        return TwoWindowDetector(config["victim_pps"], config["source_pps"], config["min_sources"],
                                 config["consecutive_windows"], protected)
    raise ValueError(f"detector {name!r} is not available")
