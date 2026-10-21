"""Detector and mitigation configuration: schema, defaults and validation.

The seven original keys stay at the top level with their original rules.
The optional "detector", "detectors" and "mitigation" sections select the
detection algorithm and the graduated response. When they are absent, the
defaults below reproduce the original behaviour exactly: the two-window
threshold detector with fixed 10-second drop rules.
"""

import copy
import hashlib
import json
import math
from pathlib import Path

from controller.lab import CLIENT_IP, LAB_IPS, VICTIM_IP


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "detector.json"
DETECTOR_NAMES = ("threshold", "ewma", "cusum", "entropy")
MITIGATION_ACTIONS = ("drop", "rate_limit", "graduated")
LEGACY_KEYS = frozenset({
    "poll_interval_s", "victim_pps", "source_pps", "min_sources",
    "consecutive_windows", "protected_sources", "mitigation_hard_timeout_s",
})
OPTIONAL_KEYS = frozenset({"detector", "detectors", "mitigation"})

DEFAULTS = {
    "detector": "threshold",
    "detectors": {
        "ewma": {"alpha": 0.2, "k_sigma": 4.0, "sigma_floor_pps": 2.0, "min_rate_pps": 20.0,
                 "warmup_windows": 3, "min_sources": 1},
        "cusum": {"alpha": 0.2, "drift_k": 0.5, "threshold_h": 6.0, "z_clip": 4.0,
                  "sigma_floor_pps": 2.0, "min_rate_pps": 20.0, "warmup_windows": 3,
                  "min_sources": 1},
        "entropy": {"alpha": 0.2, "kl_threshold_bits": 0.5, "share_delta": 0.10,
                    "min_victim_pps": 50.0, "smoothing_pps": 0.5, "warmup_windows": 3,
                    "min_sources": 1},
    },
    "mitigation": {
        "action": "drop",
        "rate_limit_pps": 20,
        "rate_limit_burst_packets": 20,
        "graduated_drop_after": 2,
        "backoff": {"enabled": False, "factor": 2.0, "max_timeout_s": 80, "memory_s": 120},
    },
}

# (kind, minimum, maximum, minimum_exclusive)
_DETECTOR_SCHEMA = {
    "ewma": {
        "alpha": ("number", 0.0, 1.0, True), "k_sigma": ("number", 0.5, 50.0, False),
        "sigma_floor_pps": ("number", 0.01, 1e6, False), "min_rate_pps": ("number", 0.0, 1e7, False),
        "warmup_windows": ("integer", 0, 1000, False), "min_sources": ("sources", 1, None, False),
    },
    "cusum": {
        "alpha": ("number", 0.0, 1.0, True), "drift_k": ("number", 0.0, 10.0, False),
        "threshold_h": ("number", 0.0, 1000.0, True), "z_clip": ("number", 0.5, 100.0, False),
        "sigma_floor_pps": ("number", 0.01, 1e6, False), "min_rate_pps": ("number", 0.0, 1e7, False),
        "warmup_windows": ("integer", 0, 1000, False), "min_sources": ("sources", 1, None, False),
    },
    "entropy": {
        "alpha": ("number", 0.0, 1.0, True), "kl_threshold_bits": ("number", 0.0, 20.0, True),
        "share_delta": ("number", 0.0, 1.0, False), "min_victim_pps": ("number", 0.0, 1e7, False),
        "smoothing_pps": ("number", 0.0, 1000.0, True),
        "warmup_windows": ("integer", 0, 1000, False), "min_sources": ("sources", 1, None, False),
    },
}
_MITIGATION_SCHEMA = {
    "rate_limit_pps": ("integer", 1, 1_000_000, False),
    "rate_limit_burst_packets": ("integer", 0, 1_000_000, False),
    "graduated_drop_after": ("integer", 1, 100, False),
}
_BACKOFF_SCHEMA = {
    "factor": ("number", 1.0, 16.0, False),
    "max_timeout_s": ("integer", None, 65535, False),  # lower bound is the base timeout
    "memory_s": ("number", 0.0, 86400.0, False),
}


def _check_number(name, value, minimum, maximum, exclusive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    try:
        finite = math.isfinite(float(value))
    except (OverflowError, ValueError):
        finite = False
    low_ok = value > minimum if exclusive else value >= minimum
    if not finite or not low_ok or value > maximum:
        low = f"greater than {minimum}" if exclusive else f"at least {minimum}"
        raise ValueError(f"{name} must be {low} and at most {maximum}")


def _check_integer(name, value, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")


def _check_section(prefix, section, schema, eligible_count, base_timeout=None):
    if not isinstance(section, dict):
        raise ValueError(f"{prefix} must be a JSON object")
    unknown = section.keys() - schema.keys()
    if unknown:
        raise ValueError(f"unknown keys in {prefix}: {', '.join(sorted(unknown))}")
    for key, value in section.items():
        kind, minimum, maximum, exclusive = schema[key]
        name = f"{prefix}.{key}"
        if kind == "number":
            _check_number(name, value, minimum, maximum, exclusive)
        elif kind == "integer":
            _check_integer(name, value, base_timeout if minimum is None else minimum, maximum)
        else:  # number of unprotected attack sources a detector must name
            _check_integer(name, value, minimum, max(minimum, eligible_count))


def validate_config(config):
    """Reject malformed detector settings and bounds that could disable expiry.

    Returns the same object unchanged so callers can keep using the raw JSON.
    """
    if not isinstance(config, dict):
        raise ValueError("detector configuration must be a JSON object")
    missing = LEGACY_KEYS - config.keys()
    unknown = config.keys() - LEGACY_KEYS - OPTIONAL_KEYS
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing keys: {', '.join(sorted(missing))}")
        if unknown:
            details.append(f"unknown keys: {', '.join(sorted(unknown))}")
        raise ValueError("invalid detector configuration (" + "; ".join(details) + ")")

    def bounded_number(name, minimum, maximum):
        _check_number(name, config[name], minimum, maximum)

    def bounded_integer(name, minimum, maximum):
        _check_integer(name, config[name], minimum, maximum)

    bounded_number("poll_interval_s", 0.1, 60.0)
    bounded_number("victim_pps", 0.0, 10_000_000.0)
    if config["victim_pps"] == 0:
        raise ValueError("victim_pps must be greater than zero")
    bounded_number("source_pps", 0.0, 10_000_000.0)
    if config["source_pps"] == 0:
        raise ValueError("source_pps must be greater than zero")
    bounded_integer("consecutive_windows", 1, 1000)
    # OpenFlow 1.3 encodes hard_timeout as an unsigned 16-bit field.
    bounded_integer("mitigation_hard_timeout_s", 1, 65535)

    protected = config["protected_sources"]
    if not isinstance(protected, list) or any(not isinstance(source, str) for source in protected):
        raise ValueError("protected_sources must be a list of lab IPv4 addresses")
    if len(protected) != len(set(protected)) or not set(protected) <= LAB_IPS:
        raise ValueError("protected_sources must contain unique lab IPv4 addresses")
    eligible_sources = LAB_IPS - {VICTIM_IP, CLIENT_IP} - set(protected)
    bounded_integer("min_sources", 1, len(LAB_IPS) - 2)
    if config["min_sources"] > len(eligible_sources):
        raise ValueError("min_sources exceeds the number of unprotected attack hosts")

    if "detector" in config and config["detector"] not in DETECTOR_NAMES:
        raise ValueError(f"detector must be one of: {', '.join(DETECTOR_NAMES)}")
    if "detectors" in config:
        detectors = config["detectors"]
        if not isinstance(detectors, dict):
            raise ValueError("detectors must be a JSON object")
        unknown = detectors.keys() - _DETECTOR_SCHEMA.keys()
        if unknown:
            raise ValueError(f"unknown detectors: {', '.join(sorted(unknown))}")
        for name, section in detectors.items():
            _check_section(f"detectors.{name}", section, _DETECTOR_SCHEMA[name], len(eligible_sources))
    if "mitigation" in config:
        mitigation = config["mitigation"]
        if not isinstance(mitigation, dict):
            raise ValueError("mitigation must be a JSON object")
        unknown = mitigation.keys() - _MITIGATION_SCHEMA.keys() - {"action", "backoff"}
        if unknown:
            raise ValueError(f"unknown keys in mitigation: {', '.join(sorted(unknown))}")
        if "action" in mitigation and mitigation["action"] not in MITIGATION_ACTIONS:
            raise ValueError(f"mitigation.action must be one of: {', '.join(MITIGATION_ACTIONS)}")
        _check_section("mitigation", {k: v for k, v in mitigation.items() if k in _MITIGATION_SCHEMA},
                       _MITIGATION_SCHEMA, len(eligible_sources))
        if "backoff" in mitigation:
            backoff = mitigation["backoff"]
            if not isinstance(backoff, dict):
                raise ValueError("mitigation.backoff must be a JSON object")
            if "enabled" in backoff and not isinstance(backoff["enabled"], bool):
                raise ValueError("mitigation.backoff.enabled must be true or false")
            _check_section("mitigation.backoff", {k: v for k, v in backoff.items() if k != "enabled"},
                           _BACKOFF_SCHEMA, len(eligible_sources),
                           base_timeout=config["mitigation_hard_timeout_s"])
    return config


def _merge(defaults, override):
    merged = copy.deepcopy(defaults)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def effective_config(config):
    """Return a validated deep copy with every optional section filled in."""
    validate_config(config)
    merged = _merge(DEFAULTS, config)
    # A partial backoff section may leave max_timeout_s below a large base timeout.
    backoff = merged["mitigation"]["backoff"]
    backoff["max_timeout_s"] = max(backoff["max_timeout_s"], merged["mitigation_hard_timeout_s"])
    return validate_config(merged)


def load_config(path=DEFAULT_CONFIG):
    """Load, validate and complete a configuration file with a useful error."""
    try:
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read detector configuration at {path}: {exc}") from exc
    return effective_config(config)


def apply_overrides(config, *, detector=None, action=None, backoff=None, rate_limit_pps=None):
    """Return an effective configuration with command-line choices applied."""
    result = effective_config(config)
    if detector is not None:
        result["detector"] = detector
    if action is not None:
        result["mitigation"]["action"] = action
    if backoff is not None:
        result["mitigation"]["backoff"]["enabled"] = bool(backoff)
    if rate_limit_pps is not None:
        result["mitigation"]["rate_limit_pps"] = rate_limit_pps
    return validate_config(result)


def config_digest(config):
    """Stable SHA-256 of the canonical JSON, recorded with each experiment."""
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
