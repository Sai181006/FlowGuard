import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from controller.config import (  # noqa: E402
    DEFAULT_CONFIG, DEFAULTS, apply_overrides, config_digest, effective_config, load_config,
    validate_config,
)


LEGACY = {
    "poll_interval_s": 1.0, "victim_pps": 100.0, "source_pps": 30.0, "min_sources": 2,
    "consecutive_windows": 2, "protected_sources": ["10.0.0.11"], "mitigation_hard_timeout_s": 10,
}


class ConfigTests(unittest.TestCase):
    def test_legacy_seven_key_config_is_still_valid_and_unchanged(self):
        config = copy.deepcopy(LEGACY)
        self.assertIs(validate_config(config), config)
        self.assertEqual(config, LEGACY)

    def test_effective_config_fills_defaults_matching_original_behaviour(self):
        config = effective_config(LEGACY)
        self.assertEqual(config["detector"], "threshold")
        self.assertEqual(config["mitigation"]["action"], "drop")
        self.assertFalse(config["mitigation"]["backoff"]["enabled"])
        self.assertEqual(effective_config(config), config)
        self.assertNotIn("detector", LEGACY)

    def test_shipped_config_and_every_preset_validate(self):
        files = [DEFAULT_CONFIG, *sorted((ROOT / "config" / "presets").glob("*.json"))]
        self.assertGreaterEqual(len(files), 6)
        for path in files:
            with self.subTest(path=path.name):
                raw = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(validate_config(raw), raw)
                load_config(path)
        self.assertEqual(load_config(DEFAULT_CONFIG)["detector"], "threshold")

    def test_partial_nested_sections_are_merged_with_defaults(self):
        config = effective_config({**LEGACY, "detectors": {"cusum": {"threshold_h": 8.0}},
                                   "mitigation": {"backoff": {"enabled": True}}})
        self.assertEqual(config["detectors"]["cusum"]["threshold_h"], 8.0)
        self.assertEqual(config["detectors"]["cusum"]["drift_k"], DEFAULTS["detectors"]["cusum"]["drift_k"])
        self.assertTrue(config["mitigation"]["backoff"]["enabled"])
        self.assertEqual(config["mitigation"]["backoff"]["factor"], 2.0)

    def test_invalid_values_and_unknown_keys_are_rejected(self):
        cases = [
            {"detector": "magic"},
            {"detectors": {"ewma": {"alpha": 0}}},
            {"detectors": {"ewma": {"alpha": 1.5}}},
            {"detectors": {"ewma": {"unknown": 1}}},
            {"detectors": {"bayes": {}}},
            {"detectors": {"cusum": {"threshold_h": 0}}},
            {"detectors": {"ewma": {"min_sources": 4}}},
            {"mitigation": {"action": "blackhole"}},
            {"mitigation": {"rate_limit_pps": 0}}, {"mitigation": {"rate_limit_pps": True}},
            {"mitigation": {"extra": 1}},
            {"mitigation": {"backoff": {"enabled": "yes"}}},
            {"mitigation": {"backoff": {"factor": 0.5}}},
            {"mitigation": {"backoff": {"max_timeout_s": 5}}},
            {"mitigation": {"backoff": {"max_timeout_s": 70000}}},
            {"surprise": True},
        ]
        for extra in cases:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                validate_config({**LEGACY, **extra})

    def test_overrides_and_digest(self):
        config = apply_overrides(LEGACY, detector="cusum", action="graduated", backoff=True,
                                 rate_limit_pps=50)
        self.assertEqual(config["detector"], "cusum")
        self.assertEqual(config["mitigation"]["action"], "graduated")
        self.assertTrue(config["mitigation"]["backoff"]["enabled"])
        self.assertEqual(config["mitigation"]["rate_limit_pps"], 50)
        self.assertEqual(config_digest(config), config_digest(copy.deepcopy(config)))
        self.assertNotEqual(config_digest(config), config_digest(effective_config(LEGACY)))
        with self.assertRaises(ValueError):
            apply_overrides(LEGACY, detector="nope")


if __name__ == "__main__":
    unittest.main()
