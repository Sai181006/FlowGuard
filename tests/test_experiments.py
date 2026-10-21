"""Native regressions for experiment output safety, validation and analysis."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from experiments import analyze, run_trial


class OutputDirectoryTests(unittest.TestCase):
    def test_existing_output_fails_before_opening_logs_or_starting_processes(self):
        with tempfile.TemporaryDirectory(dir=run_trial.ROOT / "results") as parent:
            output = Path(parent) / "already-used"
            output.mkdir()
            sentinel = output / "controller.log"
            sentinel.write_text("keep previous run", encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.object(run_trial.sys, "argv", [
                "run_trial.py", "--mode", "attack-on", "--output", str(output),
            ]), mock.patch.object(run_trial.subprocess, "Popen") as popen, \
                    mock.patch.object(run_trial, "Mininet") as mininet, \
                    contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    run_trial.main()
            stderr.seek(0)
            self.assertIn("output directory already exists; choose a fresh path", stderr.read())
            self.assertEqual(raised.exception.code, 2)
            popen.assert_not_called()
            mininet.assert_not_called()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep previous run")


class TrialValidationTests(unittest.TestCase):
    class Process:
        def __init__(self, returncode=None, running=False):
            self.returncode = returncode
            self.running = running

        def poll(self):
            return None if self.running else self.returncode

        def wait(self, timeout=None):
            self.running = False
            return self.returncode

        def terminate(self):
            self.running = False
            self.returncode = 0

        def kill(self):
            self.terminate()

    class Host:
        def __init__(self, name, probe_results):
            self.name = name
            self.probe_results = probe_results

        def popen(self, command, stdout=None, stderr=None):
            if "probe.py" in command[2]:
                count = int(command[command.index("--count") + 1])
                received = self.probe_results(self.name, count)
                stdout.write(",".join(run_trial.PROBE_COLUMNS) + "\n")
                for sequence in range(1, count + 1):
                    status = "ok" if sequence <= received else "timeout"
                    rtt = "1.250" if status == "ok" else ""
                    stdout.write(f"2026-10-20T00:00:00+00:00,{sequence},{status},{rtt}\n")
                return TrialValidationTests.Process(0 if received == count else 1)
            if "flood.py" in command[2]:
                stdout.write(json.dumps({"event": "start", "monotonic_s": 1.0}) + "\n")
                stdout.write(json.dumps({"event": "stop", "monotonic_s": 3.0}) + "\n")
                return TrialValidationTests.Process(0)
            return TrialValidationTests.Process(0, running=True)

    class Network:
        def __init__(self, probe_results, ping_loss=0):
            self.ping_loss = ping_loss
            self.hosts = {name: TrialValidationTests.Host(name, probe_results)
                          for name in ("victim", "client", "a1", "a2")}

        def addController(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def waitConnected(self, timeout=None):
            return True

        def pingAll(self):
            return self.ping_loss

        def get(self, name):
            return self.hosts[name]

        def stop(self):
            pass

    def _run_attack_on(self, client_received, recovery_received, prime_received=3, ping_loss=0):
        def probe_results(host, count):
            if count == 3:
                return prime_received
            if count == 20:
                return client_received
            if count == 10:
                return recovery_received
            raise AssertionError(f"unexpected probe count {count}")

        with tempfile.TemporaryDirectory(dir=run_trial.ROOT / "results") as parent:
            output = Path(parent) / "trial"
            network = self.Network(probe_results, ping_loss=ping_loss)
            controller = self.Process(0, running=True)
            failure = None
            with mock.patch.object(run_trial.sys, "argv", [
                "run_trial.py", "--mode", "attack-on", "--duration-s", "2",
                "--output", str(output),
            ]), mock.patch.object(run_trial.subprocess, "Popen", return_value=controller), \
                    mock.patch.object(run_trial, "Mininet", return_value=network), \
                    mock.patch.object(run_trial, "DDoSTopo", return_value=object()), \
                    mock.patch.object(run_trial.time, "sleep"), \
                    mock.patch.object(run_trial, "dump_flows",
                                      side_effect=lambda path: path.write_text("flows\n", encoding="utf-8")), \
                    mock.patch("builtins.print"):
                try:
                    exit_status = run_trial.main()
                except RuntimeError as exc:
                    exit_status = None
                    failure = str(exc)
            metadata = json.loads((output / "metadata.json").read_text(encoding="utf-8"))
        return exit_status, metadata, failure

    def test_probe_loss_remains_measurement_but_does_not_fail_trial_if_recovery_passes(self):
        exit_status, metadata, failure = self._run_attack_on(client_received=19, recovery_received=10)
        self.assertIsNone(failure)
        self.assertEqual(exit_status, 0)
        self.assertEqual(metadata["status"], "completed")
        self.assertEqual(metadata["execution_status"], "completed")
        self.assertEqual(metadata["validation"]["status"], "passed")
        self.assertEqual(metadata["measurements"]["client"], {
            "sent": 20, "received": 19, "loss_percent": 5.0, "process_exit": 1,
        })

    def test_recovery_loss_marks_validation_failed_after_execution_completes(self):
        exit_status, metadata, failure = self._run_attack_on(client_received=19, recovery_received=9)
        self.assertIsNone(failure)
        self.assertEqual(exit_status, 1)
        self.assertEqual(metadata["execution_status"], "completed")
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["validation"]["status"], "failed")
        self.assertEqual(metadata["measurements"]["recovery_client"]["received"], 9)
        self.assertEqual(metadata["validation"]["checks"]["recovery_probe"]["status"], "failed")

    def test_baseline_connectivity_failure_cannot_be_completed(self):
        exit_status, metadata, failure = self._run_attack_on(
            client_received=20, recovery_received=10, ping_loss=1,
        )
        self.assertIsNone(exit_status)
        self.assertEqual(failure, "baseline ping failed")
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["validation"]["checks"]["baseline_connectivity"]["status"], "failed")

    def test_prime_probe_failure_cannot_be_completed(self):
        exit_status, metadata, failure = self._run_attack_on(
            client_received=20, recovery_received=10, prime_received=2,
        )
        self.assertIsNone(exit_status)
        self.assertEqual(failure, "prime probe failed from client")
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["validation"]["checks"]["prime_client"]["status"], "failed")

    def test_probe_parser_rejects_truncated_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.csv"
            path.write_text("timestamp_utc,sequence,status,rtt_ms\n"
                            "2026-10-20T00:00:00+00:00,1,ok,1.0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contains 1 of 2 samples"):
                run_trial.probe_measurement(path, 2, 0)


class TrialAnalysisTests(unittest.TestCase):
    def test_repeat_artifact_is_summarized_as_two_independent_waves(self):
        summary = analyze.summarize_trial(run_trial.ROOT / "results" / "m5-repeat")
        self.assertEqual(summary["mode"], "mitigation-repeat")
        self.assertEqual(len(summary["waves"]), 2)
        wave1, wave2 = summary["waves"]
        self.assertLess(wave1["attack_start_monotonic_s"], wave2["attack_start_monotonic_s"])
        self.assertEqual(wave1["client"], {"sent": 80, "received": 80})
        self.assertEqual(wave2["client"], {"sent": 80, "received": 80})
        for wave in summary["waves"]:
            self.assertIsNotNone(wave["first_alert_latency_s"])
            self.assertEqual(wave["drop_rules_during_wave"], 2)
            self.assertEqual(wave["drop_rules_after_wave"], 0)
            self.assertEqual(len(wave["removed_after_attack_s"]), 2)
        self.assertEqual(summary["recovery_client"], {"sent": 10, "received": 10})

    def test_single_wave_comparison_matches_saved_summary_values(self):
        saved = json.loads((run_trial.ROOT / "results" / "m6-summary.json").read_text(encoding="utf-8"))
        current = analyze.compare(run_trial.ROOT / "results" / "m6-attack-off",
                                  run_trial.ROOT / "results" / "m6-attack-on")
        self.assertEqual(current, saved["matched_comparison"])

    def test_compare_rejects_repeat_and_mismatched_single_wave_trials(self):
        with self.assertRaisesRegex(ValueError, "matched single-wave"):
            analyze.compare(run_trial.ROOT / "results" / "m5-repeat",
                            run_trial.ROOT / "results" / "m6-attack-on")
        with tempfile.TemporaryDirectory() as directory:
            off = Path(directory) / "off"
            on = Path(directory) / "on"
            off.mkdir()
            on.mkdir()
            common = {"duration_s": 8, "config": {"threshold": 1},
                      "ping_loss_percent": 0.0, "status": "completed",
                      "execution_status": "completed", "validation": {"status": "passed"}}
            (off / "metadata.json").write_text(json.dumps({
                **common, "mode": "attack-off", "mitigation_enabled": False,
                "pps_per_attacker": 600,
            }), encoding="utf-8")
            (on / "metadata.json").write_text(json.dumps({
                **common, "mode": "attack-on", "mitigation_enabled": True,
                "pps_per_attacker": 700,
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must match pps_per_attacker"):
                analyze.compare(off, on)


if __name__ == "__main__":
    unittest.main()
