"""Native regressions for experiment output safety, validation and analysis."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from experiments import analyze, demo, render_availability_png, run_trial


# `tc -s -j qdisc show dev s1-eth1` (iproute2 6.x) for Mininet's TCLink tree:
# htb 5: root (rate class 5:1) with a netem 10: leaf limited to 50 packets.
TC_HTB_NETEM_JSON = (
    '[{"kind":"htb","handle":"5:","root":true,"refcnt":2,"options":{"r2q":10,"default":"0x1",'
    '"direct_packets_stat":0,"direct_qlen":1000},"bytes":1395330,"packets":8208,"drops":15302,'
    '"overlimits":21544,"requeues":0,"backlog":8500,"qlen":50},'
    '{"kind":"netem","handle":"10:","parent":"5:1","options":{"limit":50,"seed":1234567890123,'
    '"ecn":false,"gap":0},"bytes":1395330,"packets":8208,"drops":15302,"overlimits":0,'
    '"requeues":0,"backlog":8500,"qlen":50}]\n'
)
TC_NOQUEUE_JSON = ('[{"kind":"noqueue","handle":"0:","root":true,"refcnt":2,"options":{},"bytes":0,'
                   '"packets":0,"drops":0,"overlimits":0,"requeues":0,"backlog":0,"qlen":0}]\n')


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
        def __init__(self, name, probe_results, network):
            self.name = name
            self.probe_results = probe_results
            self.network = network

        def popen(self, command, stdout=None, stderr=None):
            self.network.commands.append((self.name, list(command)))
            if "probe.py" in command[2]:
                count = int(command[command.index("--count") + 1])
                received = self.probe_results(self.name, count)
                stdout.write(",".join(run_trial.PROBE_COLUMNS) + "\n")
                for sequence in range(1, count + 1):
                    status = "ok" if sequence <= received else "timeout"
                    rtt = "1.250" if status == "ok" else ""
                    stdout.write(f"2026-10-20T00:00:00+00:00,{sequence},{status},{rtt}\n")
                # The real probe writes this summary to stderr, which run_trial
                # redirects into the same CSV file.
                stdout.write(f"sent={count} received={received} "
                             f"loss={100 * (count - received) / count:.1f}%\n")
                return TrialValidationTests.Process(0 if received == count else 1)
            if "flood.py" in command[2]:
                stdout.write(json.dumps({"event": "start", "monotonic_s": 1.0}) + "\n")
                stdout.write(json.dumps({"event": "stop", "monotonic_s": 3.0}) + "\n")
                return TrialValidationTests.Process(1 if self.network.flood_fails else 0)
            return TrialValidationTests.Process(0, running=True)

    class Network:
        def __init__(self, probe_results, ping_loss=0, flood_fails=False):
            self.ping_loss = ping_loss
            self.flood_fails = flood_fails
            self.commands = []
            self.ping_called = False
            self.hosts = {name: TrialValidationTests.Host(name, probe_results, self)
                          for name in ("victim", "client", "a1", "a2")}

        def addController(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def waitConnected(self, timeout=None):
            return True

        def pingAll(self):
            self.ping_called = True
            return self.ping_loss

        def get(self, name):
            return self.hosts[name]

        def stop(self):
            pass

    class Capture:
        instances = []

        def __init__(self, path, interfaces):
            self.path = Path(path)
            self.stop_calls = 0
            self.active = False
            TrialValidationTests.Capture.instances.append(self)

        def start(self):
            self.active = True
            self.path.write_bytes(b"pcapng")
            return self

        def stop(self):
            self.stop_calls += 1
            self.active = False
            return {"file": self.path.name, "interfaces": {}, "packets_seen": {}, "truncated": False,
                    "bytes": 6}

    def _run_attack_on(self, client_received, recovery_received, prime_received=3, ping_loss=0,
                       extra_args=(), tc_output=TC_HTB_NETEM_JSON, flood_fails=False, inspect=None):
        def probe_results(host, count):
            if count == 3:
                return prime_received
            if count == 20:
                return client_received
            if count == 10:
                return recovery_received
            raise AssertionError(f"unexpected probe count {count}")

        def fake_check_output(command, **kwargs):
            if command[0] != "tc":
                raise AssertionError(f"unexpected command {command}")
            return tc_output

        self.Capture.instances = []
        with tempfile.TemporaryDirectory(dir=run_trial.ROOT / "results") as parent:
            output = Path(parent) / "trial"
            network = self.Network(probe_results, ping_loss=ping_loss, flood_fails=flood_fails)
            controller = self.Process(0, running=True)
            failure = None
            with mock.patch.object(run_trial.sys, "argv", [
                "run_trial.py", "--mode", "attack-on", "--duration-s", "2",
                "--output", str(output), *extra_args,
            ]), mock.patch.object(run_trial.subprocess, "Popen", return_value=controller), \
                    mock.patch.object(run_trial.subprocess, "check_output",
                                      side_effect=fake_check_output) as check_output, \
                    mock.patch.object(run_trial, "Mininet", return_value=network), \
                    mock.patch.object(run_trial, "DDoSTopo", return_value=object()) as topo, \
                    mock.patch.object(run_trial, "PacketCapture", self.Capture), \
                    mock.patch.object(run_trial, "switch_ports", return_value={"victim-received": "s1-eth1"}), \
                    mock.patch.object(run_trial, "QDISC_INTERVAL_S", 0.01), \
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
            if inspect is not None:
                inspect(output=output, network=network, topo=topo, check_output=check_output)
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

    def test_probe_parser_ignores_trailing_summary_lines_from_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.csv"
            path.write_text("timestamp_utc,sequence,status,rtt_ms\n"
                            "2026-10-20T00:00:00+00:00,1,ok,1.0\n"
                            "2026-10-20T00:00:00+00:00,2,timeout,\n"
                            "sent=2 received=1 loss=50.0%\n"
                            "metrics p50=1.000 p95=1.000 p99=1.000 jitter=0.000\n", encoding="utf-8")
            measurement = run_trial.probe_measurement(path, 2, 1)
            self.assertEqual(measurement["received"], 1)
            path.write_text("timestamp_utc,sequence,status,rtt_ms\n"
                            "2026-10-20T00:00:00+00:00,1,ok,1.0\n"
                            "unexpected,row,here,\n"
                            "sent=1 received=1 loss=0.0%\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contains 2 of 1 samples"):
                run_trial.probe_measurement(path, 1, 0)


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

    def assertSavedKeysUnchanged(self, saved, current, where="summary"):
        """Every key of the saved result is still produced with the same value."""
        if isinstance(saved, dict):
            self.assertIsInstance(current, dict, where)
            for key, value in saved.items():
                self.assertIn(key, current, f"{where}.{key}")
                self.assertSavedKeysUnchanged(value, current[key], f"{where}.{key}")
        else:
            self.assertEqual(current, saved, where)

    def test_single_wave_comparison_matches_saved_summary_values(self):
        saved = json.loads((run_trial.ROOT / "results" / "m6-summary.json").read_text(encoding="utf-8"))
        current = analyze.compare(run_trial.ROOT / "results" / "m6-attack-off",
                                  run_trial.ROOT / "results" / "m6-attack-on")
        self.assertSavedKeysUnchanged(saved["matched_comparison"], current, "matched_comparison")
        self.assertSavedKeysUnchanged(saved["baseline"],
                                      analyze.summarize_trial(run_trial.ROOT / "results" / "m4-baseline"))
        # The recorded unshaped M6 pair had no client loss in either mode.
        self.assertEqual(current["availability"]["loss_reduction_points"], 0.0)
        self.assertFalse(current["availability"]["improved"])
        self.assertIsNone(current["availability"]["off_qdisc_drops"])

    def test_recorded_trials_keep_every_original_summary_value(self):
        # SHA-256 of summarize_trial() as produced before the WP6 additions.
        expected = {
            "m4-baseline": "18ed3eaad81f3dfbb015ecdcd0aeb050f33aa98cf94d421ebd4777b481a38261",
            "m4-detection": "74c89924b3dd9704967fc6715e6d75b089ec4221cf1ccd37be162f2d8d0a4f1b",
            "m5-mitigation": "22018d518f794d95b298d7026913d881980c79ba13d4a5829d85dd8e26847684",
            "m5-repeat": "24c350e34e3c4651cb594a975f7e76c398659d34ac3e438d513c111917e77b02",
            "m6-attack-off": "5f5157cf49c9bf6e00cea991f3f3e4a9ebede5a224cab932307144766bee3392",
            "m6-attack-on": "7df3f6f052c4d6ba8cd80996e0da17f712dad2f07eb8fa7d7fe18d41fe26a2fc",
            "m6-high-off": "2ddc6913de5ccba2f34854a222ced775c24ae09cd37393ba21459ba1a8ace411",
        }
        added = {"bottleneck", "client_metrics", "detector", "meter_band_drops", "qdisc",
                 "ratelimit_confirmations", "ratelimit_fallbacks", "ratelimit_requests"}
        for trial, digest in expected.items():
            summary = analyze.summarize_trial(run_trial.ROOT / "results" / trial)
            original = {key: value for key, value in summary.items() if key not in added}
            self.assertEqual(hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest(),
                             digest, trial)
            self.assertEqual(summary["detector"], "threshold")
            self.assertEqual(summary["ratelimit_requests"], 0)
            self.assertIsNone(summary["qdisc"])
        metrics = analyze.summarize_trial(run_trial.ROOT / "results" / "m6-attack-off")["client_metrics"]
        self.assertEqual((metrics["sent"], metrics["received"], metrics["loss_percent"]), (80, 80, 0.0))
        self.assertEqual(metrics["source"], "client.csv")

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


class BottleneckTrialTests(TrialValidationTests):
    """run_trial.py with --bottleneck-mbit, effective config and probe metrics."""

    BOTTLENECK = ("--bottleneck-mbit", "0.5")

    def test_default_trial_keeps_unshaped_topology_and_records_effective_config(self):
        seen = {}

        def inspect(output, network, topo, check_output):
            seen["topo_calls"] = topo.call_args_list
            seen["tc_calls"] = check_output.call_count
            seen["files"] = sorted(path.name for path in output.iterdir())
            seen["effective"] = json.loads((output / "effective-config.json").read_text(encoding="utf-8"))
            seen["probes"] = [command for _, command in network.commands if "probe.py" in command[2]]

        exit_status, metadata, failure = self._run_attack_on(20, 10, inspect=inspect)
        self.assertIsNone(failure)
        self.assertEqual(exit_status, 0)
        self.assertEqual(seen["topo_calls"], [mock.call()])
        self.assertEqual(seen["tc_calls"], 0)
        self.assertNotIn("qdisc-config.json", seen["files"])
        self.assertIsNone(metadata["bottleneck"])
        self.assertEqual(metadata["config"], seen["effective"])
        self.assertEqual(metadata["config"]["detector"], "threshold")
        self.assertEqual(metadata["config_digest"], run_trial.config_digest(seen["effective"]))
        self.assertEqual(metadata["config_source"], "config/detector.json")
        self.assertNotIn("bottleneck_qdisc", metadata["validation"]["checks"])
        self.assertEqual(len(seen["probes"]), 5)  # three primes, client, recovery
        for command in seen["probes"]:
            self.assertEqual(command[command.index("--format") + 1], "binary")
            metrics = command[command.index("--metrics-json") + 1]
            self.assertTrue(metrics.endswith(".metrics.json"))
        client = next(command for command in seen["probes"] if command[command.index("--count") + 1] == "20")
        self.assertEqual(Path(client[client.index("--metrics-json") + 1]).name, "client.metrics.json")

    def test_bottleneck_builds_tclink_topology_checks_and_monitors_qdisc(self):
        seen = {}

        def inspect(output, network, topo, check_output):
            seen["topo_calls"] = topo.call_args_list
            seen["config"] = json.loads((output / "qdisc-config.json").read_text(encoding="utf-8"))
            seen["after"] = json.loads((output / "qdisc-after.json").read_text(encoding="utf-8"))
            seen["samples"] = analyze.jsonl(output / "qdisc.jsonl")
            seen["tc_commands"] = [call.args[0] for call in check_output.call_args_list]

        exit_status, metadata, failure = self._run_attack_on(
            12, 10, extra_args=(*self.BOTTLENECK, "--detector", "ewma", "--probe-format", "text"),
            inspect=inspect)
        self.assertIsNone(failure)
        self.assertEqual(exit_status, 0)
        self.assertEqual(seen["topo_calls"], [mock.call(bottleneck={"mbit": 0.5, "queue_packets": 50,
                                                                    "red": False})])
        self.assertEqual(metadata["bottleneck"], {"device": "s1-eth1", "mbit": 0.5,
                                                  "queue_packets": 50, "qdisc": "fifo"})
        self.assertEqual(metadata["config"]["detector"], "ewma")
        self.assertEqual(metadata["probe_format"], "text")
        self.assertEqual(metadata["validation"]["checks"]["bottleneck_qdisc"]["status"], "passed")
        self.assertEqual(metadata["validation"]["checks"]["bottleneck_qdisc_after"]["status"], "passed")
        self.assertEqual(metadata["validation"]["status"], "passed")
        self.assertEqual([entry["kind"] for entry in seen["config"]["qdiscs"]], ["htb", "netem"])
        self.assertEqual(seen["after"]["problems"], [])
        self.assertTrue(all(command == ["tc", "-s", "-j", "qdisc", "show", "dev", "s1-eth1"]
                            for command in seen["tc_commands"]))
        self.assertGreaterEqual(len(seen["samples"]), 1)
        self.assertEqual(seen["samples"][0]["qdiscs"][0]["drops"], 15302)
        self.assertEqual(metadata["qdisc_monitor"]["dev"], "s1-eth1")

    def test_missing_htb_fails_before_connectivity_or_traffic(self):
        seen = {}

        def inspect(output, network, topo, check_output):
            seen["ping_called"] = network.ping_called
            seen["commands"] = network.commands
            seen["config"] = json.loads((output / "qdisc-config.json").read_text(encoding="utf-8"))

        exit_status, metadata, failure = self._run_attack_on(
            20, 10, extra_args=self.BOTTLENECK, tc_output=TC_NOQUEUE_JSON, inspect=inspect)
        self.assertIsNone(exit_status)
        self.assertIn("bottleneck requested but s1-eth1 is not shaped", failure)
        self.assertIn("root qdisc is noqueue, expected htb", failure)
        self.assertFalse(seen["ping_called"])
        self.assertEqual(seen["commands"], [])
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["validation"]["checks"]["bottleneck_qdisc"]["status"], "failed")
        self.assertEqual(seen["config"]["problems"][0], "root qdisc is noqueue, expected htb")

    def test_red_request_requires_a_red_qdisc(self):
        exit_status, metadata, failure = self._run_attack_on(
            20, 10, extra_args=(*self.BOTTLENECK, "--qdisc", "red", "--queue-packets", "50"))
        self.assertIsNone(exit_status)
        self.assertIn("red qdisc requested but not installed", failure)

    def test_queue_limit_must_match_netem(self):
        exit_status, metadata, failure = self._run_attack_on(
            20, 10, extra_args=(*self.BOTTLENECK, "--queue-packets", "80"))
        self.assertIsNone(exit_status)
        self.assertIn("netem limit is 50, expected 80", failure)

    def test_pcap_capture_is_stopped_exactly_once(self):
        exit_status, metadata, failure = self._run_attack_on(20, 10, extra_args=("--pcap",))
        self.assertIsNone(failure)
        self.assertEqual(len(self.Capture.instances), 1)
        self.assertEqual(self.Capture.instances[0].stop_calls, 1)
        self.assertEqual(metadata["packet_capture"]["file"], "flowguard.pcapng")

    def test_pcap_capture_is_stopped_exactly_once_after_an_error(self):
        exit_status, metadata, failure = self._run_attack_on(
            20, 10, extra_args=("--pcap", *self.BOTTLENECK), flood_fails=True)
        self.assertEqual(failure, "flood process failed: a1")
        self.assertEqual(len(self.Capture.instances), 1)
        self.assertEqual(self.Capture.instances[0].stop_calls, 1)
        self.assertEqual(metadata["status"], "failed")
        self.assertIn("qdisc_monitor", metadata)  # the monitor thread was stopped too

    def _parse_error(self, *extra):
        with tempfile.TemporaryDirectory(dir=run_trial.ROOT / "results") as parent:
            output = Path(parent) / "trial"
            stderr = io.StringIO()
            with mock.patch.object(run_trial.sys, "argv", [
                "run_trial.py", "--mode", "attack-on", "--output", str(output), *extra,
            ]), mock.patch.object(run_trial.subprocess, "Popen") as popen, \
                    mock.patch.object(run_trial, "Mininet") as mininet, \
                    contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    run_trial.main()
            self.assertEqual(raised.exception.code, 2)
            popen.assert_not_called()
            mininet.assert_not_called()
            self.assertFalse(output.exists())
        return stderr.getvalue()

    def test_invalid_bottleneck_and_config_arguments_fail_before_starting(self):
        self.assertIn("require --bottleneck-mbit", self._parse_error("--queue-packets", "50"))
        self.assertIn("require --bottleneck-mbit", self._parse_error("--qdisc", "red"))
        self.assertIn("bottleneck-mbit must be 0.05..100", self._parse_error("--bottleneck-mbit", "200"))
        self.assertIn("bottleneck-mbit must be 0.05..100", self._parse_error("--bottleneck-mbit", "nan"))
        self.assertIn("queue-packets must be 5..1000",
                      self._parse_error("--bottleneck-mbit", "1", "--queue-packets", "4"))
        self.assertIn("config must be inside this repository", self._parse_error("--config", "/etc/hosts"))
        self.assertIn("cannot read detector configuration",
                      self._parse_error("--config", str(run_trial.ROOT / "missing-config.json")))


def write_trial(path, mode, client_ok, bottleneck=None, qdisc_drops=None, metrics_json=False,
                omit_bottleneck=False):
    """Create the minimum raw files summarize_trial/compare read for one trial."""
    path.mkdir()
    mitigation = mode == "attack-on"
    meta = {"mode": mode, "status": "completed", "execution_status": "completed",
            "validation": {"status": "passed"}, "mitigation_enabled": mitigation,
            "pps_per_attacker": 600, "duration_s": 8, "config": {"detector": "threshold"},
            "ping_loss_percent": 0.0, "attack_end_monotonic_s": 9.0}
    if not omit_bottleneck:
        meta["bottleneck"] = bottleneck
    (path / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    events = [{"type": "sample", "monotonic_s": 1.5}, {"type": "alert", "monotonic_s": 2.0,
                                                         "sources": {"10.0.0.21": 600}}]
    if mitigation:
        events += [{"type": "drop_requested", "monotonic_s": 2.1, "offense_count": 1},
                   {"type": "drop_confirmed", "monotonic_s": 2.5, "sources": ["10.0.0.21"]},
                   {"type": "ratelimit_failed", "monotonic_s": 2.2, "fallback": "drop"},
                   {"type": "meter_sample", "monotonic_s": 3.0, "band_drop_delta": {"10.0.0.22": 40}},
                   {"type": "meter_sample", "monotonic_s": 4.0, "band_drop_delta": 2},
                   {"type": "drop_removed", "monotonic_s": 12.5, "packets": 100}]
    (path / "controller.jsonl").write_text("".join(json.dumps(row) + "\n" for row in events),
                                           encoding="utf-8")
    for name in ("a1", "a2"):
        (path / f"attack-{name}.jsonl").write_text(
            json.dumps({"event": "start", "monotonic_s": 1.0}) + "\n"
            + json.dumps({"event": "stop", "monotonic_s": 9.0}) + "\n", encoding="utf-8")
    rate = 180 if not mitigation else 0
    (path / "victim.jsonl").write_text("".join(
        json.dumps({"window_start_s": 1.0 + second, "elapsed_s": 1.0,
                    "by_source": {"10.0.0.21": rate, "10.0.0.22": rate, "10.0.0.11": 10}}) + "\n"
        for second in range(8)), encoding="utf-8")
    rows = ["timestamp_utc,sequence,status,rtt_ms"]
    for sequence in range(1, 81):
        ok = sequence <= client_ok
        rows.append(f"2026-10-21T00:00:00+00:00,{sequence},{'ok' if ok else 'timeout'},"
                    f"{(100.0 + sequence) if ok else ''}")
    rows.append(f"sent=80 received={client_ok} loss={100 * (80 - client_ok) / 80:.1f}%")
    (path / "client.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    if metrics_json:
        (path / "client.metrics.json").write_text(json.dumps({
            "format": "binary", "sent": 80, "received": client_ok,
            "loss_percent": 100 * (80 - client_ok) / 80, "rtt_ms": {"p95": 42.0}}), encoding="utf-8")
    (path / "recovery-client.csv").write_text(
        "timestamp_utc,sequence,status,rtt_ms\n" + "".join(
            f"2026-10-21T00:00:00+00:00,{sequence},ok,1.0\n" for sequence in range(1, 11)),
        encoding="utf-8")
    (path / "flows-after-recovery.txt").write_text(
        " cookie=0xdd05000000000006, priority=200,udp actions=meter:1\n", encoding="utf-8")
    if qdisc_drops is not None:
        samples = []
        for index, (drops, backlog) in enumerate(((100, 0), (100 + qdisc_drops // 2, 8500),
                                                  (100 + qdisc_drops, 1700))):
            samples.append({"monotonic_s": 1.0 + index, "time_utc": "t", "dev": "s1-eth1", "qdiscs": [
                {"kind": "htb", "handle": "5:", "parent": "root", "packets": 10 * index, "bytes": 0,
                 "drops": drops, "overlimits": 0, "requeues": 0, "backlog_bytes": backlog,
                 "qlen": backlog // 170},
                {"kind": "netem", "handle": "10:", "parent": "5:1", "packets": 0, "bytes": 0,
                 "drops": drops, "overlimits": 0, "requeues": 0, "backlog_bytes": backlog,
                 "qlen": backlog // 170, "limit": 50}]})
        samples.append({"monotonic_s": 4.0, "time_utc": "t", "dev": "s1-eth1", "qdiscs": [],
                        "error": "CalledProcessError: tc failed"})
        (path / "qdisc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in samples),
                                          encoding="utf-8")
    return path


BOTTLENECK_META = {"device": "s1-eth1", "mbit": 0.5, "queue_packets": 50, "qdisc": "fifo"}


class AvailabilityComparisonTests(unittest.TestCase):
    def test_compare_computes_availability_under_a_matched_bottleneck(self):
        with tempfile.TemporaryDirectory() as directory:
            off = write_trial(Path(directory) / "off", "attack-off", 24, BOTTLENECK_META, qdisc_drops=9000)
            on = write_trial(Path(directory) / "on", "attack-on", 64, BOTTLENECK_META, qdisc_drops=2000)
            result = analyze.compare(off, on)
        table = result["availability"]
        self.assertEqual(table["off_client_loss_percent"], 70.0)
        self.assertEqual(table["on_client_loss_percent"], 20.0)
        self.assertEqual(table["loss_reduction_points"], 50.0)
        self.assertTrue(table["improved"])
        self.assertEqual(table["off_rtt_p95_ms"], 123.0)  # nearest-rank p95 of 101..124
        self.assertEqual(table["off_qdisc_drops"], 9000)
        self.assertEqual(table["on_qdisc_drops"], 2000)
        on_summary = result["attack_on"]
        self.assertEqual(on_summary["ratelimit_fallbacks"], 1)
        self.assertEqual(on_summary["meter_band_drops"], 42)
        self.assertEqual(on_summary["drop_rules_after_recovery"], 1)  # cookie ...06 counts
        self.assertEqual(on_summary["qdisc"]["max_backlog_bytes"], 8500)
        self.assertEqual(on_summary["qdisc"]["max_qlen"], 50)
        self.assertEqual(on_summary["qdisc"]["errors"], 1)
        self.assertEqual(on_summary["bottleneck"], BOTTLENECK_META)
        self.assertEqual(result["unmitigated_attacker_pps"], 360.0)
        self.assertEqual(result["mitigated_attacker_pps"], 0.0)

    def test_small_loss_reduction_is_not_reported_as_improvement(self):
        with tempfile.TemporaryDirectory() as directory:
            off = write_trial(Path(directory) / "off", "attack-off", 72, BOTTLENECK_META)
            on = write_trial(Path(directory) / "on", "attack-on", 76, BOTTLENECK_META, metrics_json=True)
            result = analyze.compare(off, on)
        self.assertEqual(result["availability"]["loss_reduction_points"], 5.0)
        self.assertFalse(result["availability"]["improved"])
        self.assertIsNone(result["availability"]["off_qdisc_drops"])
        self.assertEqual(result["attack_on"]["client_metrics"]["source"], "client.metrics.json")
        self.assertEqual(result["availability"]["on_rtt_p95_ms"], 42.0)

    def test_compare_rejects_mismatched_bottleneck_but_accepts_absent_and_none(self):
        with tempfile.TemporaryDirectory() as directory:
            off = write_trial(Path(directory) / "off", "attack-off", 80, None)
            on = write_trial(Path(directory) / "on", "attack-on", 80, BOTTLENECK_META)
            with self.assertRaisesRegex(ValueError, "must match bottleneck"):
                analyze.compare(off, on)
            older = write_trial(Path(directory) / "older", "attack-off", 80, omit_bottleneck=True)
            plain = write_trial(Path(directory) / "plain", "attack-on", 80, None)
            self.assertFalse(analyze.compare(older, plain)["availability"]["improved"])
            other = write_trial(Path(directory) / "other", "attack-off", 80,
                                {**BOTTLENECK_META, "queue_packets": 100})
            with self.assertRaisesRegex(ValueError, "must match bottleneck"):
                analyze.compare(other, on)

    def test_availability_chart_panels_and_png(self):
        with tempfile.TemporaryDirectory() as directory:
            off = write_trial(Path(directory) / "off", "attack-off", 24, BOTTLENECK_META, qdisc_drops=9000)
            on = write_trial(Path(directory) / "on", "attack-on", 64, BOTTLENECK_META, qdisc_drops=2000)
            comparison = analyze.compare(off, on)
            panels = render_availability_png.availability_panels(comparison)
            self.assertEqual([panel[0] for panel in panels],
                             ["Client probe loss", "Client RTT p95", "Mean queue backlog"])
            self.assertEqual(panels[0][2:], (70.0, 20.0))
            if render_availability_png.Image is None:
                self.skipTest("Pillow is not installed")
            image = Path(directory) / "chart.png"
            render_availability_png.render(comparison, image)
            self.assertEqual(image.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")


class DemoTimelineTests(unittest.TestCase):
    @staticmethod
    def _show(event, **state):
        base = {"flood_seen": True, "first_high_seen": True, "block_seen": False,
                "post_block_seen": False, "victim_threshold": 100, "source_threshold": 30,
                "min_sources": 2}
        base.update(state)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            demo.show_event(event, base)
        return stdout.getvalue()

    def test_new_mitigation_events_are_narrated(self):
        self.assertIn("RATE-LIMIT request meter for 10.0.0.21", self._show(
            {"type": "ratelimit_requested", "source": "10.0.0.21", "victim": "10.0.0.10",
             "port": 9000, "rate_pps": 20, "hard_timeout_s": 10}))
        self.assertIn("RATE-LIMIT OpenFlow barrier confirms meter rules for 10.0.0.21, 10.0.0.22",
                      self._show({"type": "ratelimit_confirmed", "sources": ["10.0.0.21", "10.0.0.22"]}))
        self.assertIn("METER-FALLBACK", self._show({"type": "ratelimit_failed", "source": "10.0.0.21",
                                                    "fallback": "drop"}))
        self.assertIn("meter bands dropped 40 packets above", self._show(
            {"type": "meter_sample", "band_drop_delta": {"10.0.0.21": 25, "10.0.0.22": 15}}))
        self.assertIn("meter bands dropped 7 packets for 10.0.0.22", self._show(
            {"type": "meter_sample", "meter_id": 2, "source": "10.0.0.22", "band_drop_delta": 7}))
        self.assertIn("METER-FALLBACK meter for 10.0.0.21, 10.0.0.22 failed (meter_unsupported)",
                      self._show({"type": "ratelimit_failed", "sources": ["10.0.0.21", "10.0.0.22"],
                                  "fallback": "drop", "reason": "meter_unsupported"}))
        self.assertEqual(self._show({"type": "meter_sample", "band_drop_delta": {}}), "")
        backoff = self._show({"type": "drop_requested", "source": "10.0.0.21", "victim": "10.0.0.10",
                              "port": 9000, "hard_timeout_s": 20, "offense_count": 2})
        self.assertIn("RULE    request UDP drop 10.0.0.21 -> 10.0.0.10:9000 for 20 s", backoff)
        self.assertIn("BACKOFF offense 2 for 10.0.0.21: timeout raised to 20 s", backoff)
        first = self._show({"type": "drop_requested", "source": "10.0.0.21", "victim": "10.0.0.10",
                            "port": 9000, "hard_timeout_s": 10, "offense_count": 1})
        self.assertNotIn("BACKOFF", first)

    def test_alert_wording_depends_on_mitigation(self):
        alert = {"type": "alert", "victim": "10.0.0.10", "victim_pps": 1200,
                 "sources": {"10.0.0.21": 600, "10.0.0.22": 600}}
        self.assertIn("the client is protected", self._show(alert))
        self.assertIn("Mitigation is off", self._show(alert, mitigation=False))

    def test_trial_command_passes_new_flags_only_when_given(self):
        plain = SimpleNamespace(pps=600, duration_s=8, pcap=False, bottleneck=False, detector=None,
                                mitigation_action=None, backoff=None)
        command = demo.trial_command(Path("/x/out"), "attack-on", plain)
        self.assertEqual(command[3:], ["--mode", "attack-on", "--output", "/x/out", "--pps", "600",
                                       "--duration-s", "8"])
        full = SimpleNamespace(pps=600, duration_s=8, pcap=True, bottleneck=True, detector="cusum",
                               mitigation_action="graduated", backoff=False)
        command = demo.trial_command(Path("/x/off"), "attack-off", full)
        self.assertEqual(command[command.index("--bottleneck-mbit") + 1], "0.5")
        self.assertEqual(command[command.index("--queue-packets") + 1], "50")
        self.assertIn("--pcap", command)
        self.assertIn("--no-backoff", command)
        self.assertEqual(command[command.index("--detector") + 1], "cusum")
        self.assertEqual(command[command.index("--mitigation-action") + 1], "graduated")

    def test_run_live_lets_run_trial_create_the_folder_and_keeps_the_runner_log(self):
        class Runner:
            def __init__(self, command, cwd=None, stdout=None, stderr=None):
                output = Path(command[command.index("--output") + 1])
                output.mkdir()  # run_trial.py refuses an existing folder
                stdout.write("*** Results: 0% dropped (20/20 received)\n")
                stdout.flush()
                self.returncode = 0

            def poll(self):
                return self.returncode

        args = SimpleNamespace(pps=600, duration_s=8, pcap=False, bottleneck=False, detector=None,
                               mitigation_action=None, backoff=None)
        config = {"victim_pps": 100, "source_pps": 30, "min_sources": 2}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "demo-run"
            with mock.patch.object(demo.subprocess, "Popen", Runner), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(demo.run_live(output, "attack-on", args, config), 0)
            self.assertIn("20/20 received", (output / "demo-runner.log").read_text(encoding="utf-8"))
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["demo-run"])

    def test_availability_interpretation_requires_measured_improvement(self):
        with tempfile.TemporaryDirectory() as directory:
            off = write_trial(Path(directory) / "off", "attack-off", 24, BOTTLENECK_META, qdisc_drops=9000)
            on = write_trial(Path(directory) / "on", "attack-on", 64, BOTTLENECK_META, qdisc_drops=2000)
            flat_off = write_trial(Path(directory) / "flat-off", "attack-off", 80, None)
            flat_on = write_trial(Path(directory) / "flat-on", "attack-on", 80, None)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                demo.show_availability(off, on)
            self.assertIn("availability improvement measured", stdout.getvalue())
            self.assertIn("70.0%", stdout.getvalue())
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                demo.show_availability(flat_off, flat_on)
            self.assertNotIn("availability improvement measured", stdout.getvalue())
            self.assertIn("no availability improvement was measured", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
