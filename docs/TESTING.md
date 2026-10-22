# FlowGuard testing and verification

This page lists every automated test, how to run each subset, how to set up
a Linux lab for the live Mininet/OVS trials, and — most importantly for a
viva — exactly **what has and has not been verified** on this branch.

## 1. Test inventory

All tests live in [`tests/`](../tests/) and use the standard-library
`unittest` runner. `tests/` is not a package: run them with
`python3 -m unittest discover -s tests` from the repository root.

| Test file | Tests | What it checks | Needs |
|---|---:|---|---|
| `test_detection.py` | 4 | `CounterTracker` rates, counter resets, per-destination aggregation; original two-window detector; protected client never counts as a source | stdlib |
| `test_detectors.py` | 19 | EWMA / CUSUM / entropy behaviour on quiet, burst, sustained, low-rate, pulsing and flash-crowd inputs; baseline freezing; counter-reset handling; the numbers quoted in the docstrings (CUSUM 3.5/7.0, KL 1.73 bits) | stdlib |
| `test_config.py` | 6 | Legacy 7-key config unchanged; defaults; every preset validates; partial sections merge; invalid values/unknown keys rejected; overrides and digest | stdlib |
| `test_mitigation_primitives.py` | 10 | `TokenBucket`, `OffenderHistory` back-off and memory, `choose_action` | stdlib |
| `test_queueing.py` | 12 | D/1 FIFO order and departures, tail drop, delay behind backlog, idle restart, stall catch-up cap, RED thresholds and seeding, RED idle decay, `FluidQueue` | stdlib |
| `test_scenarios.py` | 9 | Original six scenarios match the dashboard engine second by second; pulsing, ramp, flash crowd, three-source, repeat-offender shapes; seeded Poisson noise | stdlib |
| `test_benchmark.py` | 8 | Same seed ⇒ identical JSON; committed benchmark is current; latency frame; detector separation claims; ROC sweep | stdlib |
| `test_probe_protocol.py` | 14 | FGPB layout, round trip, CRC single-bit failure, `describe()`, nearest-rank percentiles, RFC 3550 jitter, loss/late/duplicate/reorder | stdlib |
| `test_probe_cli.py` | 7 | `probe.py` text/binary × stopwait/stream against a real localhost echo; timeouts; late and duplicate classification; `flood.py` formats; argument validation | stdlib (real UDP on 127.0.0.1) |
| `test_live_lab.py` | 15 | Native gateway: real-socket forward/echo/drop, unknown source port rejected, rate limit and graduated/back-off, queue path, phase schedule with waves and warm-up, per-phase probe metrics, CLI validation | stdlib (real UDP on 127.0.0.1) |
| `test_qdisc_monitor.py` | 5 | `tc -s -j qdisc show` parsing for an HTB/netem tree, edge cases, sampling survives `tc` errors | stdlib (mocked `tc`) |
| `test_wireshark_dissector.py` | 4 | Lua dissector compiles and decodes FGPB, bad CRC, legacy text, Mininet flood, native payloads, non-lab packets — against a **mock** Wireshark API, and one test with real `tshark` (passes with TShark 4.2.2) | `texlua`/`lua` for 3 tests; `tshark` for 1 |
| `test_demo_engine.py` | 22 | Dashboard model determinism, two-window behaviour, TTL expiry, blind spots, recorded data preservation, static asset and CSRF/Origin/Host protections | stdlib |
| `test_forwarding.py` | 45 | Controller with a mock datapath and the **real OS-Ken v1.3 serializer**: identity-bound punts, ARP checks, broadcast bypass, counting scope, config bounds, drop rules, rate-limit meter + metered flow, MODIFY on reinstall, meter error fallback (attributed, unattributed, unsupported), graduated + back-off, meter telemetry, reconnect cleanup | `os-ken` |
| `test_meters.py` | 9 | Meter id mapping, `OFPMeterMod` flags/bands, delete-all, identity-bound match, meter-then-output instructions, multipart requests encode | `os-ken` |
| `test_experiments.py` | 28 | `run_trial.py` with a fake Mininet: output-folder collisions, validation rules, probe CSV parsing (incl. stderr summary lines), bottleneck TCLink/qdisc checks, pcap stop, `analyze.compare` availability, demo timeline narration | `mininet` + `os-ken` importable |
| `test_topology.py` | 4 | `DDoSTopo` default unchanged; only `s1-eth1` shaped; RED and validation; the tc commands an installed Mininet would run | `mininet` importable (skipped otherwise) |

## 2. Running the tests

```bash
# Full suite (needs os-ken and mininet importable; see section 3)
.venv/bin/python -m unittest discover -s tests -v

# Development machine used for this branch: packages vendored in ../.deps
PYTHONPATH=/path/to/FlowGuard_repo/.deps python3 -m unittest discover -s tests

# Standard-library subset (Windows/macOS, no packages)
python3 -m unittest tests.test_detection tests.test_detectors tests.test_config \
    tests.test_mitigation_primitives tests.test_queueing tests.test_scenarios \
    tests.test_benchmark tests.test_probe_protocol tests.test_probe_cli \
    tests.test_live_lab tests.test_qdisc_monitor tests.test_wireshark_dissector \
    tests.test_demo_engine -v

# If "No module named tests.test_…" appears, a site-wide package called `tests`
# is shadowing this folder (it happens on the development machine); add -S
# (python3 -S -m unittest …) for the stdlib subsets, which need no site-packages.

# Portable subset used by the Windows package check (runs under python -S)
python3 -S -m unittest tests.test_detection tests.test_demo_engine tests.test_live_lab -v

# Focused security / experiment-integrity regressions -> audit/reproductions.json
python3 audit/reproduce.py

# Detector benchmark is reproducible byte for byte
python3 experiments/benchmark_detectors.py --check
```

Results on 22 October 2026 (Linux, Python 3.12.3, commit 5129b9d plus these
documentation changes):

| Command | Result |
|---|---|
| Full suite with OS-Ken 4.1.1, Mininet 2.3.0.dev6 and TShark 4.2.2 | **233 tests, OK, 0 skipped** |
| Same suite **without** those packages | `test_forwarding`, `test_meters`, `test_experiments` fail to import (3 errors) and 4 topology tests skip — expected; use the stdlib subset instead |
| Stdlib subset (13 files) | 135 tests, OK |
| Portable subset under `python -S` | 41 tests, OK |
| `audit/reproduce.py` | 223 tests in three suites (security 67, experiment integrity 43, advanced networking 113), passed |
| `benchmark_detectors.py --check` | `benchmark outputs in …/results/benchmarks are up to date` |

`python3 demo/run.py --scenario bugs` runs `audit/reproduce.py` and prints
its JSON. `python3 demo/terminal.py --doctor` is the presentation preflight
(Python version, offline assets, detectors and benchmark load, free UDP ports
19000–19022, capture tool presence).

### Packaging checks

```bash
python3 scripts/package_demo.py      # builds artifacts/FlowGuard-Windows-Demo.zip + package-check.json
python3 scripts/verify_portable.py   # extracts it, runs the portable tests with python -S,
                                     # starts demo/server.py on a free port, fetches every asset,
                                     # 12 simulation requests, /api/recorded, and 5 real UDP probes
```

`verify_portable.py` writes `artifacts/portable-package-check.json`. Its
`portable_tests` field is a hard-coded label (21) from an older revision; the
portable subset now has 41 tests and the check fails if any of them fails.

## 3. Linux lab setup

Tested environments: the recorded M2–M7 evidence used Ubuntu 26.04 LTS in
WSL2, Python 3.14.4, Mininet 2.3.0, Open vSwitch 3.7.1, OS-Ken 4.1.1 (see
[SETUP](SETUP.md)); the M8 runs of this branch used Ubuntu 24.04.3, Mininet
2.3.0, Open vSwitch 3.3.9, OS-Ken 4.1.1 and TShark 4.2.2 with the commands
below:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-venv tshark
sudo systemctl start openvswitch-switch
# A venv that can still see the apt-installed Mininet module:
python3 -m venv --system-site-packages .venv
.venv/bin/pip install os-ken==4.1.1          # or: sudo apt install -y python3-os-ken
.venv/bin/pip install 'Pillow>=12,<13'       # optional, only for the PNG charts
```

`FLOWGUARD_SYSTEM_SITE_PACKAGES=1 bash scripts/setup.sh` does the same with
the pinned `requirements.txt` and then runs the unit tests.

OS-Ken compatibility probe (checks the version and that the OpenFlow 1.3
meter classes the controller needs exist):

```bash
.venv/bin/python -c "import importlib.metadata as m; from os_ken.ofproto import ofproto_v1_3 as o, ofproto_v1_3_parser as p; print('os-ken', m.version('os-ken'), 'METER_MOD', o.OFPT_METER_MOD, 'meter instruction', hasattr(p, 'OFPInstructionMeter'), 'drop band', hasattr(p, 'OFPMeterBandDrop'))"
```

Expected: `os-ken 4.1.1 METER_MOD 29 meter instruction True drop band True`
(observed on the development machine). Then run the real-serializer tests:
`.venv/bin/python -m unittest discover -s tests -p 'test_meter*.py' -v` and
`.venv/bin/python -m unittest discover -s tests -p test_forwarding.py -v`.

Live checks, in order (each needs root, cleans up after itself; after an
interrupted run use `sudo mn -c`):

```bash
sudo .venv/bin/python topology/smoke.py              # ends with: M2 smoke test: PASS
sudo .venv/bin/python topology/controller_smoke.py   # ends with: M3 controller smoke test: PASS
sudo .venv/bin/python experiments/demo.py            # one narrated mitigated trial
sudo ovs-ofctl -O OpenFlow13 meter-features s1       # while a trial runs: does this OVS support meters?
```

`sudo` must be given the venv interpreter explicitly; `run_trial.py` starts
the controller with the same interpreter (`sys.executable`), so OS-Ken must
be importable by it.

### How to read a live trial

`experiments/run_trial.py` writes `metadata.json` with
`validation.status` = `passed` only if baseline pings were 0 % loss, every
3-probe prime from client/a1/a2 succeeded, the recovery probe got 10/10 and,
with a bottleneck, the qdisc tree was HTB + netem with the requested limit
both before and after the run. Client loss *during* the attack is a
measurement, never a failure. `python3 experiments/analyze.py <off> <on>`
refuses to compare trials whose rate, duration, configuration or bottleneck
differ, or whose validation did not pass, and reports
`availability.improved` only for a loss reduction of at least 10 percentage
points.

## 4. What is and is not verified

| Claim | Status | Evidence |
|---|---|---|
| Original detector, drop rules, expiry, recovery on a live OVS (pre-branch code) | **Measured** 13 and 20 October 2026 | `results/m4-*`–`m6-*`, [evidence/m7](../evidence/m7/RESULTS.md) |
| New config schema, detectors, policy primitives, queue model, probe protocol | **Unit-tested** | sections 1–2 |
| Native lab with bottleneck, rate limit, RED, EWMA/CUSUM/entropy, graduated + back-off | **Measured** with real localhost UDP on Linux, 21 October 2026 | [results/M9_NATIVE_EVIDENCE.md](../results/M9_NATIVE_EVIDENCE.md), [RESULTS](RESULTS.md#m9-advanced-results) |
| Detector comparison across 11 scenarios | **Simulated** (deterministic model, real detector code) | [detector-benchmark.md](../results/benchmarks/detector-benchmark.md) |
| Original demo regression on the current code (detect, drop, expire, recover, pcap) | **Measured live** 22 Oct 2026: alert 1.838 s, barrier 1.839 s, 7,470 packets blocked, client 80/80, recovery 10/10 | `results/m8-demo-original` |
| OpenFlow meter messages and metered flow accepted by OVS; meter features probe | **Measured live** on OVS 3.3.9: `supported`, `max_meter` 200000; meters 1021/1022 confirmed; `actions=meter:1021,output:1` | `results/m8-meter-on`, [RESULTS §M8](RESULTS.md#m8-live-mininet--open-vswitch-runs) |
| OVS polices at 20 pps, meter stats, FLOW_REMOVED for metered flows | **Measured live**: 6,735 band drops, ≈153 packets/source passed (≈20 pps + burst 20), `ratelimit_removed` reason 1 | `results/m8-meter-on/controller.jsonl` |
| Meter fallback to drop on OpenFlow errors | Unit-tested only (real serializer, mock datapath); **not exercised live** because this OVS supports meters | `tests/test_forwarding.py` |
| Mininet TCLink bottleneck builds HTB + netem on `s1-eth1` | **Verified live** with `tc -s -j qdisc show` before and after each run (`htb 5:` root, `netem 10:` limit 50) | `results/m8-*/qdisc-config.json`, `qdisc-after.json` |
| Availability improvement in Mininet with `--bottleneck` | **Measured live**: client loss 70.0 % → 25.0 %, RTT p95 136.2 → 0.6 ms (one run per mode) | `results/m8-bottleneck-compare` |
| CUSUM + graduated + back-off on OVS | **Measured live**: wave 1 meter rate limit 10 s, wave 2 drop 20 s | `results/m8-cusum-graduated-waves` |
| Mininet RED on a 50-packet queue | Expected to be inert (byte thresholds); **not measured** | [ARCHITECTURE §10.3](ARCHITECTURE.md#103-mininet-tclink-bottleneck) |
| Lua dissector decodes all payload families | **Verified with TShark 4.2.2** (Lua 5.2) on synthetic packets, the M7 sample and the live M8 captures (270 FGPB probe frames, all CRC-valid, in `m8-demo-original`); Wireshark GUI and Lua 5.4 builds not tried | `tests/test_wireshark_dissector.py`, [SCENARIOS §16](SCENARIOS.md#16-wireshark-dissector) |
| Wireshark profile I/O graphs and filter buttons | Written for Wireshark 4.6.9 interface IDs; not opened in Wireshark on this branch | [`wireshark/FlowGuard/`](../wireshark/FlowGuard/) |
| Native lab and dashboard on Windows | Earlier revision rehearsed on macOS only; Windows runtime still to rehearse | [VALIDATION](../VALIDATION.md) |
| OpenFlow control channel capture (`tcp.port == 6653`) | Not attempted (the `openflow_v4.type` field exists in TShark 4.2.2) | [WIRESHARK_DEMO](WIRESHARK_DEMO.md#capturing-the-openflow-control-channel-unverified) |
