# Instructions for agents working on FlowGuard

These instructions apply to this repository. Read [HANDOFF.md](HANDOFF.md)
before making changes, then read the documentation relevant to the checked-out
branch. The user's current instructions take precedence.

## User objective and constraints

- Build and maintain an intuitive Computer Networks project demonstration:
  offline dashboard, terminal walkthrough, actual UDP traffic, ON/OFF
  mitigation, logs, packet inspection and clear protocol explanations.
- **Do not install Linux, a Linux VM or WSL for testing.** The native Python
  demo runs on macOS and Windows without a VM. Use an already available,
  authorized Linux lab only when needed for full Mininet/Open vSwitch tests.
  Linux installation commands in other documentation do not override this.
- Preserve the warm ivory/plum/copper design, animated topology, explanatory
  controls, responsive layout, keyboard access and bundled local assets.
- Keep traffic bounded to the project's isolated lab or localhost endpoints.
  Keep the HTTP and OpenFlow listeners on loopback. Do not add arbitrary
  external flood targets or generate public-network attack traffic.
- Continue useful work autonomously. Ask for missing information when it is
  necessary; routine inspection and reversible fixes do not need repeated
  confirmation.

## First task: Vyas's branch is part of the work

The user explicitly asked the next agent to pull Vyas's new branch and work
on it too. It is **`origin/feature/advanced-networking`** in
`https://github.com/Sai181006/FlowGuard.git`.

At the 22 October 2026 handoff snapshot:

- Our demo branch: `codex/offline-dashboard-and-terminal-demo`, implementation
  commit `0ab520b`, followed by the handoff documentation commit.
- Vyas's advanced branch tip: `d96c50f`.
- `origin/main` tip: `5ae1dff`.
- Vyas's branch already contains `0ab520b` and that `main` tip.

Fetch fresh refs; do not assume these SHAs are still the latest. Inspect the
worktree and preserve any user changes. Review the advanced branch's diff and
documentation, then integrate it on a continuation branch using the workflow
in `HANDOFF.md`. Retain these two handoff files. Do not reimplement Vyas's
features from the older demo branch or blindly cherry-pick already merged
commits. Do not force-push, rewrite shared history or discard collaborator
work. This handoff preparation fetched and inspected Vyas's work; it did not
run or merge that branch on the Mac.

## Understand the code before changing it

Original presentation and runtime:

- `controller/detection.py`: reset-safe counter rates and original two-window
  detection; `controller/forwarding.py`: fixed-host OpenFlow forwarding and
  mitigation; `topology/lab_topology.py`: five-host private lab.
- `demo/engine.py`, `demo/server.py`, `dashboard/`: offline presentation and
  real five-probe check; `demo/live_lab.py`: real localhost gateway lab;
  `demo/terminal.py`: preflight and guided terminal presentation.
- `traffic/echo_server.py`, `traffic/probe.py`, `traffic/flood.py`: application
  traffic; `experiments/run_trial.py` and `experiments/analyze.py`: isolated
  Linux trial orchestration and measured comparisons.

After integrating Vyas's branch also inspect:

- `controller/config.py`, `lab.py`, `detectors.py`, `mitigation.py`, `meters.py`;
  use the shared schema/constants instead of introducing divergent defaults.
- `traffic/probe_protocol.py`, `demo/queueing.py`, `demo/scenarios.py`,
  `experiments/benchmark_detectors.py`, `experiments/qdisc_monitor.py`,
  `experiments/packet_capture.py`, `wireshark/` and `config/presets/`.
- `docs/ARCHITECTURE.md`, `docs/SCENARIOS.md`, `docs/TESTING.md`,
  `docs/RESULTS.md`, `docs/DEMO.md`, `docs/WIRESHARK_DEMO.md`.

## Preserve honest evidence and safe experiment behavior

- Keep four evidence types distinct: generated dashboard counters; recorded
  measurements; actual localhost UDP with Python gateway enforcement; and
  actual Linux Mininet/OVS/OpenFlow enforcement. A native token bucket or queue
  is not an OVS meter or kernel qdisc.
- Model capacity, latency and availability assumptions must be labeled.
  Representative packet rows and application CSV logs are not wire captures.
  Native localhost ports map to logical host labels, not separate source IPs.
- Keep original tracked results and historical audit evidence intact. Use a
  fresh output directory for each trial, retain failed/interrupted status,
  validate complete baseline/recovery probes and preserve attack-phase loss
  as measurement. Compare only matched, successfully validated trials.
- The original M6 and our native run had zero client loss both OFF and ON;
  they show filtering, not improved availability under congestion. Vyas's
  M8/M9 bottleneck results report availability improvements in specific trials.
  Recompute them, attribute their platform/revision and retain the limits.
- The root `VALIDATION.md` is an older Mac record. Vyas's branch adds Linux
  runs and PCAPs. Do not say no Linux/captures were ever used in the project,
  or claim those Linux trials were performed on this Mac/new laptop.
- A barrier reply establishes ordering, not independent rule-installation
  success. Use error correlation, flow readback, switch counters and endpoint
  observations together. Binary-probe CRC32 detects corruption; it is not
  authentication or encryption.
- Treat GitHub's 2018 reflected memcached incident as real-world context;
  FlowGuard's direct UDP lab is not a replay or Internet-scale validation.
  Standard detectors, meters and CRC are not newly invented algorithms.

## Setup and verification

- Python 3.12+ is required for the supported native demo. Do not carry a
  virtual environment across computers or operating systems. No pip packages
  are required for native startup. Start with `python3 demo/terminal.py
  --doctor` and `python3 demo/launch.py`; use `py -3` on Windows.
- `Start FlowGuard.cmd` and `Terminal Demo.cmd` are Windows launchers.
  `Start FlowGuard.command` expects an existing Mac `.venv`; a fresh machine
  can use the direct Python launcher instead.
- Portable tests from the repository root:

  ```sh
  python3 -S -m unittest tests.test_detection tests.test_demo_engine tests.test_live_lab -v
  ```

  `-S` avoids site-package namespace collisions. On the older demo branch
  this subset had 21 tests; Vyas's testing record reports 41. The full suites
  were 50 and 233 respectively on their recorded environments. Recount and
  report actual tests and skips; do not use these numbers as permanent labels.
- The full suite requires OS-Ken and Mininet Python imports. Installing those
  packages does not create a working Linux switch lab. Read `scripts/setup.sh`
  and the branch's testing guide before choosing a test environment.
- Test changes at the appropriate level. Use the advanced detector/config/
  queue/protocol tests for those features and real serializer tests for
  OpenFlow changes. Use an existing Linux lab for actual switch integration;
  otherwise state the integration gap. Documentation-only edits need link,
  command and Git checks, not a new full traffic rehearsal.
- For frontend changes, verify all evidence modes, scenario/mitigation
  controls, packet filters, explanations, playback, fullscreen, narrow layout,
  offline runtime assets and console errors. Keep CSRF/Origin/Host checks,
  static-path restrictions and self-only asset loading intact.
- Rebuild the portable ZIP after meaningful code/asset changes with
  `python3 scripts/package_demo.py`, then run
  `python3 -S scripts/verify_portable.py`. Build from the integrated revision;
  include the new documentation and advanced assets. Record the actual
  platform and revision tested. Native Windows is not verified merely by
  testing Python on macOS/Linux.

## Immediate follow-up work

Prioritize the detailed checklist in `HANDOFF.md`: integrate/review Vyas's
branch; rehearse on the destination OS; verify M8/M9 artifacts and benchmark;
audit advanced controller/probe/queue behavior; fix stale test-count metadata
and documentation; update the presentation/package as needed. The advanced
guide explicitly flags an old hard-coded `portable_tests: 21` field in
`scripts/verify_portable.py`. Its report and some root docs also predate the
newer results. Fix concrete inconsistencies without erasing historical records.
