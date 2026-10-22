# FlowGuard laptop handoff

Prepared on **22 October 2026**, Asia/Kolkata. Read this together with
[AGENTS.md](AGENTS.md). This document transfers the project context to a new
laptop and a new coding agent; it does not claim that the new laptop has been
tested.

## Start here: continue with Vyas's work

The user explicitly asked the next agent to **pull Vyas's new branch, review
it, and continue working on it as well as the existing demo**.

Repository: <https://github.com/Sai181006/FlowGuard>

| Ref | Observed tip on 22 October | Meaning |
|---|---|---|
| `codex/offline-dashboard-and-terminal-demo` | `0ab520b` before this handoff commit | Our audited controller, offline dashboard, native terminal demo and Windows package. This branch now also carries this handoff and the agent instructions. |
| `feature/advanced-networking` | `d96c50f0daafdd50659756cc32624d870408bb11` | Vyas's branch; latest observed commit rebuilds the portable demo package. |
| `main` | `5ae1dffdbfa019a46652b92e89ebe1575ad6ec39` | Newer reviewer materials, project documentation and packet-capture improvements. |

Git history and author metadata identify `feature/advanced-networking` as
Vyas-Vis06's branch. At the observed tip it **already contains both `0ab520b`
and the current `main` tip**. Do not reapply all our earlier commits or assume
Vyas's branch starts from an unrelated codebase. Fetch again: these tips may
advance after this document was written.

### Fresh laptop: obtain the handoff, then integrate the advanced branch

Run these Git commands in Terminal or PowerShell. Choose a fresh destination
folder. These commands do not install Linux or Python packages.

```sh
git clone --branch codex/offline-dashboard-and-terminal-demo https://github.com/Sai181006/FlowGuard.git FlowGuard
cd FlowGuard
git fetch origin --prune
git status --short --branch
```

Read `AGENTS.md` and this file. Review Vyas's changes before merging:

```sh
git log --oneline --graph --decorate --all -25
git log --oneline HEAD..origin/feature/advanced-networking
git diff --stat HEAD...origin/feature/advanced-networking
git show origin/feature/advanced-networking:README.md
git show origin/feature/advanced-networking:docs/TESTING.md
```

Then use a continuation branch to retain this handoff and incorporate Vyas's
work. This is the next agent's task; the handoff preparation itself did not
merge Vyas's code into this Mac checkout.

```sh
git switch -c work/continue-flowguard
git merge --no-edit origin/feature/advanced-networking
```

If that local branch name already exists, inspect it and reuse it if suitable,
or choose another descriptive name. In an existing checkout, inspect and
preserve local changes before switching or merging. Resolve any conflicts
after comparing both implementations; do not select one entire side blindly.
Do not force-push either collaborator's branch. For later updates use
`git fetch origin --prune`, inspect new commits, and merge the fetched branch
deliberately. A ZIP extraction has no Git history: clone the repository for
continued development.

## What the user wants

The objective is an impressive but understandable Computer Networks project
demonstration: an offline dashboard, complete terminal demonstration, real
logs and packet inspection, ON/OFF mitigation comparison, protocol explanation,
and clear evidence of which parts actually ran. The user grants creative
freedom to strengthen the project while keeping it easy to explain.

Persistent constraints and preferences:

- **Do not install Linux, a Linux VM, or WSL for testing.** An already available
  authorized Linux lab is a separate option, not a prerequisite for the native
  dashboard or terminal demo. Do not follow Linux installation instructions in
  other documents automatically.
- The native demonstration should run on macOS or Windows without a VM. The
  original full Mininet/Open vSwitch network needs a Linux environment.
- Keep the presentation offline-ready. Bundle libraries and fonts locally.
- Preserve the warm ivory, plum and copper visual design and the animated
  topology; avoid replacing it with a generic blue/black card dashboard.
- Make the demonstration self-explanatory, with toggles, explanations, logs,
  traffic flows and a polished presentation sequence.
- Be candid about measured results, generated counters, recorded evidence,
  and native gateway enforcement versus actual OpenFlow enforcement.

The earlier references to a presentation happening "tomorrow" are historical;
do not infer a new deadline from them. The new laptop's OS and installed
capture tools are not yet confirmed. Detect the environment and continue useful
work without waiting for optional preferences.

## Project in plain language

The original lab has a victim UDP echo service at `10.0.0.10:9000`, a protected
client at `.11`, and traffic-source hosts `.21`, `.22`, `.23`, connected to one
OpenFlow 1.3 OVS switch. OS-Ken polls service-flow counters. The original
detector requires victim traffic above 100 packets/s, at least two eligible
sources above 30 packets/s each, and two consecutive high observations.
Temporary source-specific rules stop matching UDP traffic for 10 seconds.

The native lab sends actual UDP datagrams on `127.0.0.1` using the project's
detector, echo service and probe. Its enforcement point is a Python gateway.
Ports 19011, 19021 and 19022 map to logical host labels `.11`, `.21`, `.22`;
the captured source IP is still localhost. Gateway ingress is 19001, backend
19002, and victim service 19000. This mapping is not source authentication.

## What is already complete on our demo branch

- Controller hardening: fixed MAC/IP/ingress-port bindings, validated ARP and
  destination identities, service-specific UDP accounting, active offender
  reconciliation, validated configuration and reconnect-state cleanup.
- Experiment fixes: reject output collisions, validate complete probes and
  recovery, distinguish measurement from successful execution, analyze repeat
  waves, and compare only compatible runs.
- Dashboard: six original scenarios, mitigation toggle, assumed-capacity
  control, animated network, synchronized journal and packet desk, recorded
  data mode, real five-probe localhost check, keyboard/fullscreen controls,
  narrow-screen layout, and GitHub's 2018 memcached reflection case study.
- Native terminal presentation: detector walkthrough, saved switch-rule
  evidence, actual UDP OFF/ON filtering, client RTTs, expiry, recovery and
  timestamped JSONL/CSV evidence. Windows `.cmd` launchers are included.
- Documentation: `README.md`, `DEMO.md`, `WINDOWS_DEMO.md`,
  `PROJECT_EXPLAINED.md`, `AUDIT.md`, `RESEARCH.md`, `VALIDATION.md`.
- Dependencies and assets: stdlib native runtime; D3 and eight local font
  files; pinned dependencies for the wider test/SDN environment.

## What Vyas added: read and work on this too

The following was established by reading fetched source, documentation,
commit history and selected saved metadata, **not by rerunning that branch**
on this Mac:

| Area | Files to inspect after integration |
|---|---|
| Shared lab constants and validated configuration | `controller/lab.py`, `controller/config.py`, `config/presets/` |
| EWMA, CUSUM and traffic-mix/KL detectors | `controller/detectors.py`, `demo/scenarios.py`, `experiments/benchmark_detectors.py`, `results/benchmarks/` |
| Rate limiting, graduated response and repeat-offender back-off | `controller/mitigation.py`, `controller/meters.py`, `controller/forwarding.py` |
| Native bottleneck and FIFO/RED queues | `demo/queueing.py`, `demo/live_lab.py` |
| Real Mininet bottleneck and qdisc evidence | `topology/lab_topology.py`, `experiments/qdisc_monitor.py`, `experiments/run_trial.py` |
| Binary FGPB probe, CRC32 and QoS metrics | `traffic/probe_protocol.py`, `traffic/probe.py`, `tests/test_probe_protocol.py` |
| Capture and packet decoding | `experiments/packet_capture.py`, `wireshark/flowguard.lua`, `wireshark/FlowGuard/` |
| Extended dashboard and terminal controls | `dashboard/`, `demo/engine.py`, `demo/server.py`, `demo/terminal.py` |
| Full architecture, scenario and result guides | `docs/ARCHITECTURE.md`, `docs/SCENARIOS.md`, `docs/TESTING.md`, `docs/RESULTS.md`, `docs/DEMO.md`, `docs/WIRESHARK_DEMO.md` |

Read the advanced branch's
[README](https://github.com/Sai181006/FlowGuard/blob/feature/advanced-networking/README.md),
[testing record](https://github.com/Sai181006/FlowGuard/blob/feature/advanced-networking/docs/TESTING.md)
and [results](https://github.com/Sai181006/FlowGuard/blob/feature/advanced-networking/docs/RESULTS.md).
Those files are newer than the root-level 20 October validation record.

## Evidence: keep the dates and platforms separate

| Evidence | Status and limits |
|---|---|
| Our Mac baseline, 20 October | Full 50-test suite passed. Python 3.12 stdlib-only rehearsal and extracted-package checks passed; portable subset then had 21 tests, 13 assets, 12 scenario/mitigation API requests and 5/5 actual UDP replies. |
| Our actual native OFF/ON run | `artifacts/terminal-verified/`: source ingress 9,616 each mode; victim echo replies 9,616 OFF versus 2,418 ON; actual gateway drops 0 versus 7,198; client 230/230 each mode; expiry and source recovery passed. Filtering, not saturation protection. |
| Original M6, 13 October | Saved Mininet runs: about 1,200 attacker packets/s OFF versus zero in selected complete post-mitigation windows ON; client 80/80 in both. These older results do not show an availability improvement. |
| Vyas's native M9, 21 October | Branch reports real localhost UDP through a Python bottleneck queue: attack-phase loss 71.2% OFF versus 23.8% ON. Inspect `results/M9_NATIVE_EVIDENCE.md` and `results/m9-native-*`. A userspace queue is not a kernel qdisc. |
| Vyas's Linux M8, 22 October | Committed Mininet/OVS evidence under `results/m8-*`: bottleneck compare, meter run, original-behavior regression and CUSUM/graduated waves. Selected metadata read during handoff has completed/passed status. Branch reports bottleneck loss 70% OFF versus 25% ON, OVS meter band drops and longer repeat-offender rules. Recompute from raw data before making claims; these were not run on this Mac. |
| Advanced automated checks | `docs/TESTING.md` reports 233 tests, 135 in the stdlib subset, and 41 in the portable subset on its Linux environment. Recount after fetching; do not describe these as tests performed on the new laptop. |

The advanced branch includes actual PCAPNG files and TShark evidence. The older
statement "no PCAP produced on this Mac" remains true for our Mac session,
but must not be generalized to the whole repository now. Native Windows and
the newer advanced code on macOS still need their own rehearsal. The advanced
branch also identifies live meter-error fallback, Mininet RED, the Wireshark
GUI profile and OpenFlow-channel capture as unverified in that work. Its live
results are limited trials, not production-scale or statistically broad proof.

## Run on another laptop without a VM

Use Python **3.12 or newer**. Do not copy this Mac's `.venv` to another laptop.
The native dashboard and live terminal demonstration need no pip packages.

macOS/Linux-style shell, from the repository root:

```sh
python3 --version
python3 demo/terminal.py --doctor
python3 demo/launch.py
```

The last command opens the dashboard at <http://127.0.0.1:8765/> and starts the
server if necessary. In another terminal:

```sh
python3 demo/terminal.py --step
python3 demo/live_lab.py --mitigation compare
```

On Windows, use `py -3` in place of `python3`, or double-click
`Start FlowGuard.cmd` / `Terminal Demo.cmd`. If `py` is unavailable, the
`scripts/python-windows.cmd` helper also tries `python`. On a fresh Mac,
`Start FlowGuard.command` expects `.venv/bin/python`, so the direct Python
launcher above is the simpler first run.

After integrating Vyas's branch, these additional native commands are available:

```sh
python3 demo/terminal.py --section detectors
python3 demo/terminal.py --section bottleneck
python3 demo/live_lab.py --bottleneck-pps 300 --queue-packets 50 --mitigation compare
python3 demo/live_lab.py --bottleneck-pps 300 --queue-packets 50 --action graduated --backoff --waves 3 --mitigation on
```

Use `--help` on the checked-out revision before scripting newer options.
Choose a fresh `--output` path for every live trial. The dashboard uses TCP
8765; the native lab uses UDP 19000, 19001, 19002, 19011, 19021, 19022.
Wireshark capture is optional and requires the correct loopback interface and
capture permissions. On Windows that means Npcap's loopback capture adapter.
Follow the branch's `docs/WIRESHARK_DEMO.md` and `WINDOWS_DEMO.md`.

## Verification after integration

Start with the native subset, which is suitable for a fresh Mac/Windows laptop:

```sh
python3 -S -m unittest tests.test_detection tests.test_demo_engine tests.test_live_lab -v
python3 experiments/benchmark_detectors.py --check
```

On Windows substitute `py -3` for `python3`. `-S` avoids an unrelated installed
package named `tests` shadowing this project's namespace and disables site
packages. The benchmark command exists on Vyas's branch. Use the larger stdlib
subset in `docs/TESTING.md` when testing advanced behavior; report optional
Lua/TShark skips honestly.

The full suite needs OS-Ken and Mininet's Python module importable. On the
original Mac environment it was run using `.venv/bin/python`; do not assume
that environment exists or works on the new laptop. `scripts/setup.sh` installs
the broader pinned Python dependencies and runs the full suite; read it and
choose an appropriate environment before using it. It is unnecessary for
native presentation startup. Installing Python packages alone does not make
the full SDN topology work outside Linux.

For dashboard changes, check browser behavior, offline assets, all evidence
modes, keyboard controls and narrow layouts. For package changes:

```sh
python3 scripts/package_demo.py
python3 -S scripts/verify_portable.py
```

The root Markdown files are included by the packaging script, so a subsequent
rebuild should include `HANDOFF.md` and `AGENTS.md`. Do not overwrite Vyas's
newer package with one rebuilt from the old demo branch.

## Concrete next-agent priorities

1. Fetch, review and integrate `feature/advanced-networking` into a continuation
   branch as above. Read the advanced architecture and testing guides.
2. Rehearse the advanced native demo on the actual destination OS; verify the
   four detectors, queue/mitigation choices, protected replies, expiry and
   recovery. Preserve the simple original demo as a fallback.
3. Recompute M8/M9 comparisons and detector benchmarks from their raw saved
   files. Inspect meter rules, events, qdisc metadata and capture summaries.
   Reuse evidence from an existing Linux lab without installing a new Linux VM.
4. Reconcile stale documentation and reporting: `VALIDATION.md` and portions of
   `AUDIT.md` describe older revisions. The advanced testing guide also notes
   that `scripts/verify_portable.py` hard-codes the old `portable_tests: 21`
   label even though that branch's subset has 41 tests. Report actual counts.
5. Inspect the course report in `reports/`: it still describes the older M6
   results and has blank team details. Align any requested update with verified
   advanced results; do not invent names or registration numbers.
6. Audit the changed controller/protocol/queue code as needed, especially
   error attribution, meter fallback, rule cleanup, scheduling, CRC semantics
   and consistency of dashboard labels. A barrier alone is ordering evidence;
   correlate errors, flow readback, counters and endpoint measurements.
7. Update explanations and the presentation sequence, rebuild the portable
   package after code/assets change, and record which OS/revision was tested.

## Suggested first message to the new agent

> Read AGENTS.md and HANDOFF.md. Continue FlowGuard on this laptop. Fetch and
> review origin/feature/advanced-networking, Vyas's branch, then integrate it
> with the handoff branch on a continuation branch and work on its improvements
> too. It already contains the earlier dashboard work and main as of the
> handoff snapshot. Do not install Linux, a VM or WSL. Rehearse the native
> dashboard/terminal demo on this machine, audit the advanced features, verify
> saved M8/M9 evidence, fix concrete issues and stale documentation, and retain
> a reliable offline demo. Clearly separate simulation, recorded Linux evidence
> and actual native UDP enforcement. Preserve collaborators' work and explain
> what was tested here versus what came from prior evidence.
