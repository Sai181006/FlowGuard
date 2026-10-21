# FlowGuard audit and remediation record

Date: 20 October 2026 (Asia/Kolkata). Reviewed upstream commit
`8bd3f5877aebda8c71e57f0790c4d340e57a7318` on `main`.

## Follow-up hardening — 20 October 2026

The seven findings below describe the original upstream code. The user
subsequently authorized fixes and an offline presentation dashboard. All seven
now have focused code changes and native regression coverage:

| Finding | Current change | Native regression evidence |
|---|---|---|
| FG-01: identity theft | Bind known MAC/IPs to explicit topology ingress ports before forwarding and in punt rules | Attacker-first identity rejection and actual topology port mapping checks |
| FG-02: ARP validation bypass | Validate sender/target form and retain sender IP/MAC/opcode in learned rules | Forged ARP rejected; legitimate discovery and learned matches checked |
| FG-03: uncounted broadcast path | Reject group-addressed or inconsistent L2 destinations for unicast lab IPv4; use fixed egress mapping | Broadcast/multicast UDP never produces packet-out |
| FG-04: UDP scope mismatch | Count only victim UDP/9000; other UDP forwarding uses a different cookie; reconcile offenders during active alerts | UDP/9001 excluded from detection; new/expired offenders reconciled |
| FG-05: mixed rerun artifacts | Require a new output directory before opening logs or starting subprocesses | Collision rejects without touching sentinel data or starting Mininet |
| FG-06: repeat analysis failure | Summarize each repeat wave with its own timings, probes, and flow snapshots | Existing two-wave artifact analyzes successfully; original M6 summary stays identical |
| FG-07: completion without validation | Validate complete probe CSVs and successful baseline, priming, and recovery; preserve attack-phase packet loss as measurement | Failure paths and completion/validation separation checked with mocked processes |

The controller also validates configuration, including an OpenFlow-compatible
hard timeout of **1–65,535 seconds**, and clears pending switch state on
disconnect/reconnect. The complete native suite currently passes **45 tests**.
`audit/reproduce.py` now runs current regression checks; the initial reproduction
output is retained in `audit/reproductions-original.json`.

These checks use real packet codecs/OpenFlow message classes with recording
datapaths and mocked experiment processes. **The changed controller has not been
run against a live Mininet/Open vSwitch topology**, per the no-Linux constraint.
The historical 13 October results predate these fixes. A barrier reply still
confirms ordering only; correlated switch-error handling and installed-rule
readback remain work for an actual switch validation run.

The dashboard separately labels simulated counters, original recorded data,
and real localhost UDP exchanges. Its modeled service capacity, client success,
latency, animated particles, and representative packet rows are not measured
server telemetry or a Wireshark capture. See [PROJECT_EXPLAINED.md](PROJECT_EXPLAINED.md)
and [RESEARCH.md](RESEARCH.md).

## Original upstream assessment

The existing happy-path tests and saved single-wave analysis work. This is a
small, fixed-topology lab with useful controls: loopback-only OpenFlow listening,
a default-drop switch rule, lab IP/MAC allowlists, bounded traffic generation,
source-attributable counters, and temporary mitigation flows. The strongest
remaining risks concern trusting host identity and preserving experiment
validity. It should not yet be treated as a hardened network defense.

Application code was unchanged during the initial audit. The follow-up changes
above are now present locally; the original historical results remain unchanged.

## Original prioritized findings (historical)

### FG-01 — P1: First-seen host identity can be stolen

Location: `controller/forwarding.py:171-190,298-313`.

The punt rules bind a MAC to an IP but omit the known switch ingress port. The
packet-in handler then learns the first port presenting that pair and rejects
subsequent moves. Before a legitimate host has been learned, or after controller
reconnect resets learning, another lab host can present that host's MAC/IP pair.
The attacker is accepted and the real host's later packets are rejected. Claiming
the protected client's identity also avoids source-based detection.

**Evidence:** `protected_identity_takeover` in `audit/reproduce.py` uses actual
OS-Ken packet serialization and controller handlers with a recording datapath.
A frame claiming `10.0.0.11` on attacker port 3 is forwarded; the real client's
identical frame on port 2 is subsequently rejected. This is an offline controller
reproduction, not an on-wire exploit test. It requires control of a lab host and
the ability to choose Ethernet/IP source fields before identity learning.

**Fix:** Bind each permitted MAC/IP to its expected ingress port at switch rule
installation, using the fixed topology's port mapping. Validate that same binding
in packet-in handling. Test attacker-first and reconnect ordering.

### FG-02 — P1: Learned ARP rules bypass sender identity validation

Location: `controller/forwarding.py:46-48,175,305-306`.

Initial ARP punt rules restrict `arp_spa`, but learned priority-20 ARP forwarding
rules only match ingress port, Ethernet source/destination, and EtherType. They
outrank the priority-5 punt rules. Once an allowed unicast ARP exchange installs a
forwarding rule, the same host can send matching frames with a different ARP
sender IP or hardware address directly through the switch. Those fields never
reach the controller's allowlist check. Even the packet-in path only verifies
that an ARP header exists; it does not verify sender hardware identity.

**Evidence:** `broad_arp_rule` records the exact match generated by the production
helper and confirms `arp_spa`/`arp_sha` are absent. The committed flow dumps also
contain learned ARP rules without those fields. Whether a particular peer accepts
the forged ARP reply was not tested.

**Fix:** Validate Ethernet source against ARP sender hardware/IP fields and include
the validated sender fields in installed ARP matches. Combine with FG-01's ingress
binding. Test forged ARP after a legitimate cached unicast exchange.

### FG-03 — P1: Broadcast-addressed UDP bypasses detection counters

Location: `controller/forwarding.py:218-225,301-305,314-318,332-339`.

An allowed source can address a UDP packet to the victim's IPv4 address while
using the Ethernet broadcast destination. The controller accepts it and emits an
`OFPP_FLOOD` packet-out, but installs no attributable UDP forwarding flow because
the Ethernet destination is not learned. Repeated packets follow the same path.
The statistics handler only counts `COOKIE_UDP` flows, so this traffic is absent
from the detector's source and victim rates. Every such packet also consumes
controller processing.

**Evidence:** `uncounted_broadcast_udp` sends two serialized frames from allowed
sources through the real packet-in handler with the victim MAC already learned.
Both produce flood packet-outs and neither installs a counted UDP flow. This is
an offline forwarding/counter reproduction; victim-side reception and saturation
were not tested on a live switch.

**Fix:** Reject or explicitly handle Ethernet broadcast/multicast destinations for
victim-directed unicast IP traffic. Preserve source attribution for every accepted
UDP forwarding path, including unresolved destinations. Test that permitted
traffic cannot reach the victim through an uncounted path.

### FG-04 — P2: Detection and mitigation cover different UDP traffic

Location: `controller/forwarding.py:50-57,69-74,117-120,218-225`;
`controller/detection.py:72-79`.

UDP forwarding and statistics aggregate every UDP destination port at the victim.
An alert causes drops only for port 9000. A flood to another UDP port therefore
triggers a mitigation event while the offending traffic remains permitted. It can
also keep `alert_active` latched, preventing a new mitigation decision when a
port-9000 flood joins the same continuously high episode.

**Evidence:** `udp_service_mismatch` feeds two valid source counters for UDP port
9001 through the real stats handler and records two drop rules for port 9000.
The current broad forwarding flows cannot distinguish those services at all.

**Fix:** Define whether the protected resource is port 9000 or all victim UDP
traffic, and align forwarding counters, statistics selection, and drop matches
with that scope. Reevaluate new offenders and expired blocks during a continuing
alert rather than relying solely on a transition from low to high traffic.

### FG-05 — P2: Trial reruns mix old events with replacement artifacts

Location: `experiments/run_trial.py:63-73`;
`controller/forwarding.py:101-103`; `traffic/echo_server.py:51-57,69-75`.

The runner accepts an existing output directory, replaces probe/log/metadata
files, but the controller and victim append JSONL records. Running a trial twice
in the same directory produces a mixture of old and new event timelines, while
the metadata and client CSV describe only the latest run. Analysis can then count
old alerts, select the wrong first confirmation, and derive invalid latencies or
traffic comparisons. Existing historical results can also be overwritten.

**Evidence:** Confirmed by file-open modes and the absence of an output collision
check. Historical directories were not modified to demonstrate this defect.

**Fix:** Require a new, empty directory or generate a unique run ID and put all
artifacts beneath it. Verify input run IDs during analysis. Do not silently mix
append-only and replacement files.

### FG-06 — P2: Repeat-wave trials cannot be analyzed

Location: `experiments/analyze.py:20-21,70-81`;
`experiments/run_trial.py:135-168`.

The runner's supported `mitigation-repeat` mode writes `attack-a1-wave1.jsonl`,
`client-wave1.csv`, and per-wave flow dumps. The analyzer treats every non-baseline
mode as a single wave and opens `attack-a1.jsonl`, `client.csv`, and
`flows-after-recovery.txt`. The committed `results/m5-repeat` directory therefore
raises `FileNotFoundError` immediately.

**Evidence:** Running `python experiments/analyze.py results/m5-repeat` reproduces
the exception. `repeat_analysis_failure` asserts it against the committed data.

**Fix:** Branch on the trial mode, analyze each wave with its own start/end and
client data, and summarize rearming and rule expiry separately for both waves.

### FG-07 — P2: Failed legitimate probes still yield a completed trial

Location: `experiments/run_trial.py:157-168,185-200`.

The runner explicitly excludes the client's nonzero return code from its failure
condition. It also records the recovery probe return code without checking it
before setting `status` to `completed`. A broken legitimate path can therefore
produce an apparently completed mitigation experiment. Client process failures
and dropped packets are not distinguished.

**Evidence:** `failed_probes_reported_complete` runs the real orchestration with
mocked network processes. Both legitimate and recovery probes exit 1; metadata
still records `status: completed` and `recovery_probe_exit: 1`.

**Fix:** Record traffic completion separately from experiment validation. Preserve
measured packet loss, but fail explicit baseline/recovery acceptance checks and
distinguish expected loss from process or parsing failures.

## Additional limitations

- `experiments/summarize.py:57-61` hardcodes the original WSL kernel, CPU, memory,
  and package versions. These are historical labels and must not be reused as
  automatically collected provenance for a new machine.
- A barrier reply is logged as `drop_confirmed`, but there is no application
  handler correlating OpenFlow errors with flow modifications. A barrier confirms
  processing order, which alone does not prove successful rule installation.
  Verify rule existence or error correlation before making that claim.
- Configuration validation now rejects zero/negative/nonfinite/out-of-range
  values, including a hard timeout above the OpenFlow 16-bit limit.
- Pending multipart/barrier state is now cleared on disconnect and reconnect.
  Entries still have no age-based expiry while a switch stays connected.
- The original nine unit tests have expanded to 45 native tests. Live switch
  installation/error behavior remains outside the verification performed here.

## Verification and evidence

- Native host: macOS/Apple Silicon, CPython 3.14.6 in `.venv`.
- All 9 upstream unit tests passed using
  `.venv/bin/python -m unittest discover -s tests -v`.
- The controller opened `127.0.0.1:6653` and sent an OpenFlow 1.3 HELLO to a local
  test socket. It was stopped after verification.
- Local UDP echo/probe integration passed: 5/5 probes on loopback port 19000.
  The service was stopped after verification.
- Baseline, matched M6 on/off, and high-load summary objects regenerated from raw
  committed files match all corresponding saved JSON objects exactly.
- `pip-audit` 2.10.1 scanned the 37 fully pinned runtime dependencies and reported
  **no known vulnerabilities** on the audit date. Raw output is in
  `audit/dependencies.json`; this is not a guarantee of vulnerability absence.
- The initial six offline reproductions confirmed the upstream defects. Their
  historical output is retained in `audit/reproductions-original.json`; current
  regression results in `audit/reproductions.json` verify the follow-up changes.
- Python compilation and shell syntax checks passed.
- Traffic CLI bounds rejected excess rate/duration, an external probe target,
  and a wildcard echo binding before any packets were sent.
- Full Mininet/Open vSwitch integration was **not run**, per the user's request
  not to install Linux. The attempted image download was canceled; its partial
  image, profile configuration, and unused disk were removed before any VM was
  created. No Linux environment was installed.
- `demo/run.py --scenario all` passed natively: actual detector behavior with
  simulated counters, recalculation of historical SDN results, and a live local
  UDP exchange. These are explicitly labeled and do not claim live SDN enforcement.

The original matched trials report approximately 1.55 s to detection, 1.63 s to
drop confirmation, and zero attacker traffic in the selected post-mitigation
windows. Legitimate probes succeeded 80/80 with mitigation **and 80/80 without
mitigation**, including at the highest committed unmitigated load. These results
support filtering correctness in the tested lab. They do not demonstrate improved
availability or resistance to a saturated, adaptive, or spoofing adversary.

## Reproduce locally

```sh
bash scripts/setup.sh
.venv/bin/python audit/reproduce.py
.venv/bin/python experiments/analyze.py results/m6-attack-off results/m6-attack-on
# Repeat-wave analysis now succeeds:
.venv/bin/python experiments/analyze.py results/m5-repeat
```

The original priority order was ingress/ARP/accounting enforcement, followed by
UDP scope and experiment integrity. Focused fixes now address that sequence;
live-switch validation is still needed before expanding the security claims.
