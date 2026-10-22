# FlowGuard scenario guide

Sixteen things you can run, what each one teaches, the exact commands, what
the output looks like, and how to explain it. Commands were checked against
each tool's `--help`. Output excerpts are copied or re-rendered from committed
evidence (the source file is named under every excerpt); nothing below is an
invented measurement. Live Mininet/Open vSwitch runs of this branch
(`results/m8-*`, 22 October 2026, Ubuntu 24.04.3, Mininet 2.3.0, OVS 3.3.9,
OS-Ken 4.1.1) are quoted where they exist; behaviour still not exercised live
is labelled **expected, not yet measured**. Summary lines marked "re-rendered"
were produced by running the tool's own print function on the saved files.

Background for the mechanisms: [ARCHITECTURE](ARCHITECTURE.md). What is
verified and how: [TESTING](TESTING.md). Packet-level walkthrough:
[WIRESHARK_DEMO](WIRESHARK_DEMO.md).

## Requirements at a glance

| Runtime | OS | Privileges | Python packages | Terminals |
|---|---|---|---|---|
| Dashboard (`demo/server.py`) and terminal (`demo/terminal.py`, `demo/run.py`) | Windows, macOS, Linux | none | stdlib only, Python ≥ 3.12 | 1 (+ browser) |
| Native localhost lab (`demo/live_lab.py`) | Windows, macOS, Linux | none (capture may need Wireshark/Npcap permissions) | stdlib only | 1, plus Wireshark if capturing |
| Mininet / OVS (`experiments/demo.py`, `run_trial.py`) | Linux (Ubuntu or WSL2 with systemd) | **root** | `mininet`, `os-ken` 4.1.1 (see [TESTING](TESTING.md#3-linux-lab-setup)) | 1; a 2nd for `ovs-ofctl`/`tail -f` |

On Windows use `py -3` instead of `python3`. Only one native lab (fixed UDP
ports 19000–19022) and one Mininet trial (controller port 6653, switch `s1`)
can run at a time.

In the commands, `results/native-*`, `results/demo-*` and `results/m8-*`
folders are git-ignored scratch locations; copy a run you want to keep to a
new committed folder (as was done for `results/m9-native-*`).

Dashboard: `python3 demo/server.py`, open <http://127.0.0.1:8765/>, stay on
**01 The network → Interactive model**. "Tune the model" opens the detector,
response, rate-limit, back-off and bottleneck-queue controls.

---

## 1. Original Mininet demo (one mitigated trial)

**Objective.** Show the original end-to-end SDN loop: OVS counters → controller
detection → OpenFlow drop rules → expiry → recovery.

**CN concepts.** Control plane vs data plane; OpenFlow 1.3 flow tables,
priorities, match fields, `hard_timeout`, barrier; UDP echo; flow statistics
polling.

**Commands (Linux, root).**

```bash
sudo python3 experiments/demo.py                  # one attack-on trial, results/demo-<timestamp>/
sudo python3 experiments/demo.py --pcap           # also writes flowguard.pcapng
python3 experiments/analyze.py results/<run>
grep 'cookie=0xdd05000000000005' results/<run>/flows-during.txt
```

**Live regression on this branch** (`results/m8-demo-original`, review summary
re-rendered by `experiments/demo.py`'s `review()` and `show_capture()`):

```text
  Host connectivity: 100%
  Alert latency: 1.838 s
  Switch confirmation: 1.839 s
  Attacker packets counted by expired drop rules: 7470
  Legitimate probes during attack: 80/80
  Legitimate probes after recovery: 10/10
  Drop rules after recovery: 0
  Wireshark file: results/m8-demo-original/flowguard.pcapng
  Captured UDP packets by observation point: a1-offered=4800, a2-offered=4800, client-offered=90, victim-received=2294, client-reply-egress=90
```

**Terminal phases.** The phase lines come from `experiments/demo.py`
(`[1/5] BASELINE`, `NORMAL 20/20 host pings…`, `[2/5] FLOOD`, `[3/5] DETECT AND
BLOCK`, `ALERT`, `RULE`, `BLOCK`, `VERIFY`, `[4/5] RECOVERY`, `EXPIRE`,
`[5/5] REVIEW SUMMARY`). The clean rehearsal in
[evidence/m7/RESULTS.md](../evidence/m7/RESULTS.md) observed: alert at
1.851 s, both drop rules confirmed at 1.914 s, client 80/80 during the attack
and 10/10 after recovery, zero drop rules in the recovery flow table. The
saved rules of the M6 trial (`results/m6-attack-on/flows-during.txt`):

```text
cookie=0xdd05000000000005, duration=2.367s, table=0, n_packets=1287, n_bytes=218790, hard_timeout=10, send_flow_rem priority=200,udp,nw_src=10.0.0.21,nw_dst=10.0.0.10,tp_dst=9000 actions=drop
cookie=0xdd05000000000005, duration=2.341s, table=0, n_packets=1217, n_bytes=206890, hard_timeout=10, send_flow_rem priority=200,udp,nw_src=10.0.0.22,nw_dst=10.0.0.10,tp_dst=9000 actions=drop
```

**Animation.** None; the dashboard's **Recorded experiment** tab replays the
M6 data of this trial type.

**Wireshark.** Open the run's `flowguard.pcapng` (or the committed
[sample](../evidence/m7/flowguard-wireshark-sample.pcapng)). No capture filter
is needed (the file only holds lab UDP). Display filters:
`frame.interface_name == "victim-received" && (ip.src == 10.0.0.21 || ip.src == 10.0.0.22)`
falls to zero after the rule; `frame.interface_name == "client-reply-egress"`
keeps flowing.

**Explanation.** Detection is two consecutive 1-s windows above 100 pps total
and 30 pps from each of two sources; the barrier reply proves only that the
switch processed the rules in order, so filtering is shown by the flow table
counters, victim receive counts and the capture together. Without a
bottleneck the client is not congested, so this demo shows **selective
filtering, not availability improvement**.

## 2. Original native compare (no bottleneck)

**Objective.** Same detection and drop policy with real UDP on localhost, on any OS.

**CN concepts.** UDP sockets and ports, proxying, request/response matching,
RTT measurement, why an uncongested path shows no availability difference.

**Commands.**

```bash
python3 demo/live_lab.py --output results/native-original
python3 demo/terminal.py --section live      # same run, with the preflight first
```

**Expected output** (re-rendered by `print_comparison` from
`results/m9-native-original-final/comparison.json`):

```text
COMPARISON | real received datagrams, entire trial
  OFF | attacker ingress  9,614 | victim echoes  9,614 | gateway drops      0 | client 230/230
  ON  | attacker ingress  9,616 | victim echoes  2,420 | gateway drops  7,196 | client 230/230

ATTACK PHASE | protected client probes sent during the attack
                                     OFF        ON
  client loss %                      0.0       0.0
  p95 RTT ms                         0.6       0.7
  gateway drops (whole trial)          0     7,196
  availability_improved: n/a (not applicable: no bottleneck, so the flood cannot congest the client path)
```

**Wireshark.** Interface: Linux `lo` / Windows "Adapter for loopback traffic
capture" (Npcap). Capture filter `udp portrange 19000-19022`. Display filters:
`udp.dstport == 19001` (offered to the gateway), `udp.dstport == 19000`
(forwarded to the victim), `flowguard.kind == "native_flood"` (source
datagrams, needs the dissector).

**Explanation.** The gateway counts forwarded datagrams like a switch flow
counter, the original detector alerts at ≈4.0 s (two windows after the attack
starts at 2 s), and 10-s drop rules discard 3,598 datagrams per source. Client
loss is 0 % in both modes — the honest reason the original project could not
claim improved availability.

## 3. Dashboard basics: normal, burst, sustained, waves, single-source, low-rate

**Objective.** Explain the threshold detector's decisions and blind spots without sending packets.

**CN concepts.** Rate from counter differences, thresholds, persistence
(consecutive windows), attribution, rule TTL.

**Commands.** Dashboard: choose the story in **TRAFFIC STORY** — "An ordinary
day" (normal), "The innocent burst" (burst), "The coordinated flood"
(sustained), "The second wave" (waves), "One very noisy source"
(single-source), "Below the radar" (low-rate). Terminal equivalent of the
detector walkthrough:

```bash
python3 demo/terminal.py --section detector
python3 demo/run.py --scenario detector --step
```

**Expected behaviour** (shipped threshold detector, noise-free model): normal
and burst never alert; sustained alerts at t = 7 s (attack starts at 5 s;
two windows), rules expire at 17 s and the still-running flood is re-detected
at 19 s; single-source never alerts (`min_sources` = 2); low-rate never
alerts (2 × 40 + 10 = 90 pps < 100 pps).

**Animation.** Host rates on the network map (source C, `10.0.0.23`, is
shown as a reserve node and joins in the three-source and flash-crowd
stories), the two "high window" dots filling, the controller state, active
rule pills, queue-depth, queue-overflow and detector-score tiles, the controller journal
(alert, drop requested, rule expired), the OFF/ON comparison chart, and the
packet desk of representative rows.

**Wireshark.** Not applicable — the model sends no packets. The packet desk
says "Representative model packets"; it is not a capture.

**Explanation.** These six reproduce the original dashboard exactly
(`tests/test_scenarios.py` checks parity second by second). Capacity, client
success and latency in the model are explicit assumptions.

## 4. Pulsing flood (1 s on / 1 s off)

**Objective.** Show an attack that defeats any "N consecutive windows" rule.

**CN concepts.** Sampling interval vs attack period; cumulative-sum change detection.

**Commands.** Dashboard "The pulsing flood"; Tune the model → Detector
"CUSUM change detector" to compare. Benchmark row: `python3 demo/terminal.py --section detectors`.

**Expected output** (from `results/benchmarks/detector-benchmark.md`, 20 seeds):

```text
| pulsing | 0% | 0% | 100% (3 s) | 0% |      threshold | ewma | cusum | entropy
```

In the noise-free model CUSUM alerts at t = 8 s (S = 3.5, 3.0, 6.5 > h = 6 on
the second pulse) and again at 22 s after the 10-s rules expire; threshold
raises no alert at all.

**Animation.** Source rates jump every other second; the high-window dots
never reach 2/2 with the threshold detector; with CUSUM the journal shows the
alert with a score of 6.5.

**Explanation.** CUSUM accumulates standardised excess S ← max(0, S + z − k)
across windows, so evidence survives the quiet second; detectors that require
consecutive high windows reset every time. See [ARCHITECTURE §8.3](ARCHITECTURE.md#83-page-cusum-cusumdetector).

## 5. Low-and-slow ramp

**Objective.** Show that self-adjusting baselines can learn a slowly growing attack as normal.

**CN concepts.** Adaptive baselines, concept drift.

**Commands.** Dashboard "The slow ramp" (5 → 150 pps per source over 20 s), try each detector.

**Expected output** (benchmark): threshold 100 % (median 8 s), EWMA 55 % (5 s),
CUSUM 100 % (3 s), entropy 10 % (5 s). In the noise-free model the threshold
detector alerts at 13 s, when the aggregate passes 100 pps.

**Explanation.** EWMA and entropy keep learning while the rise per window is
small, so the limit moves with the attack; a fixed threshold eventually
trips; CUSUM integrates the small positive z-scores before the baseline catches up.

## 6. Flash crowd (benign)

**Objective.** Show the false-positive problem of volume detectors.

**CN concepts.** Volume vs composition; Kullback–Leibler divergence.

**Commands.** Dashboard "The flash crowd"; switch Detector to "Traffic-mix divergence".

**Expected output** (benchmark, benign row = runs with any alert):
threshold FP 20/20, EWMA 15/20, CUSUM 20/20, entropy 0/20. In the noise-free
model the threshold detector alerts at 10 s and drops **all three** sources
including the reserve host `10.0.0.23`; entropy raises nothing.

**Explanation.** Every host, the client included, scales ×20 with the same
mix. Rates cross every volume threshold, but the share vector P equals the
baseline Q, so D(P‖Q) ≈ 0 bits. This is the only scenario where entropy wins
outright — and it misses pulsing and ramp. No detector wins every row.

## 7. Three-source flood

**Objective.** Attribution beyond the fixed pair of attackers.

**Commands.** Dashboard "Three sources at once".

**Expected output.** All four detectors 100 % (2 s) in the benchmark, with 60
true-positive source attributions out of 60 (3 sources × 20 runs) and no
false attribution. In the model the threshold detector installs three drop
rules at 7 s.

**Explanation.** Per-source counters make attribution independent of the
number of sources; the third host `10.0.0.23` exists in the Mininet topology
but is idle in the recorded runs.

## 8. Repeat offender, graduated response and back-off

**Objective.** Escalate the response for a source that comes back.

**CN concepts.** Policing vs dropping, exponential back-off (as in TCP RTO or
Ethernet CSMA/CD), state with memory.

**Commands.**

```bash
# Dashboard: "The repeat offender", Response = Graduated, tick "Back-off for repeat offenders"
python3 demo/live_lab.py --mitigation on --bottleneck-pps 300 --queue-packets 50 \
    --action graduated --backoff --waves 3 --output results/native-graduated
sudo .venv/bin/python experiments/run_trial.py --mode mitigation-repeat --bottleneck-mbit 0.5 --queue-packets 50 \
    --detector cusum --mitigation-action graduated --backoff --output results/m8-cusum-graduated-waves   # Mininet
```

**Expected output** (real events from `results/m9-native-graduated-waves/on/events.jsonl`, condensed to one line per event; a2 `10.0.0.22` has identical entries):

```text
t=4.00  alert                        10.0.0.21 599.9 pps, 10.0.0.22 599.9 pps
t=4.00  gateway_ratelimit_installed  10.0.0.21 rate 20 pps burst 20 timeout 10 s offense 1
t=14.00 rule_expired                 10.0.0.21 rate_limit
t=18.01 alert                        (wave 2)
t=18.01 gateway_drop_installed       10.0.0.21 timeout 20 s offense 2
t=38.01 rule_expired                 10.0.0.21 drop
```

Wave 3 (30–38 s) fell entirely inside the 20-s drop, so no third alert was
needed. Over all three waves the client lost 15.4 % of 240 attack-phase
probes and 0 % in gaps, expiry-wait and recovery; each source had 147
datagrams passed and 3,461 policed by the token bucket. The model shows the
same pattern for the 50-s dashboard scenario: rate limit at 7 s, 20-s drop at
24 s, and the third wave (39–44 s) absorbed by that still-active rule. The
live Mininet counterpart (`results/m8-cusum-graduated-waves`, two waves, CUSUM)
logged: wave 1 alert 2.200 s after the wave started → `ratelimit_requested`
meters 1021/1022, 20 pps, 10 s, offense 1 → `ratelimit_confirmed`; 6,686
meter band drops; wave 2 alert 2.103 s after its start → `drop_requested`
`hard_timeout_s` 20, offense 2 → `drop_confirmed`. Client loss 16.25 % in
wave 1 and 25.0 % in wave 2; recovery 10/10.

**Wireshark.** Native: `udp.dstport == 19000 && udp.srcport == 19002` shows
forwarded traffic; with the dissector, `flowguard.phase == "attack"` and an
I/O graph show the ~20 pps trickle during wave 1 and zero during wave 2.

**Explanation.** `choose_action("graduated", n)` rate-limits offense 1 and
drops from offense 2; `T(n) = min(80, 10 · 2^(n−1))` gives 10 s then 20 s.
`--waves` gaps are 6 s, well inside the 120-s back-off memory.

## 9. Bottleneck OFF vs ON — native

**Objective.** Measure availability: does mitigation restore the protected client when the path is congested?

**CN concepts.** Bottleneck link, finite FIFO buffer, tail drop, queueing
delay, bufferbloat, loss vs latency, the availability/attack-filtering distinction.

**Commands.**

```bash
python3 demo/live_lab.py --bottleneck-pps 300 --queue-packets 50 --output results/native-bottleneck
python3 demo/terminal.py --section bottleneck     # preflight + the same command
```

**Expected output** (re-rendered from `results/m9-native-bottleneck/comparison.json`):

```text
ATTACK PHASE | protected client probes sent during the attack
                                     OFF        ON
  client loss %                     71.2      23.8
  client probes                       80        80
  p95 RTT ms                       166.7       5.2
  jitter ms (RFC 3550)              0.22      0.56
  queue drops (whole trial)        7,231     1,773
  queue delay p95 ms               166.5     166.5
  gateway drops (whole trial)          0     7,198
  availability_improved: YES (ON attack-phase client loss 23.8% vs OFF 71.2% (needs at least 10 percentage points lower))
The bottleneck is an emulated 300 packets/s, 50-packet FIFO queue inside the Python gateway, not a kernel or NIC queue.
```

**Wireshark.** Capture on loopback with `udp portrange 19000-19022`. Compare
`udp.dstport == 19001` (offered, pre-queue) with `udp.dstport == 19000`
(post-queue, delivered to the victim). In the OFF run the post-queue rate is
capped at ≈300 pps while offered is ≈1,210 pps.

**Explanation.** Fluid prediction 1 − 300/1210 ≈ 75 % loss and a maximum
queueing delay of 50/300 s = 166.7 ms; measured 71.25 % and 166.5 ms. With
mitigation ON the remaining 23.75 % loss happens almost entirely in the 2 s
before the second high window (≈ 2/8 of the attack phase × ~75 %); after the
drop rules the queue empties and the RTT returns to ≈4–5 ms. The queue is a
userspace emulation, so this is evidence about the policy under congestion,
not about kernel queueing.

## 10. Bottleneck OFF vs ON — Mininet (measured live)

**Objective.** The same question with a kernel qdisc and a real OVS.

**Commands (Linux, root).**

```bash
sudo .venv/bin/python experiments/demo.py --bottleneck --compare --pcap --output results/m8-bottleneck-compare
.venv/bin/python experiments/analyze.py results/m8-bottleneck-compare/off results/m8-bottleneck-compare/on
.venv/bin/python experiments/render_availability_png.py results/m8-bottleneck-compare/off results/m8-bottleneck-compare/on
# In a second terminal during a run:
sudo tc -s qdisc show dev s1-eth1
```

**Output.** `demo.py` first prints `Bottleneck: s1-eth1 -> victim shaped to
0.5 Mbit/s (about 368 flood packets/s) with a 50-packet queue; the flood
offers 1.63 Mbit/s`. The committed live run (`results/m8-bottleneck-compare`),
re-rendered with `demo.py`'s `show_availability()`:

```text
                                              OFF           ON
  Client probe loss during attack           70.0%        25.0%
  Client RTT p95                         136.2 ms       0.6 ms
  Bottleneck queue drops                     6677         1721
  Attacker pps reaching the victim            366            0
  Loss reduction: 45.0 percentage points (attacker rate compared from 2.61 s after attack start)
  Interpretation: availability improvement measured: mitigation reduced client loss by 45.0 points under the same bottleneck and configuration.
```

The ON run's review adds `Bottleneck queue (s1-eth1): 1721 packets dropped;
max backlog 8500 bytes / 50 packets`. Sizing predicted ≈70 % OFF loss, ≈367
frames/s and ≤136 ms delay; all three match. Chart:
[availability-comparison.png](../results/m8-bottleneck-compare/availability-comparison.png);
full table in [RESULTS](RESULTS.md#m8-live-mininet--open-vswitch-runs).

**Wireshark.** `flowguard.pcapng`: `*-offered` streams are before OVS;
`victim-received` is after the qdisc dequeue (OFF run: 3,017 frames reached the
victim out of 9,690 offered; ON run: 904). Offered minus victim-received
equals drop-rule/meter drops plus queue drops (the qdisc's `drops` counter in
`qdisc.jsonl` separates the two).

**Explanation.** Detection still works under congestion because OpenFlow
counters are taken at ingress, before the egress queue. `run_trial.py`
refuses to start traffic unless `tc -s -j qdisc show dev s1-eth1` shows an
HTB root with a netem leaf of the requested `limit`.

## 11. Rate limit vs drop — native token bucket and OpenFlow meter

**Objective.** Compare policing an offender with blocking it.

**CN concepts.** Token bucket (rate r, depth b), traffic policing vs shaping,
OpenFlow 1.3 meters and drop bands.

**Commands.**

```bash
python3 demo/live_lab.py --bottleneck-pps 300 --queue-packets 50 --action rate_limit \
    --output results/native-ratelimit                   # add --rate-limit-pps 50 to change r
sudo python3 experiments/demo.py --bottleneck --compare --mitigation-action rate_limit   # Mininet
sudo ovs-ofctl -O OpenFlow13 dump-meters s1             # second terminal, during the ON run
sudo ovs-ofctl -O OpenFlow13 meter-stats s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 0xdd05000000000006
```

**Expected output** (native, `results/m9-native-ratelimit/comparison.json`):
OFF attack-phase client loss 82.5 %, ON 25.0 %; p95 RTT 167.9 → 4.8 ms;
each source passed 139 and had 3,460 datagrams policed.

Mininet, measured live (`results/m8-meter-on`, made with
`sudo .venv/bin/python experiments/run_trial.py --mode attack-on --bottleneck-mbit 0.5 --queue-packets 50 --mitigation-action rate_limit --output results/m8-meter-on`):
`meter_features` supported with `max_meter` 200000; `ratelimit_requested`
for meters 1021 and 1022 (20 pps, burst 20, 10 s), one `ratelimit_confirmed`;
`meter_sample` events of 559, 580, 581, 580, 581, 486 band drops per second
for meter 1021 (total 3,367; both meters 6,735); `ratelimit_removed` with 3,520
and 3,521 matched packets (reason 1, hard timeout). The saved flow table shows
`priority=200,udp,in_port=3,dl_src=02:00:00:00:00:21,dl_dst=02:00:00:00:00:10,nw_src=10.0.0.21,nw_dst=10.0.0.10,tp_dst=9000 actions=meter:1021,output:1`.
3,520 − 3,367 = 153 packets passed per source ≈ 20 pps × 6.6 s + 20 burst.
Client attack-phase loss 20.0 %. The operator also saw `dump-meters` print
`meter=1021 pktps burst stats bands= type=drop rate=20 burst_size=20` (not
saved in the folder). With `demo.py` the same events print as `RATE-LIMIT …`,
`METER meter bands dropped <n> packets …` lines.

**Explanation.** 2 sources × 20 pps + 10 pps client = 50 pps ≪ 300 pps, so
policing removes the congestion just as well as dropping here while still
letting a little of each offender's traffic through — useful when the
"offender" might be a legitimate but misbehaving client. In the Mininet
runtime, OVS (not FlowGuard) polices the packets; FlowGuard only sends the
`OFPMeterMod` and the metered flow ([ARCHITECTURE §9.5](ARCHITECTURE.md#95-openflow-message-sequences)).

## 12. Meter fallback to drop

**Objective.** Show robust handling when a switch rejects meters.

**CN concepts.** OpenFlow error messages, capability discovery (multipart
METER_FEATURES), barrier ordering semantics.

**Commands.**

```bash
.venv/bin/python -m unittest discover -s tests -p test_forwarding.py -k RateLimit -v
# On a live switch, inspect which path was taken:
grep -E '"type": "(meter_features|openflow_error|ratelimit_failed)"' results/<run>/on/controller.jsonl
```

**Expected output.** The unit tests named
`test_meter_mod_failure_falls_back_to_drop_with_the_same_timeout`,
`test_rejected_metered_flow_falls_back_for_that_source_only`,
`test_unattributed_meter_error_fails_every_pending_rate_limit` and
`test_switch_without_meters_gets_drop_rules_directly` pass. On a live run the
timeline would print `METER-FALLBACK meter for 10.0.0.21 failed
(openflow_error); falling back to drop` (or `(meter_unsupported)`) followed by
`RULE … BLOCK` lines — **expected, not yet measured**: FlowGuard has no switch
option to force a meter failure, and the OVS 3.3.9 used for the live runs
supports meters (`meter_features: supported`), so a live demonstration needs
a switch or datapath without meter support.

**Explanation.** OpenFlow switches process messages in order and send an
error for a failed message before answering a later barrier, so at
BARRIER_REPLY time the controller knows which rate limits failed and replaces
them with drop rules carrying the same timeout.

## 13. RED vs FIFO

**Objective.** Compare active queue management with drop-tail.

**CN concepts.** RED (min_th, max_th, max_p, w_q), average vs instantaneous
queue, delay vs loss, fairness between flows.

**Commands.**

```bash
python3 demo/live_lab.py --mitigation off --bottleneck-pps 300 --queue-packets 50 --output results/native-fifo
python3 demo/live_lab.py --mitigation off --bottleneck-pps 300 --queue-packets 50 \
    --queue-discipline red --output results/native-red
# Committed evidence used RED together with --detector ewma (detector choice does not affect OFF runs):
python3 demo/live_lab.py --bottleneck-pps 300 --queue-packets 50 --queue-discipline red --detector ewma
# Mininet (expected, not yet measured live; RED is inert at 50 packets, see below):
sudo python3 experiments/run_trial.py --mode attack-off --bottleneck-mbit 0.5 --queue-packets 50 \
    --qdisc red --output results/m8-red-off
```

**Expected output** (OFF runs, both real): FIFO
(`m9-native-bottleneck/off`) attack-phase client loss 71.25 %, queue delay
p95 166.5 ms, drops split a1 2,407 / a2 4,767; RED
(`m9-native-red-ewma-warm/off`) client loss 81.25 %, queue delay p50 100.1 ms
and p95 106.7 ms, 7,242 RED drops and 9 tail drops, split a1 3,549 / a2 3,635.

**Explanation.** RED keeps the *average* queue near max_th = 30 packets, so
delay ≈ 30/300 s = 100 ms instead of 50/300 s = 166.7 ms, and its randomised
drops spread loss evenly across flows. It does not reduce loss under a 4×
overload — nothing but removing the excess traffic can. In Mininet, RED's
hard-coded byte thresholds only act above ≈176 packets of backlog, so with a
50-packet netem limit `--qdisc red` behaves like FIFO.

## 14. Detector benchmark

**Objective.** Compare four detectors quantitatively across eleven scenarios.

**CN concepts.** Detection rate, latency, false-positive rate, ROC operating points.

**Commands.**

```bash
python3 experiments/benchmark_detectors.py --check          # verify committed outputs
python3 experiments/benchmark_detectors.py --seeds 20 --seed-base 1729 --roc \
    --output /tmp/flowguard-bench                         # regenerate elsewhere
python3 demo/run.py --scenario benchmark
python3 demo/terminal.py --section detectors
```

**Expected output** (`--check`):

```text
benchmark outputs in .../results/benchmarks are up to date
```

and the matrix of [detector-benchmark.md](../results/benchmarks/detector-benchmark.md),
printed by the terminal as:

```text
single-source: missed in most runs by threshold; caught by ewma, cusum, entropy.
low-rate: missed in most runs by threshold; caught by ewma, cusum, entropy.
pulsing: missed in most runs by threshold, ewma, entropy; caught by cusum.
ramp: missed in most runs by entropy; caught by threshold, ewma, cusum.
flash-crowd: false alerts from threshold, ewma, cusum; only entropy stayed quiet.
```

**Animation.** Dashboard page **03 Behind the scenes** → "Offline detector
benchmark" table (simulated, no packets).

**Explanation.** Simulated per-second counters with seeded Poisson noise go
through the real detector classes with mitigation off. Threshold's 40 %
low-rate detection exists only because noise occasionally pushes 90 pps over
100 pps (median 13 s). It is a model comparison, not a field measurement.

## 15. Probe protocol, RTT percentiles and jitter

**Objective.** Show a self-describing binary probe and standard QoS metrics.

**CN concepts.** Application-layer header design, network byte order, CRC32,
sequence numbers, loss/late/duplicate/reorder (RFC 4737), RFC 3550 jitter,
nearest-rank percentiles, stop-and-wait vs paced streams.

**Commands** (any free port; not the lab's fixed ports):

```bash
python3 traffic/echo_server.py --bind 127.0.0.1 --port 29555 &
python3 traffic/probe.py --target 127.0.0.1 --port 29555 --count 10 --mode stream --metrics-json probe.json
python3 traffic/probe.py --target 127.0.0.1 --port 29555 --count 3 --format text
kill %1
python3 -c "from traffic.probe_protocol import encode, describe; print(describe(encode(7, 0x1234ABCD, 0, total_bytes=64)))"
```

**Expected output** (a real run on this machine, 22 October 2026):

```text
timestamp_utc,sequence,status,rtt_ms
2026-10-22T06:32:25.048318+00:00,1,ok,0.296
...
2026-10-22T06:32:25.949261+00:00,10,ok,0.450
sent=10 received=10 loss=0.0%
metrics p50=0.450 p95=0.518 p99=0.518 jitter=0.020
```

`probe.json` adds `late`, `duplicates`, `reordered`, `max_consecutive_loss`,
`session_id` and RTT min/mean/max. The header bytes of a 64-byte probe
(seq 7, session 0x1234abcd) are
`46 47 50 42 01 01 00 20 12 34 ab cd 00 00 00 07 … 00 20 00 01 <crc32>`.

**Explanation.** See the byte table in [ARCHITECTURE §7](ARCHITECTURE.md#7-fgpb-probe-protocol).
Every Mininet trial now writes `client.metrics.json` next to each probe CSV;
the native lab computes per-phase metrics from `client.csv`.

## 16. Wireshark dissector

**Objective.** Decode FlowGuard payloads as named protocol fields.

**CN concepts.** Protocol dissection, heuristic dissectors, display vs capture filters.

**Commands.**

```bash
wireshark -X lua_script:wireshark/flowguard.lua evidence/m7/flowguard-wireshark-sample.pcapng
tshark -X lua_script:wireshark/flowguard.lua -r evidence/m7/flowguard-wireshark-sample.pcapng -Y flowguard
```

**Expected output.** In the committed sample (captured before binary probes
existed) client packets decode as "FlowGuard legacy text probe seq=N" and
floods as "FlowGuard Mininet lab flood (128 bytes)"; new captures show
"FGPB probe seq=N session=0x… len=64 crc=ok". Real TShark 4.2.2 output
(22 October 2026):

```text
$ tshark -X lua_script:wireshark/flowguard.lua -r evidence/m7/flowguard-wireshark-sample.pcapng \
    -Y flowguard -T fields -e frame.interface_name -e flowguard.kind | sort | uniq -c
   4800 a1-offered	flood
   4800 a2-offered	flood
     90 client-offered	legacy_probe
     90 client-reply-egress	legacy_probe
   1504 victim-received	flood
     90 victim-received	legacy_probe
```

and, for synthetic FGPB packets (Info column, `flowguard.crc_ok`):

```text
FGPB probe seq=7 session=0x1234abcd len=64 crc=ok	True
FGPB probe seq=8 session=0x1234abcd len=64 crc=BAD	False
FGPB flood seq=3 session=0x00000099 len=128 crc=ok	True
FlowGuard native lab a1 phase=attack seq=5
```

The live capture `results/m8-demo-original/flowguard.pcapng` also decodes:
all 270 client probe frames are FGPB probes with a valid CRC. The Wireshark
GUI and profile have not been opened on this branch.

**Explanation.** Full walkthrough, installation and filters in
[WIRESHARK_DEMO](WIRESHARK_DEMO.md#flowguard-lua-dissector).
