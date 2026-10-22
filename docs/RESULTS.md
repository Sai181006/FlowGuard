# FlowGuard controlled experiment results

**Run date:** 13 October 2026. **Scope:** one private Mininet switch, five hosts, one UDP echo service. All numerical outcomes below come from raw files in `results/`; [M4](../evidence/m4/RESULTS.md) and [M5](../evidence/m5/RESULTS.md) record the earlier milestone trials.

## Reproduce and inspect

Run as root in Ubuntu WSL from the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 experiments/run_trial.py --mode baseline --output results/new-baseline
python3 experiments/run_trial.py --mode attack-off --output results/new-off --pps 600 --duration-s 8
python3 experiments/run_trial.py --mode attack-on --output results/new-on --pps 600 --duration-s 8
python3 experiments/analyze.py results/new-off results/new-on
```

The checked-in runs are `m4-baseline`, `m6-attack-off`, and `m6-attack-on`. `python3 experiments/summarize.py` regenerates `results/m6-summary.json` and `results/m6-rate-comparison.svg` from those files. `experiments/render_chart_png.py` regenerates the PNG chart when Pillow is available.

The controller writes timestamped JSONL samples, alerts, rule requests, barrier confirmations and removals. The victim writes per-second receive counts by source. The client writes every probe result to CSV. Each trial also saves flow-table dumps, generator start/stop records and metadata. Files ending in `.log` are local diagnostics and are not required to recalculate the reported metrics.

## Environment and traffic settings

Ubuntu 26.04 LTS in WSL2; kernel `6.18.33.2-microsoft-standard-WSL2`; Python 3.14.4; Mininet `2.3.0-1.1build1`; Open vSwitch `3.7.1-2`; OS-Ken `4.1.1-1ubuntu2`. WSL saw a 12th Gen Intel Core i5-12450HX with 12 logical CPUs and 7,981,708 kB of total guest memory. The topology had no NAT or external link. The controller used one-second polls, a 100-packets/s victim threshold, a 30-packets/s source threshold, two consecutive high windows, and 10-second mitigation rules.

The matched attacks used two hosts at 600 packets/s each for eight seconds, 128-byte application payloads, and one client echo probe every 100 ms. The generator can only target `10.0.0.10:9000` and limits each host to 2,000 packets/s for at most 30 seconds. No random payload or random source selection was used, so a seed was unnecessary.

## Results against the project targets

| Measure | Project target | Observed | Outcome |
| --- | ---: | ---: | --- |
| Normal service | At least 95% of 100 probes | Client 600/600; second benign sender 600/600 | Met |
| False mitigations during at least 5 min normal traffic with a short two-source burst | 0 | 0 alerts and 0 drop requests across 307 controller samples | Met |
| Two-source alert latency | At most 5 s | 1.555 s from earliest generator start record | Met |
| Source attribution | Both sources identified | `10.0.0.21` and `10.0.0.22` | Met |
| Mitigation activation | Record switch confirmation | Barrier reply at 1.634 s | Recorded |
| Victim-received attacker rate after activation | At least 90% lower than unmitigated matched windows | 1,199.956 packets/s off vs 0 packets/s on, 100% reduction | Met |
| Legitimate service during mitigated attack | At least 95% probe success | 80/80, or 100% | Met |
| Attack rule recovery | No drop rules within 15 s after attack | Both expired about 3.6 s after attack end; none in recovery flow table | Met |

The reduction compares complete one-second victim windows starting at least 0.5 seconds after the mitigation barrier, at the same relative times in the disabled trial. Across *all* complete attack windows, including the detection delay, the observed attacker rate was 1,200.023 packets/s without mitigation and 239.244 packets/s with mitigation, an approximately 80.1% whole-trial reduction. These are different measures and should not be interchanged.

![Victim-received attacker rate in matched trials](../results/m6-rate-comparison.png)

## Interpretation and limitation

The defender removed attacker traffic from the victim after switch confirmation while retaining the legitimate client's service. The unmitigated client also succeeded 80/80 times at 1,200 aggregate attacker packets/s. An exploratory bounded maximum-load trial at 2,000 packets/s from each attacker (about 4,000 packets/s total) still produced 80/80 client replies without mitigation. Therefore these experiments do **not** show improved service availability. They show selective filtering, attribution, timely rule installation and recovery under the stated lab conditions. A different bottleneck or service model would be needed to test availability improvement.

The generator start timestamp is logged immediately before the first packet is sent, so latency is an approximation to first-packet latency. The trials share one WSL host and one switch, and do not establish internet-scale performance, cross-machine robustness, or false-positive rates for untested traffic patterns. Raw files and the analyzer make these exact claims auditable.

The review command in [DEMO.md](DEMO.md) reproduces one mitigated trial and prints each stage live. Its clean-source rehearsal is recorded in [M7 evidence](../evidence/m7/RESULTS.md); the M6 matched trials above remain the comparison used for the report.

## M9 advanced results

**Run date:** 21 October 2026. **Scope:** the native localhost lab
(`demo/live_lab.py`, real UDP on 127.0.0.1, Python gateway enforcement and an
emulated userspace bottleneck — no OpenFlow switch, no kernel qdisc) and the
offline detector benchmark (simulation). Every number below is copied from
`results/m9-native-*/**/summary.json` and `comparison.json`, or from
`results/benchmarks/detector-benchmark.json`; the run list and commands are in
[M9_NATIVE_EVIDENCE.md](../results/M9_NATIVE_EVIDENCE.md). Environment: Ubuntu
24.04, Python 3.12.3. Common settings: two sources at 600 packets/s for an
8-second attack, client probes every 100 ms, 10-second rules.

### Native availability under a bottleneck

Bottleneck = 300 packets/s service, 50-packet queue. "Attack-phase" metrics
use only the 80 client probes sent during the 8-second attack.

| Run (`results/…`) | Detector / response / queue | OFF client loss | ON client loss | OFF RTT p95 | ON RTT p95 | Queue drops OFF → ON | Alert at |
|---|---|---:|---:|---:|---:|---:|---:|
| `m9-native-original-final` (no bottleneck) | threshold / drop / — | 0.0 % | 0.0 % | 0.591 ms | 0.699 ms | — | 4.00 s |
| `m9-native-bottleneck` | threshold / drop / FIFO | 71.25 % | 23.75 % | 166.665 ms | 5.185 ms | 7,231 → 1,773 | 4.00 s |
| `m9-native-ratelimit` | threshold / rate_limit 20 pps / FIFO | 82.5 % | 25.0 % | 167.905 ms | 4.836 ms | 7,231 → 1,802 | 4.00 s |
| `m9-native-red-ewma-warm` | EWMA / drop / RED | 81.25 % | 20.0 % | 110.123 ms | 87.021 ms | 7,251 → 1,792 | 7.00 s |
| `m9-native-cusum` | CUSUM / drop / FIFO | 87.5 % | 20.0 % | 167.802 ms | 166.148 ms | 7,231 → 1,774 | 7.00 s |
| `m9-native-entropy` | entropy / drop / FIFO | 80.0 % | 22.5 % | 167.894 ms | 5.476 ms | 7,229 → 1,772 | 7.00 s |

Alert times are seconds after measurement start; the attack starts at 2 s for
the threshold runs and at 5 s for the adaptive detectors (longer baseline so
their 3-window warm-up completes), so every detector alerted 2 s after the
attack began. All 13 mode runs have `validation_status: passed`, and every
bottleneck comparison reports `availability_improved: true` (at least 10
points less attack-phase loss with mitigation ON).

Queueing: FIFO attack-phase queue delay p95 was 166.5 ms in every FIFO run,
matching the theoretical maximum 50/300 s = 166.7 ms. RED kept it at
106.7 ms p95 (p50 100.1 ms ≈ max_th/μ = 30/300 s) but did not reduce loss.
Whole-trial gateway drops with mitigation ON were 7,196–7,198 datagrams for
drop rules and 6,920 policed datagrams for the 20 pps token bucket (139
datagrams per source passed).

**Interpretation.** Unlike the M6 Mininet trials, these runs *do* show improved
client availability — but under an emulated userspace bottleneck on one host.
The residual ON loss (20–25 %) is the price of detection delay: the client is
congested for the two windows before the alert. The RTT p95 of the CUSUM ON
run stays at 166 ms because more than 5 % of its received attack-phase probes
were delayed in that pre-detection interval. Detector differences here are
in alert timing only; all four caught this plain flood.

### Graduated response with back-off (native)

`m9-native-graduated-waves` (mitigation ON only, three 8-second waves, 6 s
gaps, `--action graduated --backoff`, FIFO bottleneck): offense 1 → 10 s
token-bucket rate limit (alert 4.00 s), offense 2 → 20 s drop (alert 18.01 s);
the third wave (30–38 s) fell inside the 20 s drop, so only 2 alerts. Client
attack-phase loss 15.417 % of 240 probes; 0 % in gaps, expiry-wait and
recovery. Per source: 14,430 offered, 147 passed and 3,461 policed by the
bucket, 11,868 dropped in total.

### Detector benchmark (simulation)

20 seeds (base 1729), 600 pps per attacker, Poisson-noised per-second
counters through the real detector classes, mitigation off. Attack rows:
share of runs alerting (median latency from attack start); benign rows: runs
with any alert. Full tables, attribution counts and ROC sweep:
[detector-benchmark.md](../results/benchmarks/detector-benchmark.md).

| Scenario | threshold | EWMA | CUSUM | entropy |
|---|---|---|---|---|
| normal (benign) | FP 0/20 | FP 0/20 | FP 0/20 | FP 0/20 |
| burst (benign) | FP 0/20 | FP 0/20 | FP 0/20 | FP 0/20 |
| sustained, waves, three-source, repeat-offender | 100 % (2 s) | 100 % (2 s) | 100 % (2 s) | 100 % (2 s) |
| single-source | 0 % | 100 % (2 s) | 100 % (2 s) | 100 % (2 s) |
| low-rate | 40 % (13 s) | 100 % (2 s) | 100 % (2 s) | 100 % (2 s) |
| pulsing | 0 % | 0 % | 100 % (3 s) | 0 % |
| ramp | 100 % (8 s) | 55 % (5 s) | 100 % (3 s) | 10 % (5 s) |
| flash-crowd (benign) | FP 20/20 | FP 15/20 | FP 20/20 | FP 0/20 |

Shipped operating points (TPR over all attack runs / FPR over benign runs):
threshold 0.675 / 0.333, EWMA 0.819 / 0.250, CUSUM 1.000 / 0.333, entropy
0.762 / 0.000. No detector wins every row; the threshold detector's 40 %
low-rate detection exists only because noise sometimes lifts 90 pps above
the 100 pps victim threshold.

### M8 live Mininet / Open vSwitch runs

**Run date:** 22 October 2026. **Environment:** Ubuntu 24.04.3, Mininet
2.3.0, Open vSwitch 3.3.9, OS-Ken 4.1.1, TShark 4.2.2, run as root with the
repository `.venv` (`--system-site-packages`). All four folders are committed
(force-added; `results/m8-*` is otherwise git-ignored). Numbers below were
read from each folder's `metadata.json`, `controller.jsonl`,
`capture-summary.json`, `qdisc-*.json`, `*.metrics.json` and from
`.venv/bin/python experiments/analyze.py <folders>`. Every run has
`validation.status: passed`. The Mininet client probe uses `--mode stream`
whenever a bottleneck is configured (`metadata.json: probe_mode`).

| Run | Command |
|---|---|
| `m8-demo-original` | `sudo .venv/bin/python experiments/demo.py --pcap --output results/m8-demo-original` |
| `m8-bottleneck-compare` | `sudo .venv/bin/python experiments/demo.py --bottleneck --compare --pcap --output results/m8-bottleneck-compare` |
| `m8-meter-on` | `sudo .venv/bin/python experiments/run_trial.py --mode attack-on --bottleneck-mbit 0.5 --queue-packets 50 --mitigation-action rate_limit --output results/m8-meter-on` |
| `m8-cusum-graduated-waves` | `sudo .venv/bin/python experiments/run_trial.py --mode mitigation-repeat --bottleneck-mbit 0.5 --queue-packets 50 --detector cusum --mitigation-action graduated --backoff --output results/m8-cusum-graduated-waves` |

**Original behaviour regression (`m8-demo-original`, no bottleneck).** Alert
1.838 s and barrier confirmation 1.839 s after the first generator start;
the two drop rules counted 3,737 (`10.0.0.21`) + 3,733 (`10.0.0.22`) =
7,470 packets before removal; client 80/80 during the attack (RTT p95
0.545 ms) and 10/10 after recovery; no drop rule left after recovery. Capture
`flowguard.pcapng`: a1-offered 4,800, a2-offered 4,800, client-offered 90,
victim-received 2,294, client-reply-egress 90. TShark 4.2.2 with
`wireshark/flowguard.lua` decoded all 270 client probe frames (90 offered, 90
at the victim, 90 replies) as FGPB probes with a valid CRC32.

**Availability under the kernel bottleneck (`m8-bottleneck-compare`).** The
victim link `s1-eth1` was verified before and after each run as an `htb` root
(`5:`) with a `netem` leaf (`10:`, `limit 50`). Threshold detector, drop rules,
two sources at 600 packets/s for 8 s:

| Attack-phase measure | Mitigation OFF | Mitigation ON |
|---|---:|---:|
| Client probe loss (80 probes) | 70.0 % (24 received) | 25.0 % (60 received) |
| Client RTT p95 | 136.248 ms | 0.573 ms |
| Client RFC 3550 jitter | 2.577 ms | 0.502 ms |
| `s1-eth1` qdisc drops (root HTB, monitored phase) | 6,677 | 1,721 |
| Max backlog | 8,500 B / 50 packets | 8,500 B / 50 packets |
| Mean backlog | 3,134.7 B | 786.7 B |
| Attacker pps at the victim, from 2.609 s after attack start | 365.8 | 0.0 |
| Alert / rule confirmation after attack start | 2.117 s / — | 2.107 s / 2.109 s |
| Capture: victim-received (all) / client replies | 3,017 / 34 | 904 / 70 |
| Recovery probes | 10/10 | 10/10 |

`analyze.compare` reports a 45.0-point loss reduction, `improved: true`. The
measurements match the sizing in `topology/lab_topology.py`: 0.5 Mbit/s
carries ≈367 frames/s of 170 bytes (measured 365.8 pps of attack traffic at
the victim), the queue holds 50 × 170 = 8,500 bytes (measured max backlog),
and the worst queueing delay is ≈136 ms (measured RTT p95 136.2 ms). The
residual ON loss happens in the ≈2 s before the second high window.

![Mininet bottleneck availability, mitigation OFF vs ON](../results/m8-bottleneck-compare/availability-comparison.png)

**OpenFlow 1.3 meters on Open vSwitch (`m8-meter-on`).** `meter_features`:
supported, `max_meter` 200000, `band_types` 2, `capabilities` 15. Meters
1021 and 1022 (20 packets/s, burst 20) and their metered flows were confirmed
by one barrier; the saved flow table shows
`priority=200,udp,in_port=3,dl_src=02:00:00:00:00:21,dl_dst=02:00:00:00:00:10,nw_src=10.0.0.21,nw_dst=10.0.0.10,tp_dst=9000 actions=meter:1021,output:1`.
Meter band drops totalled 6,735 (3,367 + 3,368); the metered flows matched
3,520 and 3,521 packets before `ratelimit_removed` (reason 1, hard timeout),
so ≈153 packets per source passed the meter — consistent with a token bucket
of 20 packets/s plus a 20-packet burst over the ≈6.6 s of policed attack.
Client attack-phase loss 20.0 % (RTT p95 135.707 ms, from probes queued
before the meters took effect); root-qdisc drops 1,791; recovery 10/10; no
fallback. During the run the operator also observed
`ovs-ofctl -O OpenFlow13 dump-meters s1` print
`meter=1021 pktps burst stats bands= type=drop rate=20 burst_size=20`, and
`meter-stats` 2.7 s after installation report `packet_in_count` 1619 with
1546 band drops (that console output is not saved in the run folder).

**CUSUM + graduated response with back-off (`m8-cusum-graduated-waves`).**
Two 8-second waves. Wave 1: CUSUM alert 2.200 s after the wave started
(score 9.0 for both sources) → meter rate limit, 10 s, offense 1; 6,686 meter
band drops; the metered flows matched 3,771 packets each and expired by hard
timeout; client 67/80 (16.25 % loss). Wave 2: CUSUM alert 2.103 s after the
wave started → drop rules, **20 s** (offense 2, back-off factor 2),
confirmed 2.105 s after the wave started; client 60/80 (25.0 % loss, RTT p95
0.767 ms). The drop rules matched 3,593 and 3,537 packets. Because the 20 s
rule outlives the runner's 12 s post-wave wait, the final flow dump still
contains the 2 drop rules and they were removed with reason 2 (delete) at
teardown, not by timeout. The recovery probe still got 10/10, since the rules
match only the attackers.

**What remains unmeasured live:** meter fallback to drop (this OVS supports
meters, so the error path was not exercised), Mininet RED (`--qdisc red`),
capture of the OpenFlow control channel on port 6653, and the Wireshark GUI
profile.
