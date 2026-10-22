# FlowGuard: complete project explanation

This guide explains the live OpenFlow implementation on the GitHub main branch, from network startup through recovery. For the short setup instructions, see [DEMO.md](DEMO.md). For the measured comparison and its limits, see [RESULTS.md](RESULTS.md).

## 1. Objective and scope

FlowGuard is a small software-defined networking (SDN) lab. Its objective is to detect a sustained, multi-source UDP flood aimed at one victim, install temporary source-specific switch rules that filter it, and check that a predefined client can still use the victim service. SDN means that a controller chooses switch rules while the switch handles matching packets.

The project is an evaluated prototype of established threshold detection and OpenFlow mitigation techniques. It does not introduce a new DDoS algorithm, authenticate users, or claim Internet-scale protection. The default demonstration runs entirely within one private Mininet topology, with no NAT or external network link.

## 2. Terms used in this project

| Term | Meaning here |
| --- | --- |
| Mininet | A network emulator that creates isolated virtual hosts and links on one Linux system. |
| Open vSwitch (OVS) | The software switch named **s1** that forwards or drops packets. |
| OS-Ken controller | The Python application that reads switch statistics and requests rules. |
| OpenFlow 1.3 | The protocol between the controller and OVS. The hosts do not use OpenFlow to contact the victim. |
| UDP | A datagram transport protocol. The lab echo service listens on UDP port **9000**. |
| Flow rule | A switch entry with packet-match fields, a priority, and an action such as forward or drop. |
| Flow counter | The packet and byte totals for a switch rule. Differences between samples give a rate. |
| Packet-in | A packet sent to the controller when the switch needs a forwarding decision. |
| Barrier reply | The switch's acknowledgment that earlier OpenFlow requests were processed in order. It is not, by itself, a measurement that packets were dropped. |
| Hard timeout | A rule lifetime enforced by the switch; the mitigation rules expire after **10 seconds**. |

## 3. The network and each host

~~~text
                    OpenFlow control channel
                 OS-Ken controller (127.0.0.1:6653)
                               |
                         Open vSwitch s1
                /       /       |       \       \
       victim .10  client .11   a1 .21  a2 .22  a3 .23
        UDP :9000    probes      flood   flood   spare lab host
~~~

All five hosts use addresses in **10.0.0.0/24**. The victim is **10.0.0.10**, the client is **10.0.0.11**, and the default flood sources are **10.0.0.21** and **10.0.0.22**. Host **10.0.0.23** participates in topology and connectivity checks but is not a flood source in the default live demo. The topology fixes their MAC addresses and attaches each host to s1. See [lab_topology.py](../topology/lab_topology.py).

The victim runs a UDP echo server: when it receives a request, it sends the same bytes back. The client sends numbered requests and counts a reply only when both its payload and the responding address match. This makes successful replies an observable measure rather than an assumption. See [echo_server.py](../traffic/echo_server.py) and [probe.py](../traffic/probe.py).

## 4. Startup and normal forwarding

The live command starts [demo.py](../experiments/demo.py), which creates a new results directory and starts [run_trial.py](../experiments/run_trial.py). The trial starts the controller, creates Mininet's five hosts and OVS switch, connects s1 to the controller, and verifies every host pair with **20/20 pings**. It starts the victim's echo service, sends initial UDP probes from the client and two source hosts, and saves a pre-attack flow-table dump.

The controller launcher listens only on **127.0.0.1:6653**. On switch connection, the controller removes old rules belonging to this application, installs a default drop and narrow rules that send expected lab ARP, ICMP, and UDP traffic to the controller, and learns forwarding paths. ARP resolves local IP-to-MAC addresses; ICMP supplies the ping checks. Once learned, normal UDP forwarding rules run in OVS at priority **100**, so packets do not need a controller round trip every time. See [run.py](../controller/run.py) and [forwarding.py](../controller/forwarding.py).

The controller checks expected lab MAC/IP consistency for packets it handles and rejects an unexpected learned MAC move. These checks are useful inside the fixed topology, but they are not cryptographic host authentication.

## 5. The default traffic

After the normal checks, **a1** and **a2** each offer **600 UDP packets/s** to **10.0.0.10:9000** for **eight seconds**. Their default application payload is 128 bytes. The client simultaneously sends one echo probe every 100 ms, or about **10 probes/s**, to that same service. The generator is fixed to the lab victim and bounded to at most 2,000 packets/s per source and 30 seconds. See [flood.py](../traffic/flood.py) and [run_trial.py](../experiments/run_trial.py).

These are lab senders with fixed addresses, not a replay of Internet DDoS traffic or spoofed traffic from unrelated machines.

## 6. How the detector decides

Once per second, the controller requests UDP flow statistics for traffic toward the victim IP. The first counter sample establishes a baseline. For later samples, [CounterTracker](../controller/detection.py) uses elapsed monotonic time and computes:

~~~text
source packets/s = (current cumulative packets - previous cumulative packets)
                   / elapsed seconds
~~~

If a counter falls backwards, the tracker treats it as a reset and skips that negative difference. The rates are passed to [TwoWindowDetector](../controller/detection.py). Its current settings are in [detector.json](../config/detector.json):

| Setting | Current rule |
| --- | ---: |
| Counter polling | Every 1 second |
| Victim aggregate rate | Strictly greater than 100 packets/s |
| Each qualifying source | Strictly greater than 30 packets/s |
| Qualifying sources needed | At least 2 |
| Consecutive high observations | 2 |
| Protected source excluded from offender list | 10.0.0.11 |
| Mitigation rule lifetime | 10 seconds |

A source qualifies only when its rate exceeds the source threshold and it is not on the protected-source list. The victim rate must also exceed its threshold. The first qualifying observation makes the detector wait; the next consecutive qualifying observation raises one alert. A low observation resets the consecutive count. This reduces reactions to a single short burst, but a single high-rate source does not meet this project's multi-source policy.

**The client is not independently verified as legitimate.** Address **10.0.0.11** is predefined as protected for this controlled experiment. Its successful probes show continued service, not proof of its identity or harmlessness. A spoofed or compromised protected host is outside the demonstrated security claim.

## 7. What is blocked, and why

The alert names the qualifying source IPs. For each eligible lab source, the controller requests one priority-**200** OpenFlow rule matching:

~~~text
IPv4 + UDP
source IP = identified source, such as 10.0.0.21
destination IP = 10.0.0.10
destination UDP port = 9000
action = drop
hard timeout = 10 seconds
~~~

Priority 200 is above the normal UDP forwarding priority 100. The rule therefore filters matching source-to-service traffic while leaving other forwarding flows, including the protected client's, in place. It does **not** block all hosts in 10.0.0.0/24 or all traffic from an identified source to every destination. The controller excludes the protected client and victim from eligible drop sources. See [drop_match_fields and mitigation in forwarding.py](../controller/forwarding.py).

After the rule requests, the controller records an OpenFlow barrier reply. The saved flow-table dump independently shows the high-priority entries with **actions=drop**, and the switch's drop counters show matching packets. A later sample in the demo displays attacker forwarding at 0 packets/s while the drop counters rise. The victim's receive log and the client's reply CSV provide further observations.

The current counter query covers UDP forwarding flows toward the victim IP; the drop match is narrower because it includes UDP destination port 9000. All default attack traffic is aimed at port 9000. This fixed lab result should not be treated as a general policy for multiple victim services.

## 8. Expiry, recovery, and cleanup

The two flood programs stop after their configured duration. The runner waits long enough for the switch's ten-second hard timeouts. Flow-removed events give the final packet count for each drop rule. The runner saves a recovery flow-table dump and sends **10 more client probes**. The demo analyzer counts any remaining attack drop entries in that saved dump. The runner then stops the traffic processes, echo server, Mininet network, and controller, including when the trial fails. See [run_trial.py](../experiments/run_trial.py) and [analyze.py](../experiments/analyze.py).

An expired rule does not mean that a source is trusted. It means this temporary mitigation ended; a later qualifying flood can be detected and mitigated again.

## 9. What every run saves

A live run creates a fresh **results/demo-YYYYMMDD-HHMMSS/** directory inside the repository:

| Evidence | What to inspect |
| --- | --- |
| **controller.jsonl** | Timestamped counter samples, alert, rule requests, barrier reply, and rule removals. |
| **flows-before.txt** | Switch rules before attack traffic. |
| **flows-during.txt** | Switch rules during mitigation; look for priority 200 and actions=drop. |
| **flows-after-attack.txt** | Switch rules just after the generators finish, before waiting for expiry. |
| **flows-after-recovery.txt** | Recovery flow table; attack drop entries should be absent. |
| **prime-client.csv**, **prime-a1.csv**, **prime-a2.csv** | Initial echo checks before the flood. |
| **client.csv** and **recovery-client.csv** | Each protected-client probe and its result. |
| **victim.jsonl** | Packets received by the victim in measured windows, grouped by source. |
| **attack-a1.jsonl** and **attack-a2.jsonl** | Generator start, stop, rate, and send-count records. |
| **metadata.json** | Trial mode, settings, timestamps, status, and connectivity result. |
| **demo-runner.log** and **controller.log** | Diagnostics if the run fails. |

[analyze.py](../experiments/analyze.py) recalculates summary values from these files. The demo prints important events as they happen and then prints the measured outcome.

## 10. What the controlled comparisons found

The saved M6 comparison used the same two-source, 600-packets/s-per-source, eight-second scenario once with mitigation disabled and once with it enabled. See [RESULTS.md](RESULTS.md), [M6 evidence](../evidence/m6/RESULTS.md), [summary JSON](../results/m6-summary.json), and the [comparison chart](../results/m6-rate-comparison.png).

| Measure | Saved observation |
| --- | --- |
| Alert after source start in the enabled trial | About **1.555 seconds** |
| First barrier reply after source start | About **1.634 seconds** |
| Victim-received attacker rate in matched complete windows after confirmation | About **1,200 packets/s OFF**, **0 packets/s ON** |
| Attacker reduction across the whole attack, including detection delay | About **80.1%** |
| Protected client during attack | **80/80 replies OFF** and **80/80 replies ON** |
| Protected client after attack | **10/10 recovery replies** in each trial |
| Rules after recovery in enabled trial | **0 attack drop rules** |

The post-confirmation 100% reduction and whole-attack 80.1% reduction cover **different time windows**. Neither result establishes improved client availability: the unmitigated client already received every probe. The measured contribution is attribution, selective filtering, continued client replies, rule expiry, and reproducible evidence under these lab conditions.

A separate five-minute normal-traffic baseline recorded **307 controller samples**, no alerts, and no drop requests. Smoke, detection-only, mitigation, repeated-wave, matched-comparison, and clean-export evidence are in the [evidence directory](../evidence/).

## 11. How the animation branch fits

The [offline dashboard branch](https://github.com/Sai181006/FlowGuard/tree/codex/offline-dashboard-and-terminal-demo) provides a presentation interface. Its interactive animation uses generated counter inputs with the detector classes to explain the timeline; it does **not** contact OVS or install OpenFlow rules. Its recorded mode displays saved experiment data. Its separate native localhost gateway can send and filter real UDP datagrams, but that gateway is not the OpenFlow switch used by the main-branch demo.

For a review, use the animation to explain the idea and the main-branch terminal demo to show a fresh Mininet/OpenFlow run. Do not describe modeled values, saved trials, or localhost gateway drops as measurements from the current live switch run.

## 12. Run the live demo

On the current Windows review computer, open the main-branch checkout in VS Code and paste this into its PowerShell terminal:

~~~powershell
wsl -d Ubuntu -u root --cd 'C:\Users\Sai\Documents\ChatGPT\cn_project\m7_publish' --exec python3 experiments/demo.py
~~~

The **cn_project** directory on this computer is a Windows junction to the original workspace, so it uses the same files while avoiding a space in the typed command. On another machine, use that machine's actual checkout path. From the repository root in Ubuntu, the portable form is:

~~~bash
sudo python3 experiments/demo.py
~~~

The run prints five phases: **BASELINE**, **FLOOD**, **DETECT AND BLOCK**, **RECOVERY**, and **REVIEW SUMMARY**. The eight-second flood is only part of the run; setup, rule expiry, recovery probes, and cleanup take additional time. Run one trial at a time because trials share one switch name and controller port.

For a quick evidence inspection in the same VS Code PowerShell terminal, after the demo finishes:

~~~powershell
$run = Get-ChildItem .\results -Directory -Filter 'demo-*' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Select-String -Path (Join-Path $run.FullName 'flows-during.txt') -Pattern 'cookie=0xdd05000000000005'
Select-String -Path (Join-Path $run.FullName 'flows-after-recovery.txt') -Pattern 'cookie=0xdd05000000000005'
~~~

The first search should show two attack drop entries. The second should show no attack drop entries. The cookie identifies FlowGuard's drop-rule type. See [DEMO.md](DEMO.md) for Ubuntu commands to analyze a run and repeat the OFF/ON comparison.

## 13. Suggested three-person review sequence

1. **Codebase speaker:** Explain the five-host topology, controller, counter-rate calculation, detector settings, and specific OpenFlow match fields.
2. **Animation speaker:** Show normal traffic, a first high window, a second high window and alert, filtering, and expiry. Label this view as explanatory simulation.
3. **Terminal speaker:** Run the command above and point to the live baseline, measured rate, source attribution, rule requests, barrier reply, drop counter sample, client replies, and zero rules after recovery.

The terminal speaker can say:

> “The animation showed the logic. Here, a real Mininet switch and controller are running locally. The controller first verifies normal connectivity, then two hosts each send 600 UDP packets per second while the protected client keeps probing the same victim. One high counter window makes the detector wait; the next raises an alert for both source IPs. The controller requests ten-second source-specific drop rules. The barrier reply shows those requests were processed, and the following switch counters show attacker forwarding falling to zero while drop-rule matches rise. After the senders stop, the rules expire, the client succeeds again, and no attack drop rules remain. This proves selective filtering in our lab. It does not prove improved availability because the OFF trial also returned every client reply.”

Read the latency and blocked-packet numbers from the current run rather than memorizing one rehearsal; those values vary with scheduling.

## 14. Limits to state clearly

- The protected client is an **allowlisted lab IP**, not an authenticated human or a behavior-based legitimacy decision. Source spoofing and a compromised protected host are outside the demonstrated protection.
- The policy specifically seeks a **multi-source UDP flood**. A single high-rate source, a short burst, TCP attacks, other victim services, multiple switches, and public-network traffic are outside this tested scenario.
- The lab did not saturate the echo service enough to cause client probe loss without mitigation. It therefore does not support a claim of improved availability.
- All measurements come from one WSL host, one private switch, fixed IPs, and bounded generators. They do not establish production-scale performance.
- The dashboard animation is a model; the saved M6 comparison is historical measurement; each new terminal run is a separate live measurement. Keep these evidence types distinct.

These boundaries are part of the result, not a failure to report. They make the claim specific and reproducible.

## 15. Codebase and validation map

| Area | Main files | Purpose |
| --- | --- | --- |
| Topology | [lab_topology.py](../topology/lab_topology.py) | Defines the five hosts, one OVS switch, and fixed addresses. |
| Controller launch | [run.py](../controller/run.py) | Starts the OS-Ken application on the lab's loopback control port. |
| Switch behavior | [forwarding.py](../controller/forwarding.py) | Learns forwarding, polls flow statistics, requests drops, and logs rule lifecycle events. |
| Rate calculation and decision | [detection.py](../controller/detection.py), [detector.json](../config/detector.json) | Converts cumulative counters to rates and applies the two-window policy. |
| Traffic | [echo_server.py](../traffic/echo_server.py), [probe.py](../traffic/probe.py), [flood.py](../traffic/flood.py) | Runs the victim service, measures client replies, and sends bounded source traffic. |
| Live demonstration | [demo.py](../experiments/demo.py), [run_trial.py](../experiments/run_trial.py) | Runs one mitigated trial, narrates it, saves files, and cleans up. |
| Analysis | [analyze.py](../experiments/analyze.py), [summarize.py](../experiments/summarize.py) | Recalculates trial metrics and the saved comparison summary. |
| Checks and evidence | [unit tests](../tests/), [controller smoke test](../topology/controller_smoke.py), [milestone evidence](../evidence/), [raw results](../results/) | Check logic, live controller connectivity, trial outcomes, and reproducibility. |

From an Ubuntu repository root, the two quick checks are:

~~~bash
python3 -m unittest discover -s tests -v
sudo python3 topology/controller_smoke.py
~~~

The unit tests exercise detector and forwarding logic. The controller smoke test exercises a live switch connection, host connectivity, UDP flows, and reconnection. The bounded experiment and saved evidence then test the full detection-to-recovery sequence.

## 16. Advanced networking extensions (pointer)

This guide explains the original project. The `feature/advanced-networking`
additions — EWMA, CUSUM and entropy detectors; OpenFlow 1.3 meter rate
limiting with fallback to drop; graduated response and back-off; a Mininet
HTB/netem bottleneck and a native userspace bottleneck; the FGPB binary probe
with RFC 3550 jitter; and the Wireshark Lua dissector — are documented in:

- [ARCHITECTURE.md](ARCHITECTURE.md): components, schemas, math and OpenFlow message sequences
- [SCENARIOS.md](SCENARIOS.md): what to run and how to explain it
- [TESTING.md](TESTING.md): tests, Linux setup, verified vs not verified
- [RESULTS.md](RESULTS.md#m9-advanced-results): measured native results and the detector benchmark

Sections 1–15 above remain accurate for the default configuration, which
reproduces the original behaviour exactly.
