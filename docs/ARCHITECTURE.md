# FlowGuard architecture

This document describes how FlowGuard is built: which component does what,
how data moves through each of the three runtimes, the configuration and
event formats, the probe wire format, the detector and queue mathematics, and
the exact OpenFlow message sequences. Every statement here was checked against
the source files named in each section. Behaviour that was observed in the
live Mininet/OVS runs of 22 October 2026 (`results/m8-*`, see
[RESULTS](RESULTS.md#m8-live-mininet--open-vswitch-runs)) is marked as
measured; behaviour that has still not been exercised live (meter fallback,
Mininet RED, OpenFlow control-channel capture) is labelled as such.

Related documents: [README](../README.md) (overview), [SCENARIOS](SCENARIOS.md)
(what to run), [TESTING](TESTING.md) (what is verified), [RESULTS](RESULTS.md)
(measured numbers), [WIRESHARK_DEMO](WIRESHARK_DEMO.md) (packet view).

---

## 1. Component diagram

```text
                    +---------------------------- shared, OS-independent core ----------------------------+
                    |  controller/lab.py        fixed lab identities (IPs, MACs, switch ports, 10.0.0.10:9000) |
                    |  controller/config.py     JSON schema, defaults, validation, overrides, SHA-256 digest   |
                    |  controller/detection.py  CounterTracker (counters -> rates), TwoWindowDetector          |
                    |  controller/detectors.py  EWMA, CUSUM, entropy (KL) detectors + build_detector()        |
                    |  controller/mitigation.py TokenBucket, OffenderHistory (back-off), choose_action()      |
                    |  demo/scenarios.py        11 traffic scenarios, seeded Poisson noise                    |
                    |  demo/queueing.py         BottleneckQueue (D/1, FIFO or RED), FluidQueue                |
                    |  traffic/probe_protocol.py FGPB wire format, percentiles, RFC 3550 jitter, ProbeStats    |
                    +-------------+-----------------------------+-----------------------------+-------------+
                                  |                             |                             |
        +-------------------------v------+   +------------------v-------------+   +-----------v------------------+
        | RUNTIME A: dashboard / model   |   | RUNTIME B: native localhost lab |   | RUNTIME C: Mininet + OVS     |
        | (any OS, stdlib only)          |   | (any OS, stdlib only)           |   | (Linux, root, OS-Ken)        |
        |                                |   |                                 |   |                              |
        | dashboard/index.html, app.js   |   | demo/live_lab.py                |   | experiments/demo.py          |
        |   D3 (vendored), no CDN        |   |   LivePolicy (detector+policy)  |   |   -> experiments/run_trial.py|
        | demo/server.py  127.0.0.1:8765 |   |   Gateway (UDP proxy :19001)    |   |      topology/lab_topology.py|
        | demo/engine.py  simulate()     |   |   BottleneckQueue (optional)    |   |      controller/run.py :6653 |
        | demo/terminal.py, demo/run.py  |   | traffic/echo_server.py :19000   |   |      controller/forwarding.py|
        |                                |   | traffic/probe.py (client)       |   |      controller/meters.py    |
        | NO packets; generated counters |   | REAL UDP on 127.0.0.1           |   |      traffic/*.py in hosts   |
        | through the real detectors     |   | userspace enforcement + queue   |   |      packet_capture.py       |
        +--------------------------------+   +---------------------------------+   |      qdisc_monitor.py        |
                                                                                   | REAL UDP in namespaces, real |
        experiments/benchmark_detectors.py  (offline, deterministic, simulated)    | OVS flow table, real qdisc   |
        experiments/analyze.py, summarize.py, render_*_png.py (post-processing)    +------------------------------+
        wireshark/flowguard.lua + wireshark/FlowGuard/ profile (packet decoding)
```

The core modules have **no OS-Ken or Mininet imports** (`controller/lab.py`
says so explicitly), which is why the dashboard, the native lab and the
benchmark can run on Windows or macOS with only the Python standard library,
while sharing the exact detector and policy code the OpenFlow controller uses.

---

## 2. Who implements what

A frequent evaluation question is "which part did *you* write, and which part
is the operating system or switch doing?" This table is the honest answer.

| Function | Implemented by | FlowGuard's role |
|---|---|---|
| UDP/IPv4 sending and receiving, checksums, sockets | Linux / Windows / macOS kernel network stack | Opens sockets, chooses payloads and rates (`traffic/*.py`, `demo/live_lab.py`) |
| Loopback interface (`lo`, Npcap loopback adapter) | Kernel | Native lab binds everything to `127.0.0.1` |
| Network namespaces (one per Mininet host), veth pairs | Linux kernel, created by Mininet | Defines the 5-host topology (`topology/lab_topology.py`) |
| OpenFlow 1.3 TCP session, message framing and (de)serialisation | OS-Ken library | Builds every FLOW_MOD / METER_MOD / BARRIER / MULTIPART request and handles replies (`controller/forwarding.py`, `controller/meters.py`) |
| Flow-table lookup, per-flow packet/byte counters, `actions=drop` | Open vSwitch datapath | Chooses matches, priorities, cookies, timeouts |
| Hard/idle timeouts and FLOW_REMOVED messages | Open vSwitch | Sets `hard_timeout` and `OFPFF_SEND_FLOW_REM`, logs removal |
| Meter (token-bucket) policing in packets/s | Open vSwitch meter table | Sends `OFPMeterMod` with one `OFPMeterBandDrop`; parses meter stats |
| Bottleneck rate limiting (HTB), packet FIFO (netem `limit`), RED | Linux traffic control (`sch_htb`, `sch_netem`, `sch_red`), configured by Mininet `TCLink` | Requests the shaping parameters, verifies the qdisc tree with `tc -s -j qdisc show`, samples counters (`experiments/qdisc_monitor.py`) |
| Packet capture taps | Linux `AF_PACKET` sockets (`ETH_P_ALL`) | `experiments/packet_capture.py` writes its own pcapng (no tcpdump/dumpcap needed) |
| Packet decoding in Wireshark | Wireshark + FlowGuard Lua dissector | `wireshark/flowguard.lua` decodes FGPB headers and the text payloads |
| Counter-to-rate conversion, detection, attribution | **FlowGuard** | `controller/detection.py`, `controller/detectors.py` |
| Response policy (drop / rate-limit / graduated, back-off) | **FlowGuard** | `controller/mitigation.py`, `_mitigate()` in `forwarding.py` |
| Native enforcement (drop, token bucket) and emulated bottleneck queue | **FlowGuard** (Python userspace) | `demo/live_lab.py`, `demo/queueing.py` — not a kernel qdisc, not OVS |
| Probe protocol, loss/RTT/jitter statistics | **FlowGuard** | `traffic/probe_protocol.py`, `traffic/probe.py` |
| Dashboard model and animation | **FlowGuard** (Python + D3) | `demo/engine.py`, `dashboard/` |

### Real traffic versus simulation

| Runtime | Packets on a wire? | Enforcement | Queue | Use it to claim |
|---|---|---|---|---|
| Dashboard interactive model, `demo/run.py --scenario detector`, benchmark | **No** — generated per-second counters | Modelled | `FluidQueue` (rate model) | How the detector logic behaves; trade-offs between detectors |
| Dashboard "recorded experiment" | No (replays saved M6 files) | Historical OVS rules | none | What the 13 October 2026 Mininet trials measured |
| Native lab `demo/live_lab.py` | **Yes**, real UDP on 127.0.0.1 | Python gateway (really discards datagrams) | `BottleneckQueue` in userspace (really delays/drops datagrams) | Detection, selective filtering, availability under an *emulated* bottleneck |
| Mininet `experiments/demo.py` / `run_trial.py` | **Yes**, real UDP between namespaces | Open vSwitch flow table / meters | Linux HTB + netem qdisc | End-to-end SDN behaviour |

---

## 3. Data flow per runtime

### 3.1 Mininet / OVS controller loop (runtime C)

```text
 hosts a1,a2 (flood.py)  client (probe.py)          victim (echo_server.py)
        |                       |                          ^
        v                       v                          |  s1-eth1 egress
 +-------------------------- OVS s1 ---------------------------+  [HTB rate + netem FIFO]
 | table 0: punt(5) < control(20) < UDP fwd(100) < mitig.(200) |  (only with --bottleneck)
 +------------------------------+------------------------------+
         ^  FLOW_MOD/METER_MOD  |  MULTIPART_REPLY (flow stats, meter stats),
         |  BARRIER_REQUEST     |  BARRIER_REPLY, ERROR, FLOW_REMOVED, PACKET_IN
         |                      v
 +--------------------- controller/forwarding.py (OS-Ken, 127.0.0.1:6653) ---------------------+
 | _monitor(): every poll_interval_s send OFPFlowStatsRequest(cookie 0xdd05..., mask 0xffff...,|
 |             match udp, ipv4_dst 10.0.0.10, udp_dst 9000) [+ OFPMeterStatsRequest if meters] |
 | flow_stats_handler(): keep cookie ..03 flows -> FlowCounter -> CounterTracker.sample()      |
 |    -> rates {source_pps, victim_pps, counter_resets}                                         |
 |    -> detector.observe(rates) -> event "sample" (with detector_state, drop/ratelimit deltas)|
 |    -> alert? event "alert" -> _mitigate(): OffenderHistory.next_offense -> choose_action    |
 |       -> drop FLOW_MOD | METER_MOD + metered FLOW_MOD -> BARRIER_REQUEST                    |
 | error_handler()/barrier_handler(): confirm, or fall back to drop                             |
 | flow_removed_handler(): drop_removed / ratelimit_removed                                     |
 +-------------------------------------+-------------------------------------------------------+
                                       | JSON lines (FLOWGUARD_EVENTS=<trial>/controller.jsonl)
                                       v
 experiments/demo.py tails controller.jsonl and prints ALERT / RULE / BLOCK / RATE-LIMIT /
 METER-FALLBACK / METER / EXPIRE lines; experiments/analyze.py recomputes latency, counts,
 client loss, qdisc drops and the OFF/ON availability table from the saved files.
```

Step by step:

1. `run_trial.py` writes `effective-config.json` (the validated configuration
   with command-line overrides applied) and starts `controller/run.py` with
   `FLOWGUARD_CONFIG`, `FLOWGUARD_EVENTS` and `FLOWGUARD_MITIGATION=0|1`.
2. Mininet builds `DDoSTopo` (optionally with a `TCLink` on the victim link)
   and connects OVS `s1` to the controller at `127.0.0.1:6653`.
3. On `EventOFPSwitchFeatures` the controller deletes its old flows (by cookie
   range), deletes all meters, asks for meter features, installs the table-miss
   drop and the identity-bound punt rules, then logs `switch_connected`.
4. The first packet of each permitted host flow is punted (PACKET_IN), checked
   against the fixed MAC/IP/port identity, and a forwarding flow is installed
   (UDP to `10.0.0.10:9000` gets cookie `...03`, priority 100, idle timeout 30 s).
5. Every `poll_interval_s` (1 s) the controller requests flow statistics. Only
   cookie `...03` forwarding flows feed the detector; drop (`...05`) and
   rate-limit (`...06`) counters are reported separately. While a mitigation
   rule is installed it takes the source's packets, so the detector sees that
   source at 0 pps.
6. An alert triggers `_mitigate()`, which installs one timed rule per new
   offender and confirms the batch with a barrier (section 9).
7. When an alert episode is active, every later window re-runs
   `_mitigate()` with the detector's current `qualifying_sources`, so a newly
   qualifying source or a source whose rule expired is handled promptly.
8. Whenever a bottleneck is configured, `run_trial.py` starts every client
   probe with `--mode stream` (a fixed 10-probes/s schedule) and records
   `probe_mode` in `metadata.json`. Stop-and-wait probing would stall 500 ms
   on every lost reply and drift out of the attack window; this was found in
   the first live bottleneck run and fixed in commit 1b15847.

### 3.2 Native localhost lab (runtime B)

```text
 a1 :19021 --flowguard:a1:<phase>:<seq>:<ns>.... (128 B text) --+
 a2 :19022 --flowguard:a2:...  ---------------------------------+--> gateway :19001 (frontend socket)
 client :19011 -- FGPB probe, 64 B (traffic/probe.py) ----------+        |
                                                                         | LivePolicy.classify(source)
                                                                         |   FORWARD | DROP | RL_PASS | RL_DROP
                                                                         v
                                          [optional BottleneckQueue: service_pps, queue_packets, fifo|red]
                                                                         |   QUEUE_TAIL_DROP | QUEUE_RED_DROP
                                                                         v
                                                       backend :19002 --> echo_server :19000
                                                                         |
            client/attacker <-- gateway :19001 <-- backend :19002 <------+ (echo matched by payload)

 every poll_interval_s: CounterTracker on the gateway's *forwarded* counts -> detector.observe()
   -> alert -> LivePolicy.install(): OffenderHistory + choose_action -> drop rule or TokenBucket
```

* Ports come from `PORT_OFFSETS` in `demo/live_lab.py` (base 19000): victim
  +0, gateway +1, backend +2, client +11, a1 +21, a2 +22. The source port is
  mapped to a **logical** identity (`10.0.0.11/.21/.22`) so the same detector
  configuration applies. On the wire every packet is `127.0.0.1`.
* "Forwarded" is counted where an OpenFlow flow counter would count it —
  before the bottleneck queue — so the detector input matches the SDN case.
* Phases: baseline (2 s, or longer for adaptive detectors so warm-up completes),
  attack (`--duration-s`, optionally `--waves` 1–3 with 6 s gaps),
  expiry-wait (longest rule timeout + 1 s), recovery (2 s).
* With a bottleneck the probe runs in `--mode stream` (fixed 100 ms schedule)
  so a lossy phase is sampled evenly; without one it uses stop-and-wait.
* Output per mode: `summary.json`, `events.jsonl`, `client.csv`,
  `victim.jsonl`, `packets.csv` (per datagram), logs; `comparison.json` for
  `--mitigation compare`.

### 3.3 Dashboard engine (runtime A)

```text
 browser (dashboard/app.js + vendored D3)
   GET  /api/bootstrap            -> configuration, scenario list, detector/action catalogue, CSRF token
   GET  /api/simulation?scenario=&mitigation=&pps=&capacity=&victim_pps=&source_pps=
                        &min_sources=&consecutive_windows=&detector=&action=&backoff=
                        &rate_limit=&queue=
   GET  /api/benchmark            -> results/benchmarks/detector-benchmark.json
   GET  /api/recorded             -> saved m6 trials (controller events, victim counts, probes)
   POST /api/probe                -> five real UDP echo probes to a temporary 127.0.0.1 service
        |
 demo/server.py (127.0.0.1 only, Host/Origin checks, CSRF header, MIME allow-list, CSP)
        |
 demo/engine.py simulate(): for t = 0..duration-1
     offered = demo/scenarios.Scenario.offered(t)            (optionally Poisson noise)
     forwarded = offered minus active drop / token-bucket rules
     CounterTracker.sample() -> build_detector(config).observe()
     alert -> OffenderHistory.next_offense() -> choose_action() -> TokenBucket or drop
     server/client outcome: proportional-share formula, or FluidQueue when queue > 0
```

The model sends **no attack packets** and installs no switch rules; the
"packet desk" rows are representative per-second flow records, not a capture.

---

## 4. Module reference

| Module | Responsibility | Key names |
|---|---|---|
| `controller/lab.py` | Fixed identities | `LAB_MAC_TO_IP`, `LAB_MAC_TO_PORT`, `VICTIM_IP`, `CLIENT_IP`, `VICTIM_PORT=9000`, `VICTIM_SWITCH_PORT=1` |
| `controller/config.py` | Config schema and validation | `DEFAULTS`, `validate_config`, `effective_config`, `load_config`, `apply_overrides`, `config_digest` |
| `controller/detection.py` | Counter deltas to rates; original detector | `FlowCounter`, `CounterTracker`, `TwoWindowDetector` |
| `controller/detectors.py` | Adaptive detectors | `EwmaDetector`, `CusumDetector`, `EntropyDetector`, `build_detector` |
| `controller/mitigation.py` | Response primitives | `TokenBucket`, `OffenderHistory`, `choose_action` |
| `controller/meters.py` | OpenFlow 1.3 meter message builders | `meter_id_for`, `meter_mod_add`, `meter_delete_all`, `ratelimit_match_fields`, `ratelimit_instructions`, `parse_meter_features` |
| `controller/forwarding.py` | OS-Ken app: forwarding, polling, mitigation | `ForwardingController`, cookie/priority constants |
| `controller/run.py` | Starts OS-Ken on `127.0.0.1:6653` | `main()` |
| `topology/lab_topology.py` | 5-host Mininet topology, optional TCLink bottleneck | `DDoSTopo`, `bottleneck_params`, `BOTTLENECK_PRESET` |
| `traffic/flood.py` | Bounded flood to `10.0.0.10:9000` (1–2000 pps, ≤30 s, 64–512 B) | `--format text|binary` |
| `traffic/probe.py` | Client probe, CSV output, metrics JSON | `--format`, `--mode`, `--metrics-json` |
| `traffic/echo_server.py` | UDP echo with per-second receive counts | `--stats-jsonl` |
| `traffic/probe_protocol.py` | FGPB format and probe statistics | `encode`, `decode`, `describe`, `percentile`, `JitterEstimator`, `ProbeStats` |
| `experiments/run_trial.py` | One logged Mininet trial | modes `detection`, `mitigation`, `mitigation-repeat`, `baseline`, `attack-off`, `attack-on` |
| `experiments/demo.py` | Narrated live trial, `--compare` OFF/ON | `show_event`, `show_availability` |
| `experiments/analyze.py` | Recompute metrics; OFF/ON comparison | `summarize_trial`, `compare`, `availability`, `qdisc_summary` |
| `experiments/qdisc_monitor.py` | Parse/sample `tc -s -j qdisc show` | `QdiscMonitor`, `parse_tc_json` |
| `experiments/packet_capture.py` | AF_PACKET capture to pcapng with named interfaces | `PacketCapture`, `switch_ports` |
| `experiments/benchmark_detectors.py` | Seeded detector benchmark and ROC sweep | `run_benchmark`, `--check` |
| `experiments/render_availability_png.py` | OFF/ON availability bar chart (Pillow) | `availability_panels` |
| `demo/scenarios.py` | Traffic scenarios shared by engine and benchmark | `SCENARIOS`, `poisson` |
| `demo/queueing.py` | Bottleneck queue models | `BottleneckQueue`, `FluidQueue`, `red_defaults` |
| `demo/live_lab.py` | Native real-UDP lab | `LivePolicy`, `Gateway`, `run_trial`, `compare` |
| `demo/engine.py`, `demo/server.py`, `dashboard/` | Offline dashboard | `simulate`, `/api/*` |
| `demo/terminal.py`, `demo/run.py` | Guided terminal presentation | `--section`, `--scenario` |
| `wireshark/flowguard.lua` | Heuristic UDP dissector | fields `flowguard.*` |

---

## 5. Configuration schema

File: [`config/detector.json`](../config/detector.json); presets in
[`config/presets/`](../config/presets/). Validation lives in
`controller/config.py`. The seven **original keys are required**; the three
optional sections default to values that reproduce the original behaviour
(threshold detector, drop-only, fixed 10 s rules).

### 5.1 Required (original) keys

| Key | Type / bounds | Shipped | Meaning |
|---|---|---|---|
| `poll_interval_s` | number, 0.1–60 | 1.0 | Flow-stats polling period (one detection window) |
| `victim_pps` | number, >0, ≤10 000 000 | 100.0 | Threshold detector: aggregate rate to the victim |
| `source_pps` | number, >0, ≤10 000 000 | 30.0 | Threshold detector: per-source rate; entropy detector: minimum offender rate |
| `min_sources` | integer, 1 … number of unprotected attack hosts | 2 | Threshold detector: sources that must exceed `source_pps` |
| `consecutive_windows` | integer, 1–1000 | 2 | High windows needed before an alert (threshold, EWMA, entropy) |
| `protected_sources` | list of unique lab IPv4s | `["10.0.0.11"]` | Never named as offenders (victim and client are always protected by the controller) |
| `mitigation_hard_timeout_s` | integer, 1–65535 (OpenFlow u16) | 10 | Base rule lifetime |

### 5.2 `detector` and `detectors`

`detector` ∈ `threshold | ewma | cusum | entropy` (default `threshold`).

| Section.key | Type, bounds | Default | Used by |
|---|---|---|---|
| `detectors.ewma.alpha` | number, (0, 1] | 0.2 | EWMA weight of the newest window |
| `detectors.ewma.k_sigma` | number, 0.5–50 | 4.0 | Control-limit width in standard deviations |
| `detectors.ewma.sigma_floor_pps` | number, 0.01–1e6 | 2.0 | Minimum σ (avoids zero-variance limits) |
| `detectors.ewma.min_rate_pps` | number, 0–1e7 | 20.0 | Source must also exceed this absolute rate |
| `detectors.ewma.warmup_windows` | integer, 0–1000 | 3 | Learn-only windows, cannot alert |
| `detectors.ewma.min_sources` | integer, ≥1 and ≤ eligible hosts | 1 | Anomalous unprotected sources needed |
| `detectors.cusum.alpha` | (0, 1] | 0.2 | Baseline EWMA weight |
| `detectors.cusum.drift_k` | 0–10 | 0.5 | Allowance subtracted per window |
| `detectors.cusum.threshold_h` | (0, 1000] | 6.0 | Decision threshold on S |
| `detectors.cusum.z_clip` | 0.5–100 | 4.0 | Clip of the standardised rate |
| `detectors.cusum.sigma_floor_pps`, `min_rate_pps`, `warmup_windows`, `min_sources` | as EWMA | 2.0, 20.0, 3, 1 | |
| `detectors.entropy.alpha` | (0, 1] | 0.2 | Baseline share/volume EWMA weight |
| `detectors.entropy.kl_threshold_bits` | (0, 20] | 0.5 | Divergence threshold in bits |
| `detectors.entropy.share_delta` | 0–1 | 0.10 | Share increase that names an offender |
| `detectors.entropy.min_victim_pps` | 0–1e7 | 50.0 | Minimum victim volume for a high window |
| `detectors.entropy.smoothing_pps` | (0, 1000] | 0.5 | Additive smoothing ε for shares |
| `detectors.entropy.warmup_windows`, `min_sources` | as EWMA | 3, 1 | |

### 5.3 `mitigation`

| Key | Type, bounds | Default | Meaning |
|---|---|---|---|
| `mitigation.action` | `drop | rate_limit | graduated` | `drop` | Response type |
| `mitigation.rate_limit_pps` | integer, 1–1 000 000 | 20 | Meter / token-bucket rate (packets/s) |
| `mitigation.rate_limit_burst_packets` | integer, 0–1 000 000 | 20 | Bucket depth (0 sends no `OFPMF_BURST` flag; the native bucket still holds 1 token) |
| `mitigation.graduated_drop_after` | integer, 1–100 | 2 | In `graduated`, offense number from which the response is drop |
| `mitigation.backoff.enabled` | boolean | false | Exponential timeout back-off |
| `mitigation.backoff.factor` | number, 1–16 | 2.0 | Multiplier per repeat offense |
| `mitigation.backoff.max_timeout_s` | integer, ≥ `mitigation_hard_timeout_s`, ≤ 65535 | 80 | Cap |
| `mitigation.backoff.memory_s` | number, 0–86400 | 120 | An offense more than this long after the previous rule ended starts again at 1 |

Unknown keys anywhere are rejected. `effective_config()` deep-merges the
defaults, `apply_overrides()` applies `--detector`, `--action` /
`--mitigation-action`, `--backoff` and `--rate-limit-pps`, and
`config_digest()` records a SHA-256 of the canonical JSON in each Mininet
trial's `metadata.json`.

Presets (each differs from `config/detector.json` only in these keys):

| Preset | `detector` | `mitigation.action` | `backoff.enabled` |
|---|---|---|---|
| `ewma.json` | ewma | drop | false |
| `cusum.json` | cusum | drop | false |
| `entropy.json` | entropy | drop | false |
| `ratelimit.json` | threshold | rate_limit | false |
| `graduated-backoff.json` | cusum | graduated | true |

---

## 6. Event schemas

### 6.1 Controller events (`controller.jsonl`, Mininet runtime)

Every record has `type`, `time_utc` (ISO 8601), `monotonic_s` and `dpid`.

| `type` | Additional fields | Emitted when |
|---|---|---|
| `switch_connected` | `mitigation_enabled` | Features reply processed, state reset |
| `meter_features` | `supported`, `max_meter`, `band_types`, `capabilities` | Meter-features multipart reply |
| `sample` | `elapsed_s`, `source_pps`, `source_bytes_per_s`, `victim_pps`, `counter_resets`, `drop_packet_delta`, `drop_packet_total`, `ratelimit_packet_delta`, `ratelimit_packet_total`, `detector_state` | Every complete flow-stats reply |
| `alert` | `victim`, `victim_pps`, `sources` {ip: pps}, `detector`, `scores` {ip: score} | Detector starts an alert episode |
| `drop_requested` | `source`, `victim`, `port`, `hard_timeout_s`, `offense_count`, `action` ("drop") | Drop FLOW_MOD sent |
| `ratelimit_requested` | `source`, `victim`, `port`, `meter_id`, `rate_pps`, `burst_packets`, `hard_timeout_s`, `offense_count` | METER_MOD + metered FLOW_MOD sent |
| `drop_confirmed` | `sources` [ip] | Barrier reply for a batch containing drop rules |
| `ratelimit_confirmed` | `sources` [ip] | Barrier reply; these rate limits had no error |
| `ratelimit_failed` | `sources`, `error_type`, `error_code`, `fallback` ("drop"), `reason` (`meter_unsupported` or `openflow_error`) | Meter unsupported, or a switch error before the barrier reply |
| `openflow_error` | `error_type`, `error_code`, `xid` | Any OFPT_ERROR from the switch |
| `meter_sample` | `meter_id`, `source`, `packet_in_delta`, `band_drop_delta`, `band_drop_total`, `flow_count` | Meter stats reply with activity |
| `drop_removed` / `ratelimit_removed` | `source`, `packets`, `reason` (OpenFlow `OFPRR_*`, 1 = hard timeout) | FLOW_REMOVED for cookie `...05` / `...06` |

`detector_state` per detector:

| Detector | Fields |
|---|---|
| threshold | `detector`, `high_windows`, `alert_active` |
| ewma | the above + `windows`, `warm`, `scores` (z per source), `baselines` {ip: {mean_pps, std_pps}}, `victim_baseline`, `k_sigma`, `sigma_floor_pps` |
| cusum | the above (with clipped z as `scores`) + `cusum` {ip: S}, `threshold_h`, `drift_k` |
| entropy | `detector`, `high_windows`, `alert_active`, `windows`, `warm`, `scores` (share delta), `victim_baseline`, `entropy_bits`, `normalised_entropy`, `kl_bits`, `kl_threshold_bits`, `shares`, `baseline_shares` |

Older recorded trials (`results/m4-*` to `m6-*`) predate `detector`,
`scores`, `offense_count`, `action` and `detector_state`; the analyzer treats
the missing fields as the original threshold/drop behaviour.

### 6.2 Native lab events (`events.jsonl`)

Every record has `timestamp_utc`, `t_s` (seconds since measurement start) and `type`.

| `type` | Fields |
|---|---|
| `phase` | `name` (`baseline`, `attack`, `gap`, `expiry-wait`, `recovery`), `wave` (multi-wave only) |
| `sample` | `rates` (CounterTracker output), `offered`, `forwarded`, `dropped`, `active_rules` {ip: deadline}, `rule_actions` {ip: action}; with a bottleneck also `queue_depth`, `queue_drops` |
| `alert` | `sources`, `victim_pps` |
| `gateway_drop_installed` | `source`, `timeout_s`, `offense_count`, `enforcement` |
| `gateway_ratelimit_installed` | `source`, `rate_pps`, `burst`, `timeout_s`, `offense_count`, `enforcement` |
| `rule_expired` | `source`, `action`, `offense_count` |
| `finished` | `validation_status`, `checks` |

Other per-run files: `victim.jsonl` (echo server: `window_start_s`,
`elapsed_s`, `by_source`, `packets`, `total_packets`), `client.csv`
(`timestamp_utc,sequence,status,rtt_ms`), `packets.csv` (one row per datagram
at the gateway with `gateway_decision` ∈ `FORWARD, DROP, RL_PASS, RL_DROP,
QUEUE_TAIL_DROP, QUEUE_RED_DROP, ERROR`), and in Mininet trials
`qdisc.jsonl` (one `tc` sample every 0.5 s), `qdisc-config.json`,
`qdisc-after.json`, `capture-summary.json`, `client.metrics.json`.

---

## 7. FGPB probe protocol

Defined in [`traffic/probe_protocol.py`](../traffic/probe_protocol.py);
`struct` format `!4sBBHIIQHHI` (network byte order), 32-byte header followed
by `payload_len` bytes of padding (`bytes(i & 0xFF)`).

```text
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------------------------------------------------------+
|                     magic = "FGPB" (4 bytes)                  |  0
+---------------+---------------+-------------------------------+
| version = 1   | msg_type      |       header_len = 32         |  4
+---------------+---------------+-------------------------------+
|                         session_id                            |  8
+---------------------------------------------------------------+
|                            seq                                | 12
+---------------------------------------------------------------+
|                    tx_time_ns (64 bits)                       | 16
|                                                               |
+-------------------------------+-------------------------------+
|          payload_len          |            flags              | 24
+-------------------------------+-------------------------------+
|              crc32 over bytes 0..27 + padding                 | 28
+---------------------------------------------------------------+
|                     padding (payload_len bytes)               | 32
```

| Offset | Field | Type | Value / meaning |
|---|---|---|---|
| 0 | `magic` | 4s | `FGPB` |
| 4 | `version` | u8 | 1 |
| 5 | `msg_type` | u8 | 1 probe request, 2 probe reply (reserved), 3 flood |
| 6 | `header_len` | u16 | 32 |
| 8 | `session_id` | u32 | random per run (or `--session-id`) |
| 12 | `seq` | u32 | starts at 1 |
| 16 | `tx_time_ns` | u64 | sender wall clock, display only |
| 24 | `payload_len` | u16 | padding bytes after the header |
| 26 | `flags` | u16 | bit 0 = padded |
| 28 | `crc32` | u32 | `zlib.crc32(bytes[0:28] + bytes[32:])` |

The echo server returns the datagram unchanged, so replies also carry
`msg_type 1`. `decode()` rejects a datagram whose length is not
`32 + payload_len`. The CRC detects corruption of the probe (one flipped bit
fails, see `tests/test_probe_protocol.py`); UDP's own checksum is computed by
the kernel independently.

Legacy payloads the tools still emit or decode: `ddos-probe:<seq>:<ns>`
(text probe, `probe.py --format text`, used by every recorded M4–M7 trial),
`FLOWGUARD-LAB-ONLY:XXXX...` (Mininet flood, `flood.py` default) and
`flowguard:<source>:<phase>:<seq>:<ns>....` (native lab sources, padded to 128 B).

### Probe statistics

* **Loss** = sent probes without an on-time reply. A reply after
  `--timeout-ms` (500 ms) is *late*, not received.
* **Percentiles** use the nearest-rank rule: the value at rank ⌈p·n/100⌉ of
  the sorted RTTs.
* **Jitter** follows RFC 3550 §6.4.1: for consecutive packets
  D = (R_i − R_{i−1}) − (S_i − S_{i−1}) and J ← J + (|D| − J)/16. Because the
  send and receive stamps come from the same host clock, R − S is the RTT, so
  D is simply the RTT difference.
* **Reordering** follows RFC 4737: a first arrival whose seq is below the
  highest seq already received. Duplicates and late replies are counted
  separately. When metrics are rebuilt from a CSV (`ProbeStats.from_csv`),
  late/duplicate/reordered are `null` because the CSV cannot show them.

---

## 8. Detector mathematics

All detectors consume the output of `CounterTracker.sample()`:
r_s = (P_s(t) − P_s(t−1)) / Δt for each source s, where P is the cumulative
packet counter of its forwarding flow; a negative delta (counter reset) gives
no rate for that window. The victim rate is V = Σ_s r_s.

### 8.1 Threshold (original, `TwoWindowDetector`)

A window is **high** iff V > `victim_pps` **and**
|{s ∉ protected : r_s > `source_pps`}| ≥ `min_sources`. The alert fires when
the run of consecutive high windows reaches `consecutive_windows`, once per
episode; any non-high window resets the run. Shipped: V > 100, r_s > 30, two
sources, two windows.

### 8.2 EWMA control chart (`EwmaDetector`)

Per series (each source and the victim aggregate) an exponentially weighted
mean and variance (West/Finch form):

```text
delta  = x − μ
μ     ← μ + α·delta
σ²    ← (1 − α)·(σ² + α·delta²)
```

Source s is anomalous iff r_s > μ_s + k·max(σ_s, σ_floor) **and** r_s >
`min_rate_pps`. A window is high iff the detector is warm (more than
`warmup_windows` windows seen), the victim series is anomalous by the same
rule, and at least `min_sources` unprotected sources are anomalous; the alert
needs `consecutive_windows` high windows. Baselines are frozen for anomalous
series and while an alert is active, so a flood is never learned as normal. A
source first seen after the first window starts at μ = 0. The reported score
is z = (x − μ)/max(σ, σ_floor).

### 8.3 Page CUSUM (`CusumDetector`)

```text
z  = clip((x − μ) / max(σ, σ_floor), −z_clip, +z_clip)
S ← max(0, S + z − k)          (k = drift_k)
```

A source offends when S > h and r_s > `min_rate_pps`; the alert fires as soon
as `min_sources` sources offend (CUSUM accumulates evidence itself, so
`consecutive_windows` is not used). μ and σ come from the same EWMA, updated
only while S = 0 and no alert is active. With the shipped z_clip 4, k 0.5,
h 6: a sustained flood gives S = 3.5, 7.0 (alarm in window 2); a one-window
burst peaks at 3.5 and decays; 1 s on / 1 s off pulsing gives 3.5, 3.0, 6.5
(alarm on the second pulse). This is why CUSUM is the only shipped detector
that catches the pulsing scenario.

### 8.4 Traffic-mix divergence (`EntropyDetector`)

Shares with additive smoothing ε = `smoothing_pps`, over every source seen
(protected hosts included):

```text
p_s = (x_s + ε) / Σ_j (x_j + ε)
D(P‖Q) = Σ_s p_s · log2(p_s / q_s)      bits, Q = baseline share vector
```

A window is high iff warm, D > `kl_threshold_bits` and V > max(`min_victim_pps`,
μ_V + 3σ_V). Offenders are unprotected sources with r_s > `source_pps` and
p_s − q_s > `share_delta`. The alert needs `consecutive_windows` high windows
and at least `min_sources` offenders. The baseline Q ← (1 − α)Q + αP and the
victim volume baseline are updated only in non-high windows. Shannon entropy
H = −Σ p log2 p is reported in `detector_state` but **not** used: a
two-source flood moves the shares (a1, a2, client) from (.14, .14, .71) to
(.50, .50, .01), which changes normalised entropy only from 0.73 to 0.67
while D = 1.73 bits (docstring and `tests/test_detectors.py`). A flash crowd
scales every source equally, so P ≈ Q and D ≈ 0 — the reason entropy has no
flash-crowd false alarms in the benchmark.

---

## 9. Response mechanisms

### 9.1 Policy

`OffenderHistory.next_offense(source, now)` forgets sources whose last rule
ended more than `memory_s` ago, increments the offense count n and returns the
timeout

```text
T(n) = min(max_timeout_s, round(base · factor^(n−1)))   if back-off enabled
T(n) = base                                              otherwise
```

With base 10 s, factor 2, cap 80 s: 10, 20, 40, 80, 80 … s.
`choose_action(action, n, graduated_drop_after)` returns `drop` or
`rate_limit`; `graduated` rate-limits offenses 1 … (drop_after − 1) and drops
from offense `graduated_drop_after` on (shipped: rate-limit first, drop on the
second offense).

### 9.2 Token bucket (`TokenBucket`, native lab and model)

```text
tokens ← min(C, tokens + (t − t_last)·r)      C = max(burst, 1), r = rate_pps
admit if tokens ≥ 1, then tokens ← tokens − 1
```

Over an interval of length T at most C + r·T packets pass, so a 600 pps
source limited to 20 pps with burst 20 delivers ≈ 20 pps plus a one-off burst
of 20 packets. A clock that steps backwards never adds tokens.

### 9.3 OpenFlow 1.3 meter (Mininet runtime)

`meter_mod_add()` builds `OFPMeterMod(command=ADD or MODIFY,
flags=OFPMF_PKTPS | OFPMF_STATS | (OFPMF_BURST if burst > 0),
meter_id=1000 + last octet, bands=[OFPMeterBandDrop(rate=rate_pps,
burst_size=burst)])`. A packets-per-second drop band is the switch-side
equivalent of the token bucket above: packets exceeding the rate (after the
burst allowance) are dropped by the meter; admitted packets continue to the
`apply_actions` instruction (output to the victim's port 1). Meter ids: a1
`10.0.0.21` → 1021, a2 → 1022, a3 → 1023. The meter outlives its flow; a later
rate limit for the same source re-sends it with `MODIFY` so a changed rate
applies. On every (re)connection the controller sends
`OFPMeterMod(DELETE, meter_id=OFPM_ALL)`.

**Measured live** (`results/m8-meter-on`, Open vSwitch 3.3.9): the
meter-features reply reported `supported`, `max_meter` 200000, `band_types` 2
(drop) and `capabilities` 15; meters 1021/1022 and the flow
`actions=meter:1021,output:1` were accepted, the bands dropped 6,735 packets
and ≈153 packets per source passed in ≈6.6 s, i.e. 20 packets/s plus the
20-packet burst. Meter support in OVS depends on its version and datapath,
which is why the meter-features reply decides whether FlowGuard attempts
rate limiting at all. If the reply reports
no meters, no drop band or no packets-per-second capability, the controller
installs drop rules instead and logs `ratelimit_failed` with
`reason=meter_unsupported`.

### 9.4 Cookies, priorities and timeouts

| Cookie | Priority | Match | Instructions | Timeouts | Purpose |
|---|---|---|---|---|---|
| `0xdd05000000000001` | 0 | everything (table miss) | none (drop) | — | Unrelated frames are dropped in the switch |
| `0xdd05000000000004` | 5 | `in_port`, `eth_src`, ARP `arp_spa` or IPv4 `ipv4_src` + `ip_proto` 1/17 for each lab host | output CONTROLLER | — | Identity-bound punt: only lab hosts on their own ports reach the controller |
| `0xdd05000000000002` | 20 | ARP, ICMP, and UDP not to `10.0.0.10:9000`, with `in_port`/`eth_src`/`eth_dst` | output port | idle 30 s | Ordinary forwarding (not counted by the detector) |
| `0xdd05000000000003` | 100 | UDP `ipv4_src`, `ipv4_dst=10.0.0.10`, `udp_dst=9000`, `in_port`, `eth_src`, `eth_dst` | output port | idle 30 s | Protected-service forwarding; **its counters feed the detector** |
| `0xdd05000000000005` | 200 | `ip_proto=17`, `ipv4_src=<offender>`, `ipv4_dst=10.0.0.10`, `udp_dst=9000` | none (drop) | hard `T(n)`, `SEND_FLOW_REM` | Drop rule |
| `0xdd05000000000006` | 200 | drop-rule match + `in_port`, `eth_src` (offender), `eth_dst` (victim) | `meter 1000+octet`, then `apply_actions output:1` | hard `T(n)`, `SEND_FLOW_REM` | Rate-limit rule (identity-bound) |

The controller deletes only flows in its cookie range (`cookie 0xdd05…`,
mask `0xffff000000000000`) on reconnect. The source file notes one caveat: a
back-off timeout longer than the 30 s idle timeout lets the source's
priority-100 forwarding flow idle out underneath the mitigation rule; when the
rule expires the next packet is punted again and the counter tracker loses one
window for that source.

### 9.5 OpenFlow message sequences

OpenFlow 1.3 message type numbers (from `os_ken/ofproto/ofproto_v1_3.py`):
ERROR 1, PACKET_IN 10, FLOW_REMOVED 11, PACKET_OUT 13, FLOW_MOD 14,
MULTIPART_REQUEST 18, MULTIPART_REPLY 19, BARRIER_REQUEST 20,
BARRIER_REPLY 21, METER_MOD 29. Error types used: BAD_INSTRUCTION 3,
METER_MOD_FAILED 12. Multipart types: FLOW 1, METER 9, METER_FEATURES 11.

**Drop (shipped default)**

```text
controller                                   OVS s1
    |  MULTIPART_REQUEST(FLOW, cookie mask)  ->  |     every poll_interval_s
    |  <-  MULTIPART_REPLY(flow stats)           |
    |  [detector: alert]  event alert            |
    |  FLOW_MOD ADD prio 200 cookie ..05         |
    |    match {udp, src=a1, dst=victim, 9000}   |
    |    no instructions, hard_timeout=T,        |
    |    flags=SEND_FLOW_REM   event drop_requested
    |  FLOW_MOD ADD ... src=a2 ...           ->  |
    |  BARRIER_REQUEST                       ->  |
    |  <-  BARRIER_REPLY       event drop_confirmed (rules processed in order)
    |          ... T seconds ...                 |
    |  <-  FLOW_REMOVED(reason=HARD_TIMEOUT, packet_count)  event drop_removed
```

**Rate limit (`--mitigation-action rate_limit`, or first offense in `graduated`)**

```text
controller                                   OVS s1
    |  (at connect) METER_MOD DELETE OFPM_ALL ->  |
    |  (at connect) MULTIPART_REQUEST(METER_FEATURES) ->
    |  <-  MULTIPART_REPLY(max_meter, band_types, capabilities)  event meter_features
    |  [alert]                                    |
    |  METER_MOD ADD id 1021 PKTPS|STATS|BURST     |
    |    band DROP rate=20 burst=20           ->  |
    |  FLOW_MOD ADD prio 200 cookie ..06          |
    |    match {in_port 3, eth_src a1, eth_dst victim, udp, src, dst, 9000}
    |    instr [METER 1021, APPLY output:1]   ->  |   event ratelimit_requested
    |  BARRIER_REQUEST                        ->  |
    |  <-  BARRIER_REPLY      event ratelimit_confirmed
    |  MULTIPART_REQUEST(METER stats, OFPM_ALL) -> |   each poll while meters exist
    |  <-  MULTIPART_REPLY    event meter_sample (band_drop_delta = policed packets)
    |  <-  FLOW_REMOVED       event ratelimit_removed
```

**Meter fallback (switch rejects the meter or the meter instruction)**

```text
controller                                   OVS s1
    |  METER_MOD ADD id 1021 (xid x1)         ->  |
    |  FLOW_MOD ADD metered (xid x2)          ->  |
    |  BARRIER_REQUEST (xid x3)               ->  |
    |  <-  ERROR type 12 METER_MOD_FAILED (xid x1)   event openflow_error
    |  <-  ERROR type 3 BAD_INSTRUCTION (xid x2)     event openflow_error (if sent)
    |      controller marks the source failed and the switch "unsupported"
    |  <-  BARRIER_REPLY (x3): an OpenFlow switch answers a barrier only after
    |      every earlier message, so the error is already known here
    |      event ratelimit_failed {reason: openflow_error, fallback: drop}
    |  FLOW_MOD ADD drop rule, same hard_timeout ->|   event drop_requested
    |  BARRIER_REQUEST                        ->  |
    |  <-  BARRIER_REPLY      event drop_confirmed
```

If the meter-features reply already said "unsupported", the controller skips
the meter entirely, installs the drop rule and logs `ratelimit_failed` with
`reason=meter_unsupported` and `error_type=null`. These sequences are verified
by unit tests that run the real OS-Ken v1.3 serializer against a mock datapath
(`tests/test_meters.py`, `tests/test_forwarding.py`). The drop and
rate-limit sequences were also observed live on OVS 3.3.9 (`m8-demo-original`,
`m8-meter-on`, `m8-cusum-graduated-waves`: `drop_confirmed`,
`ratelimit_confirmed`, `meter_sample`, `ratelimit_removed`/`drop_removed`).
The fallback sequence has **not** been exercised live, because that switch
supports meters.

---

## 10. Queue models

### 10.1 `BottleneckQueue` (native lab)

A finite queue with deterministic service — one packet leaves every
1/μ seconds while busy (μ = `service_pps`). In queueing notation the service
is D (deterministic) with one server; arrivals are whatever the real sockets
produce. Arrivals that find `capacity` packets in the system are tail-dropped
(FIFO). A packet that arrives behind n packets waits about n/μ, so the
maximum queueing delay is Q/μ. With the evidence settings μ = 300 pps and
Q = 50 packets:

```text
max queueing delay = 50 / 300 s = 166.7 ms
```

which is exactly the measured attack-phase queue-delay p95 of 166.5 ms in
`results/m9-native-bottleneck` (FIFO, mitigation OFF).

Under overload (arrival rate λ > μ) a full FIFO admits μ per second, so the
long-run drop fraction is

```text
p_drop ≈ 1 − μ/λ = 1 − 300/1210 ≈ 0.75
```

for two 600 pps sources plus the 10 pps client. The measured OFF attack-phase
client loss was 71.25 % (80 probes), close to the fluid estimate; with 80
probes one probe is 1.25 percentage points, so the run cannot resolve a
difference of a few points. The FIFO also served the two sources unequally
(a1 lost 2,407 datagrams to the queue, a2 lost 4,767). The likely cause is
phase alignment: each scheduling tick of `demo/live_lab.py` sends a1's due
packets before a2's, so a2's arrivals more often find the queue full. Tail
drop is not fair between flows, which is one motivation for RED and per-flow
queueing (with RED the split was 3,549 vs 3,635).

**RED** (Floyd and Jacobson 1993), when `--queue-discipline red`:

```text
on each arrival:  avg ← (1 − w_q)·avg + w_q·q             (q = current depth)
after idle time:  avg ← (1 − w_q)^m · avg                  (m = packets the link could have sent)
avg <  min_th            : admit
avg ≥  max_th            : drop
otherwise                : p_b = max_p · (avg − min_th)/(max_th − min_th)
                           p_a = p_b / (1 − count·p_b)     (count = admits since last drop)
```

Defaults scale with the queue: min_th = 0.2·Q, max_th = 0.6·Q (10 and 30 for
Q = 50), max_p = 0.1, w_q = 0.02 (not the textbook 0.002: with only 50
packets the average would need ~500 arrivals to follow the queue, so tail drop
would act first). Tail drop still applies at capacity. In overload RED holds
the average near max_th, so the expected delay is about 30/300 s = 100 ms;
the measured RED attack-phase queue-delay p50 was 100.1 ms and p95 106.7 ms
(`results/m9-native-red-ewma-warm/off`).

### 10.2 `FluidQueue` (dashboard model)

Per one-second step with arrivals A, capacity C and limit Q:

```text
B' = clamp(B + A − C·dt, 0, Q)
drops  = max(0, B + A − C·dt − Q)
served = B + A − drops − B'
delay  = 1000 · (B + B') / 2 / C      ms (mean backlog over the interval)
```

### 10.3 Mininet TCLink bottleneck

From `topology/lab_topology.py`: only `s1-eth1` (switch → victim egress) is
shaped. Mininet runs, in the root namespace,

```text
tc qdisc add dev s1-eth1 root handle 5:0 htb default 1
tc class add dev s1-eth1 parent 5:0 classid 5:1 htb rate 0.5Mbit burst 15k
tc qdisc add dev s1-eth1 parent 5:1 handle 10: netem limit 50
```

HTB is the rate limiter; netem with no delay/loss is the FIFO whose `limit`
is the tail-drop length. Sizing of the preset: a text flood frame is
14 + 20 + 8 + 128 = 170 bytes; two 600 pps sources offer
2·600·170·8 = 1.63 Mbit/s; 0.5 Mbit/s carries 0.5·10⁶/(170·8) ≈ 367 pps, so
about 70 % of victim-bound requests (including the client's) are expected to
be tail-dropped while the flood is forwarded; the worst-case queueing delay is
50·170·8/0.5·10⁶ ≈ 136 ms (below the probe's 500 ms timeout). HTB's 15 kB
burst lets roughly 90 frames through at line rate when the queue first fills.

Measured live (`results/m8-bottleneck-compare`, mitigation OFF): `tc` showed
`htb 5:` root and `netem 10:` with `limit 50`; 365.8 attack packets/s reached
the victim; maximum backlog 8,500 bytes = 50 frames × 170 bytes; client loss
70.0 % and RTT p95 136.2 ms — all as predicted.

RED caveat: Mininet hard-codes RED `min 30000 max 35000 avpkt 1500` bytes.
With 170-byte frames RED would only start dropping above an average backlog of
~176 packets, so with a queue below ~200 packets the netem tail drop acts
first and `--qdisc red` behaves like FIFO (expected; not measured live). Use
the native lab's RED model to demonstrate RED.

Detection is unaffected by the bottleneck: OpenFlow counters count packets
when OVS matches them on ingress, before the egress qdisc. The victim's echo
statistics and the `victim-received` capture stream are post-bottleneck (see
[WIRESHARK_DEMO](WIRESHARK_DEMO.md)).
