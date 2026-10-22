# FlowGuard, explained

> **Advanced networking branch.** The dashboard now also offers pulsing,
> slow-ramp, flash-crowd, three-source and repeat-offender stories, four
> detectors, rate-limit/graduated responses, back-off and a bottleneck queue
> ("Tune the model"), plus an offline detector benchmark on the "Behind the
> scenes" page. Commands and talk tracks: [docs/SCENARIOS.md](docs/SCENARIOS.md)
> and the 10-minute advanced review in [docs/DEMO.md](docs/DEMO.md#advanced-review-10-minutes).
> Measured native bottleneck results: [docs/RESULTS.md](docs/RESULTS.md#m9-advanced-results).

FlowGuard is a small software-defined networking (SDN) lab that observes UDP traffic to one protected echo service, detects a sustained multi-source rate, and asks an OpenFlow switch to temporarily drop matching traffic. Its value is in making the full loop inspectable: packet counters, a simple rule, a saved experiment, and a clear account of what each demo does and does not prove. It is not a general DDoS service, and the project does not claim a new detection algorithm.

## The simple analogy

For the new practical presentation, see [WINDOWS_DEMO.md](WINDOWS_DEMO.md).
`demo/terminal.py` explains the detector, reads the original switch evidence,
then sends real localhost UDP through a gateway with mitigation OFF and ON.
The original detector, echo server and probe execute; the native gateway
enforces the decision in Python. The full OpenFlow switch remains a separate
implementation requiring an existing Linux lab. This makes the distinction
between an explanation, historical evidence and a fresh live measurement clear.

Picture five offices connected to one mailroom. The switch is the mailroom sorter: it forwards traffic along the right local link and can apply a short rule such as “do not deliver this sender's UDP mail to the protected service.” The controller is the supervisor: it periodically reads the sorter’s counters, checks whether the pattern meets the configured rule, then sends a temporary instruction back.

The analogy has limits. A switch forwards actual frames; the controller does not inspect every packet as if it were a person reading each letter. It usually reads aggregate flow counters and changes the forwarding table. The live simulation page does not contact a switch at all; it supplies deterministic counter values to the project’s actual detection classes.

## The exact lab

The Mininet topology is one Open vSwitch, named s1, with five fixed hosts and no NAT or external links. The OS-Ken controller connects to the switch over the OpenFlow control channel. The configured host-to-switch port mapping is part of the controller’s trust boundary.

    OS-Ken controller
          │  OpenFlow 1.3 control channel
          │  stats replies ↑   requests / rules ↓
    ┌─────┴──────────────────────────┐
    │        Open vSwitch s1          │
    └─┬──────┬──────┬──────┬──────┬──┘
      │      │      │      │      │
    port 1 port 2 port 3 port 4 port 5
      │      │      │      │      │
    10.0.0.10  10.0.0.11  10.0.0.21  10.0.0.22  10.0.0.23
    UDP    protected traffic-source hosts
    :9000  client

All five addresses are in 10.0.0.0/24 and are listed in [topology/lab_topology.py](topology/lab_topology.py). The controller binds the victim to switch port 1, the client to port 2, and A1/A2/A3 to ports 3/4/5 in [controller/forwarding.py](controller/forwarding.py). Port numbers are switch ports, not UDP ports. UDP destination port 9000 is the echo service on the victim.

## What the protocols do here

An application sends a UDP datagram to the echo server’s IP address and destination port 9000. UDP supplies lightweight datagrams and port numbers; it does not guarantee delivery or retransmission. IPv4 carries the source and destination network addresses. Ethernet carries each local-hop frame using source and destination MAC addresses. Before a host can send a frame to a local IPv4 neighbor, ARP can resolve that IPv4 address to an Ethernet address. [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html), [RFC 791](https://www.rfc-editor.org/rfc/rfc791.html), and [RFC 826](https://www.rfc-editor.org/rfc/rfc826.html) describe those protocol roles.

The controller and switch use OpenFlow 1.3 to exchange flow statistics and flow-table instructions. A flow rule can match on fields such as Ethernet type, IP protocol, IPv4 addresses, UDP port, and ingress switch port, then apply an action such as forwarding or dropping. OpenFlow is the controller-to-switch control protocol; it is not the protocol used by the client to talk to the echo application. See the [Open Networking Foundation OpenFlow 1.3 specification](https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf).

### Control plane and data plane

The data plane is the switch’s fast packet-handling path. It forwards known traffic using installed rules. The control plane is the OS-Ken application that sets up those rules, polls flow counters, evaluates rates, and asks for mitigation. On first contact, allowed lab traffic can be sent to the controller so it can validate and learn the path; the controller then installs forwarding state and sends that packet onward. Subsequent matching packets can be handled by the switch without a controller round trip.

At switch connection, the controller clears its own stale pending state and removes its own old cookie range from the switch. It installs a table-miss drop and narrowly punts expected ARP, ICMP, and UDP traffic from the fixed lab identities. The handler checks that a known MAC arrives on its configured port, that its IPv4 or ARP sender address agrees with that MAC, and that a unicast IPv4 destination matches the expected lab MAC. These checks are useful in this small topology; they do not authenticate hosts across arbitrary networks.

## How the detector decides

The current defaults in [config/detector.json](config/detector.json) are:

| Setting | Default | Meaning |
|---|---:|---|
| Poll interval | 1 second | How often the controller requests flow statistics |
| Victim threshold | More than 100 packets/s | Combined measured rate to the protected UDP service |
| Per-source threshold | More than 30 packets/s | Minimum rate for a source to qualify |
| Minimum sources | 2 | Number of distinct eligible source IPs that must qualify |
| Consecutive windows | 2 | Number of adjacent high observations needed to alert |
| Protected source | 10.0.0.11 | Excluded from offender qualification and mitigation |
| Mitigation timeout | 10 seconds | Hard lifetime of each installed drop rule |

The controller polls only IPv4 UDP flows destined to 10.0.0.10:9000. For each flow identity, [CounterTracker](controller/detection.py) compares the current cumulative packet and byte counters with the previous sample, then divides each nonnegative difference by the elapsed monotonic time. The first sample establishes a baseline and cannot produce a rate. If a counter goes backwards—for example, after a switch counter reset—the tracker skips that difference and uses the new value as the next baseline. When the switch reconnects, the controller creates a fresh tracker and detector.

The detector sums source rates for the victim threshold, then counts distinct unprotected sources whose individual rate is strictly greater than 30 packets/s. It alerts only when the victim total is strictly greater than 100 packets/s and at least two eligible sources qualify for two observations in a row. Any observation that does not meet the combined condition clears the consecutive-window count. The protected client’s traffic can contribute to the total victim rate, but its address is excluded from the offender set and its packets are excluded from source-specific drop rules.

For example, the sustained model offers 600 packets/s from A1, 600 packets/s from A2, and 10 packets/s from the protected client. Once the counters report that load, the victim total is about 1,210 packets/s; each of the two source addresses is above 30 packets/s. The first consecutive high observation leaves the detector waiting. The next consecutive high observation raises the alert. A single high observation alone does not.

This is a configured threshold rule, not a learned baseline or a classifier. Two source addresses are a minimum diversity requirement; it is not a maximum source-count safeguard, and an address is not proof of a distinct attacker. The dashboard includes a single-source scenario to make that blind spot visible.

## What mitigation changes

For each eligible source in the alert, the controller adds a high-priority drop rule matching IPv4 UDP from that source to 10.0.0.10 on destination port 9000. It excludes both the victim and protected client. The rule has a hard timeout of 10 seconds; the controller requests flow-removed notifications and records when the switch reports removal. While an alert remains active, it checks current qualifying sources again, so an expired rule can be reinstalled if that source is still over threshold. If rates fall below the detection condition, the detector resets its consecutive count and can alert on a later wave.

The current controller records a drop request, then sends an OpenFlow barrier and labels its reply as drop-confirmed. A barrier reply establishes ordering of prior controller messages; by itself it is not an independent readback proving the intended flow is present or that packets were dropped. For a careful presentation, say “the controller received the barrier reply,” and point to switch flow records and victim counters as the separate evidence of filtering. The saved experiment contains those records.

The current code also adds several defensive boundaries that are visible in [controller/forwarding.py](controller/forwarding.py):

- It binds each known lab MAC/IP identity to its expected ingress switch port and rejects mismatches.
- It validates ARP sender hardware and protocol addresses, target addresses, lengths, and request/reply form before learning or forwarding.
- It rejects group-addressed Ethernet frames and IPv4/MAC destination mismatches for the lab’s unicast IP traffic.
- It monitors the same UDP destination service that the drop rules protect, avoiding a mismatch between what the detector counts and what mitigation blocks.
- It validates detector configuration bounds, clears pending multipart/barrier state on reconnect or disconnect, and re-evaluates qualifying sources during an active alert.

These are hardening steps for the fixed lab. They do not make the detector robust to every attack pattern, nor do they turn the host map into Internet-wide identity verification.

## Three evidence modes, three different claims

The local dashboard and [demo/engine.py](demo/engine.py) keep three kinds of evidence separate:

| Mode | What it uses | What it demonstrates |
|---|---|---|
| Interactive model | Deterministic one-second counter rows passed through the project’s actual CounterTracker and TwoWindowDetector classes | How the configured thresholds react to normal traffic, a short burst, a sustained two-source load, repeated waves, one source, or a below-threshold load. It installs no switch rule and sends no attack packets. |
| Recorded experiment | The original m6 attack-off and attack-on files, including controller logs, victim measurements, client probes, and flow dumps | What happened in the historical five-host SDN trial. The raw evidence is retained; some relative times and offered-rate comparisons are derived from it and labeled as derived. |
| Live UDP check | Five real echo probes to 127.0.0.1 on a temporary local port, using the project’s echo and probe programs | A real local UDP request/reply and round-trip measurement. It does not involve the SDN switch or send a flood. |

The packet desk in the model is an explanatory view of representative generated counter rows, not a packet capture and not a Wireshark trace. It helps explain fields and decisions; it cannot establish that those exact frames crossed a physical network interface.

The simulated “service capacity” is an adjustable hypothetical packets-per-second value, defaulting to 1,000. The model uses it to estimate a load ratio and to calculate illustrative client success and latency under overload. Neither the capacity nor those outcomes were measured from the echo server. The recorded mode deliberately leaves capacity-dependent load and modeled client fields blank because the historical experiment did not estimate server capacity. Keep these simulated values visually and verbally separate from raw measurements.

## What the saved results actually show

The saved m6 runs are dated 13 October 2026 and used two traffic sources, each sending 600 packets/s for eight seconds. In the attack-on run, the first alert was recorded 1.5548 seconds after the recorded attack start, and the first barrier reply was recorded 1.6338 seconds after it. The matched comparison window reports attacker traffic at the victim falling from about 1,199.96 packets/s in the attack-off trial to zero in the attack-on trial. The attack-on trial requested two source rules, received one barrier reply for them, and recorded two rule removals.

The legitimate client received 80 of 80 replies in both attack-off and attack-on trials; recovery probes were 10 of 10 in both. Therefore, the saved data demonstrate that source-specific filtering took effect in this bounded lab run, while legitimate probes succeeded. They do not demonstrate an availability improvement: the unmitigated comparison also had no probe loss. They do not establish behavior under server saturation, a larger topology, or a real Internet-scale flood. These figures are in [results/m6-summary.json](results/m6-summary.json) and are summarized in [DEMO.md](DEMO.md). The dashboard’s provenance note states that these historical trials predate the current hardening changes in [dashboard/index.html](dashboard/index.html).

The honest contribution is the reproducible integration and evidence path: source-attributed counter rates, explicit thresholds, narrow time-limited OpenFlow rules, recovery observations, raw experiment files, regression checks, and an explanation that separates simulated, recorded, and live behavior. Threshold-based DDoS detection and SDN flow rules are established techniques; this project does not propose a new detection algorithm.

## The real-world comparison: GitHub, 28 February 2018

The dashboard’s case study is the GitHub DDoS incident reported for 28 February 2018. GitHub reported that its site was unavailable from 17:21 to 17:26 UTC and intermittently unavailable until 17:30 UTC. GitHub reported a peak of 1.35 Tbps and 126.9 million packets per second, with traffic spanning more than 1,000 autonomous systems and tens of thousands of unique endpoints. These are GitHub’s published figures, not values reconstructed from raw packet data. [GitHub’s first-party incident report](https://github.blog/news-insights/company-news/ddos-incident-report/) gives the impact, reported scale, and response timeline.

The mechanism matters more than the headline number. In a memcached UDP reflection/amplification attack, a request is sent to exposed third-party memcached servers with the victim’s address forged as the source. Those servers send their larger replies to the victim. Cloudflare’s contemporaneous account describes the UDP port 11211 vector and gives an example in which a 15-byte request could produce a response up to 750 kB; that is Cloudflare’s vector example, not a packet capture from GitHub’s incident. [Cloudflare’s technical explanation](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/) explains the reflection path. GitHub reported shifting traffic to Akamai beginning at 17:26 UTC, followed by route reconvergence and filtering at Akamai’s edge; GitHub reported full recovery by 17:30 UTC. [GitHub’s incident report](https://github.blog/news-insights/company-news/ddos-incident-report/) describes that response sequence.

FlowGuard’s lab uses direct UDP traffic from its fixed source hosts to its own echo service. It has no memcached servers, spoofed requests, Internet reflectors, BGP rerouting, provider scrubbing service, or terabit-scale capacity. In the GitHub case, the source addresses visible at the victim can be the reflectors that sent replies, rather than the machine that initiated the spoofed request. So the incident is a comparison to teach the difference between direct floods and reflection; it is not a replay or validation of FlowGuard.

## Defensive ideas and their limits

| Idea | How to explain it | What this project supports |
|---|---|---|
| Bind identity at ingress | In a controlled switch lab, an allowed address should arrive on its expected port, with consistent MAC and IP fields. This makes simple identity spoofing inside the lab harder. | Implemented for the five fixed hosts. It is not Internet-wide source authentication. Provider ingress filtering such as [BCP 38 / RFC 2827](https://www.rfc-editor.org/rfc/rfc2827.html) can reduce forged source prefixes, but cannot stop every flood or tell who initiated a reflection attack. |
| Use source-aware, narrow mitigation | Match an eligible source, victim, protocol, and service so a rule has a defined scope. Treat observed source IPs as evidence, not as guaranteed attacker identities. | Implemented for UDP from one eligible lab source to 10.0.0.10:9000. A reflected reply may arrive from a legitimate reflector, which makes indiscriminate source blocking risky. |
| Require sustained load | A persistence condition can avoid reacting to one short observation, at the cost of detection delay and the possibility of missing a very short event. | Implemented as two consecutive one-second-poll observations under default settings. It is a simple consecutive-window check, not a sliding average, hysteresis, or adaptive baseline. |
| Track source diversity carefully | Distinct source addresses can help identify a distributed pattern. A minimum source count is different from a limit on source-table size; spoofing and reflection also make addresses differ from initiators. | The detector requires at least two distinct eligible source IPs. It has no maximum-cardinality threshold or bot identity system. A larger design should bound state and display source diversity separately from attacker count. |
| Apply progressive policy | A cautious system can observe, alert, apply a narrow temporary action, verify effects, then escalate only when evidence supports it. | FlowGuard implements a narrow temporary drop after an alert. It does not implement a multi-stage mitigation policy or upstream traffic cleaning. |
| Expire and recover explicitly | Temporary rules avoid leaving a permanent block by accident. Expiry, rule removal, traffic reduction, and application recovery are separate facts and should be measured separately. | The rule has a 10-second hard timeout and flow-removal logging. The saved data shows removal; the dashboard should not equate that with general service recovery. |
| Avoid availability overclaims | A rule can filter traffic without the test showing that legitimate service was previously unavailable. | Both saved trials had 80/80 client replies. This demonstrates filtering in the measured setup, not improved availability or protection against upstream link saturation. |

For large-provider networks, [RFC 8955](https://www.rfc-editor.org/rfc/rfc8955.html) specifies a way to distribute BGP Flow Specification traffic filters using packet fields and actions. It is a rule-distribution mechanism, not an attack detector, policy-safety guarantee, or promise of availability. [GitHub’s report](https://github.blog/news-insights/company-news/ddos-incident-report/) describes shifting traffic toward Akamai and filtering at its border; a five-host lab switch cannot substitute for that scale of upstream response.

## A six-minute presentation story

1. **Start with the system (0:00–0:45).** Point to the five fixed hosts, one switch, and controller. Say: “The switch counts and forwards; the controller reads rates and installs a short rule.” Identify the victim’s UDP echo service on port 9000.
2. **Explain the decision (0:45–1:45).** Walk through the 100 packets/s victim threshold, two sources each above 30 packets/s, two consecutive high observations, and protected client .11. Use the 600 + 600 + 10 packets/s example. Clarify that a window is a counter observation, not a proof that a human attacker exists.
3. **Show the interactive model (1:45–2:45).** Play the sustained scenario, then show a one-window burst or single-source case. State explicitly that the values are deterministic model input passed into the real detector; no attack packets are sent and no switch rules are installed.
4. **Show historical evidence (2:45–4:00).** Open the saved on/off experiment. Point to the alert at 1.555 seconds, barrier reply at 1.634 seconds, victim rate change in the matched window, and the source-specific flows and removal evidence. Say “filtering was observed in this lab run.” Add that both trials delivered 80/80 client replies, so availability improvement was not demonstrated.
5. **Connect to GitHub (4:00–5:15).** Show the reported impact and peak, then explain spoofed-request memcached reflection. Emphasize that the victim sees reflector replies and the Internet-scale mitigation used upstream capacity. Do not suggest the lab replayed that event.
6. **Close with local proof and limits (5:15–6:00).** Run the five-probe localhost UDP check if useful. It proves a local echo exchange only. Finish with the contribution claim: an inspectable, reproducible integration with clear evidence boundaries, not a novel algorithm or a general DDoS protection service.

## Questions you may get in a viva

**What does SDN mean in this project?** The control logic is separated from the switch’s packet-forwarding logic. The OS-Ken controller programs OpenFlow rules and polls flow statistics; the Open vSwitch forwards matching packets.

**Why UDP?** The application is a simple UDP echo service, and UDP has easy-to-explain datagrams and source/destination ports. This makes the lab traffic easy to count by flow. It does not mean the detector protects every UDP service or all network protocols.

**Why use two consecutive windows?** To require persistence and ignore a single high observation. It adds nominally about another poll interval before alerting and can miss an attack that ends quickly. Actual timing varies with polling and event handling.

**Does the “two sources” rule identify a botnet?** No. It requires two eligible source IP addresses above threshold. It does not establish two physical attackers; spoofing, NAT, proxies, and reflectors complicate source identity. One source also falls below this detector’s configured source-diversity rule.

**What proves the drop worked?** The barrier reply alone only establishes message ordering. In the saved run, the case is supported by the installed flow dump, lower victim-received attacker counters, and subsequent flow-removal records. These support behavior in that experiment only.

**Did mitigation keep the client online?** The client got all 80 replies in both attack-off and attack-on trials. That is evidence the client worked in both measured runs; because the baseline also had no loss, it does not show improved availability under saturation.

**Is the GitHub event reproduced?** No. GitHub’s case was UDP reflection/amplification through third-party memcached servers. FlowGuard is a direct fixed-host UDP echo flood. The case teaches mechanism and scale differences.

**What is the project’s novelty?** The project does not claim a new detector. Its contribution is the integrated and reproducible lab, source-level rule scope, timed mitigation, evidence files, regression checks, and a presentation that distinguishes simulation from measurements.

**What would you add next?** Test more source patterns and higher rates, measure server and network capacity, improve error correlation/readback for rule installation, test single-source and low-rate defenses, and study upstream mitigation. Those require evidence and infrastructure beyond the current results.

## Run the local dashboard

From the project root, run:

    python demo/server.py

Open the address printed by the server, normally http://127.0.0.1:8765/. The server binds to loopback; Ctrl+C stops it. The interactive model and recorded experiment can be explored without a live attack. Choosing the live UDP check runs five probes against a temporary service bound to 127.0.0.1, then stops that service.

## Primary references

- [GitHub, “February 28th DDoS Incident Report”](https://github.blog/news-insights/company-news/ddos-incident-report/) — incident impact, reported rates, timeline, and response.
- [Cloudflare, “Memcrashed - Major amplification attacks from UDP port 11211”](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/) — reflection/amplification mechanism and Cloudflare’s vector example.
- [Open Networking Foundation, OpenFlow Switch Specification 1.3.0](https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf) — controller-switch protocol and flow-table behavior.
- [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html) — User Datagram Protocol.
- [RFC 791](https://www.rfc-editor.org/rfc/rfc791.html) — Internet Protocol version 4.
- [RFC 826](https://www.rfc-editor.org/rfc/rfc826.html) — Ethernet Address Resolution Protocol.
- [RFC 2827 / BCP 38](https://www.rfc-editor.org/rfc/rfc2827.html) — network ingress filtering against forged source addresses.
- [RFC 8955](https://www.rfc-editor.org/rfc/rfc8955.html) — BGP Flow Specification.

The implementation references and experiment files linked above are part of this project. The incident values are attributed to their original publishers; they are not reconstructed measurements.
