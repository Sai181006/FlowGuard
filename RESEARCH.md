# FlowGuard dashboard research

Prepared 20 October 2026. Scope: current FlowGuard behavior, a documented
real-world DDoS case, defensible defensive explanations, and browser technology
for an offline presentation.

## Recommendation

Use GitHub's 28 February 2018 memcached amplification incident as the dashboard's
real-world case. GitHub published a first-party timeline with reported peak rate,
packet rate, impact, and mitigation sequence. Cloudflare, which observed this
memcached vector at its network, explains how a small spoofed UDP request can
cause large replies from exposed third-party servers. The case makes a useful
teaching point: at the victim, packet source IPs can identify reflectors rather
than the host that initiated the attack.

Present this as a comparison case, not a replay or validation of FlowGuard.
FlowGuard models a direct UDP echo flood in a small, fixed-host lab. It has no
memcached reflectors, spoofed Internet traffic, DNS service, BGP rerouting, or
upstream scrubbing capacity. Its controller demonstrates rate calculation,
sustained multi-source detection, and a narrow lab drop rule; it cannot support
claims about mitigating a terabit-scale Internet attack.

Primary case sources: [GitHub's incident report](https://github.blog/news-insights/company-news/ddos-incident-report/)
and [Cloudflare's contemporaneous memcached report](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/).

## Verified incident facts

| Claim for the dashboard | Evidence and safe wording |
|---|---|
| Date and user impact | On 28 February 2018, GitHub.com was unavailable from 17:21 to 17:26 UTC and intermittently unavailable until 17:30 UTC. GitHub said data confidentiality and integrity were not at risk. Attribute these times and impact to [GitHub's report](https://github.blog/news-insights/company-news/ddos-incident-report/). |
| Attack mechanism | The vector abused public memcached servers with UDP enabled. The attacker sent a request with a spoofed source address, so each reflector sent its response toward that address. GitHub described amplification of up to about 51,000 times. See [GitHub's account](https://github.blog/news-insights/company-news/ddos-incident-report/) and [Cloudflare's technical explanation](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/). |
| Reported scale | GitHub reported a peak of 1.35 Tbps and 126.9 million packets per second. It reported traffic spanning more than 1,000 autonomous systems and tens of thousands of unique endpoints. Keep the attribution “GitHub reported”; this research did not independently reconstruct those values. [GitHub incident report](https://github.blog/news-insights/company-news/ddos-incident-report/). |
| Amplification example | Cloudflare's technical example shows a 15-byte request producing a response of up to 750 kB and identifies UDP port 11211. This is Cloudflare's example of the vector, not a packet capture of the GitHub event. Cloudflare identifies the responding hosts it observed as vulnerable memcached servers. [Cloudflare report](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/). |
| Response sequence | At 17:21 UTC GitHub's monitoring detected an unusual ingress-to-egress ratio. After inbound transit at one facility exceeded 100 Gbps, GitHub began moving its announcements to Akamai at 17:26. Routes reconverged and ACLs at Akamai's border mitigated the attack. GitHub reported full recovery at 17:30 and a later 400 Gbps spike shortly after 18:00. The 100 Gbps figure is for one facility, not the attack peak. [GitHub incident report](https://github.blog/news-insights/company-news/ddos-incident-report/). |

An accurate mechanism illustration is:

> initiator sends a small UDP request with GitHub's address forged as the source
> → exposed memcached server replies toward GitHub
> → many reflectors send large UDP responses toward GitHub
> → GitHub reroutes traffic to Akamai
> → Akamai edge ACLs filter the attack traffic

This is a mechanism illustration, not a recovered packet trace. The public
incident report does not supply the full per-packet time series or reflector list
needed to recreate a faithful animated curve. Show the peak as a labeled point or
badge. Do not invent intermediate values or animate a fabricated curve as
measured incident data.

## What the current FlowGuard worktree models

The project describes its presentation modes in [DEMO.md](DEMO.md). The detector
and defaults are in [controller/detection.py](controller/detection.py) and
[config/detector.json](config/detector.json); forwarding and mitigation logic are
in [controller/forwarding.py](controller/forwarding.py).

| Area | Current behavior | Dashboard wording |
|---|---|---|
| Topology and identity | Five fixed lab hosts use 10.0.0.10, .11, .21, .22, and .23. The current controller maps known MAC/IP identities to configured switch ports, checks IPv4/MAC source and destination pairings, and validates ARP sender fields. These are fixed-lab checks, not Internet-wide source authentication. | “Fixed five-host Mininet lab.” Do not call these hosts anonymous Internet attackers. |
| Traffic counted | OpenFlow counters cover IPv4 UDP to victim 10.0.0.10 on destination port 9000. Counter deltas are divided by elapsed monotonic time and grouped by IPv4 source. The protected service is a UDP echo port. | “Direct UDP echo traffic to :9000.” The incident also used UDP, but its memcached responses came from third-party reflectors and did not target the lab's echo service. |
| Detection | Defaults are 1-second polling, victim rate greater than 100 packets/s, at least two unprotected sources each greater than 30 packets/s, and two consecutive qualifying observations. The protected lab client is 10.0.0.11. A non-high observation resets the consecutive count. See [detector code](controller/detection.py) and [configuration](config/detector.json). | “Two consecutive counter observations” is precise. “Two seconds” is only nominal because polling and replies can vary. |
| Mitigation | A high-priority drop rule matches one lab source, victim, IPv4 UDP, and destination port 9000. Default hard timeout is 10 seconds. While an alert remains active, the current controller rechecks qualifying sources and can reinstall a rule after expiry. See [forwarding code](controller/forwarding.py). | Show one source-specific, time-limited lab rule. It is not an upstream scrubber or BGP mitigation. |
| Demo evidence | The detector walkthrough feeds simulated cumulative counters to the actual detector. The recorded scenario recalculates saved lab results. The loopback scenario is local UDP echo only. See [DEMO.md](DEMO.md). | Label each view “simulated counter walkthrough,” “recorded lab experiment,” or “live localhost echo.” None is a live GitHub incident replay. |

### Audit-file version caveat

[AUDIT.md](AUDIT.md) says it reviewed upstream commit
8bd3f5877aebda8c71e57f0790c4d340e57a7318. Its FG-01 through FG-04 findings
describe older controller behavior. The current worktree contains fixed
MAC/IP-to-port checks, ARP sender validation, rejection of group-addressed or
inconsistent IPv4/MAC destinations, UDP :9000-specific counters, and active
mitigation reconciliation. Do not present those four older findings as verified
defects in the current code. The audit's warning that a barrier reply is logged as
“drop confirmed” without correlating OpenFlow errors or reading the installed
flow remains relevant. I did not independently re-run the audit reproductions or
test the current changes for this research task.

## Defensive features worth explaining

These are design recommendations for an educational defense story. Label them
as guidance unless the behavior is explicitly present in the current lab.

1. **Bind identity at ingress.** In a fixed switch lab, map an allowed host's
   expected MAC and IP to its physical switch port and enforce the mapping before
   forwarding. The current code has this binding. On the public Internet,
   customer-network ingress filtering can reduce packets with forged source
   prefixes; [IETF BCP 38, RFC 2827](https://www.rfc-editor.org/rfc/rfc2827.html)
   describes this control. RFC 2827 also states it does not stop floods using
   valid source prefixes. It cannot identify an attacker from traffic relayed by
   a memcached server with a real address.

2. **Treat source as evidence, not proof of who attacked.** In the GitHub case,
   a visible sender of the large replies is a memcached server, not necessarily
   the host that sent the spoofed request. A rule that blocks every apparent
   source can affect those servers' unrelated traffic. Match service and traffic
   context narrowly, and coordinate large-volume filtering with the transit or
   mitigation provider. [RFC 8955](https://www.rfc-editor.org/rfc/rfc8955.html)
   defines a way to distribute rules using fields such as source and destination
   prefixes, protocol, and ports, with actions including filtering and rate
   limiting. It is a rule-distribution standard; it does not detect attacks,
   establish that a match is safe, or guarantee availability.

3. **Explain burst tolerance as a chosen tradeoff.** FlowGuard requires two
   consecutive high observations, so one high observation is not enough to alert.
   This filters a one-sample spike in the model, but it also delays detection and
   may miss a shorter attack. Thresholds are lab configuration, not universal
   safe values. A more advanced design could use separate high and recovery
   thresholds (hysteresis), but the current detector resets on any non-high
   observation and does not implement that behavior.

4. **Show sustained rate and source count separately.** The current rule is:
   victim rate above 100 packets/s and at least two eligible source IPs each
   above 30 packets/s for two consecutive observations. This is a small,
   deterministic lab rule, not a learned baseline. The minimum source count is
   not a maximum source-cardinality limit. A source IP count is not a bot count:
   spoofing and reflection can make the observed source set diverge from the
   initiating hosts. Label counts “observed source IPs” or “reported endpoints,”
   never “attackers” without supporting evidence.

5. **Make mitigation narrow, progressive, and observable.** The current lab
   installs a temporary exact source/victim/protocol/service drop. That is
   source-specific enforcement, but it is not a sequence of severity-based
   mitigations. For an educational design, show: observe → alert → review a narrow
   match → install temporary policy → inspect drop and legitimate-client counters
   → remove or renew deliberately. For provider-scale volume, show the actual
   case's route change to a mitigation network and edge filtering instead of
   implying a five-host switch can absorb or clean 1.35 Tbps.

6. **Represent expiry and recovery as separate facts.** The default lab rule
   expires after 10 seconds and the controller records a flow-removed event. This
   demonstrates a bounded rule lifetime, not proof that an application recovered.
   The controller logs a barrier reply as “drop confirmed”; the audit notes that
   this establishes message ordering, not successful rule installation without
   error correlation or flow readback. A dashboard should say “rule requested,”
   “barrier reply received,” and “flow removed” unless it has direct evidence for
   stronger labels.

7. **Avoid unsupported availability claims.** [DEMO.md](DEMO.md) reports 80/80
   legitimate probes both with and without mitigation, including at the highest
   saved unmitigated load. The saved experiment supports that filtering occurred
   in that lab run; it does not show improved availability because the baseline
   also had no probe loss. It does not establish resilience to a saturated,
   adaptive, spoofing, reflective, or Internet-scale adversary.

## Browser implementation recommendation

For a live presentation, prefer a self-contained HTML page with local CSS, inline
SVG, small local JavaScript, and no CDN requests. A five-host network diagram,
four incident timestamps, one peak statistic, and a handful of event rows do not
need visualization frameworks. Keep GitHub incident facts, saved FlowGuard
results, simulated counters, and design recommendations in visibly separate
panels. Label each source and unit, and use separate scales for Tbps/Mpps
incident measurements and packets/s lab thresholds.

| Need | Candidate | Assessment |
|---|---|---|
| Data-driven SVG or Canvas graphics | [D3 documentation](https://d3js.org/) | D3 provides selections/data joins, scales, shapes, interactions, and transitions. It is appropriate if the dashboard needs coordinated animated SVG elements, and can be bundled locally with only the modules used. Its lower-level flexibility also means more code and care than inline SVG for this small fixed story. Keep data and animation deterministic; do not imply fabricated values are measurements. |
| Small time-series chart | [uPlot project and documentation](https://github.com/leeoniya/uPlot) | A focused Canvas chart for time series. The project's benchmark lists 47.9 KB for uPlot v1.6.24 and larger historical bundles for Chart.js and ECharts; treat those as the maintainer's 2023 test, not a current independent comparison. Use it only if real, ordered samples are worth plotting. It cannot turn a peak-only incident report into a measured time series. |
| General charts and chart animation | [Chart.js performance](https://www.chartjs.org/docs/latest/general/performance.html), [animation](https://www.chartjs.org/docs/latest/configuration/animations.html), and [integration](https://www.chartjs.org/docs/latest/getting-started/integration.html) | A reasonable option for several conventional chart types. Its docs support local UMD files, configurable animation, and disabling animation for performance. Bundle a pinned local build; a CDN reference would make an offline demo depend on Internet access. It is unnecessary for the small factual timeline here. |
| Interactive topology graph | [Cytoscape.js documentation](https://js.cytoscape.org/) | Supports interactive graph display, user events, panning, zooming, and graph analysis. Useful for a larger explorable network, but excessive for the fixed five-host topology. Inline SVG gives direct control over labels and packet direction with no graph library. |
| Packet/event table | [Tabulator quickstart](https://www.tabulator.info/docs/6.x/quickstart/) | Offers sorting, filtering, and a virtual DOM for very large tables. The presentation has a small set of explained events, so a semantic HTML table is lighter, easier to print, and more dependable offline. Consider Tabulator only if people must search or filter large local JSONL captures. |
| Short animations | [Web Animations API, Element.animate()](https://developer.mozilla.org/en-US/docs/Web/API/Element/animate) | Browser-native finite animations need no external package. Animate generic packet markers through the illustrated path, not a claimed live packet trace. Provide pause/replay and respect reduced-motion preferences. |

If a library is selected, pin its version and ship the required JavaScript and CSS
beside the page. Avoid runtime CDN imports, live APIs, fonts, and remote images so
the presentation still opens without Internet access. Prefer a static annotated
incident timeline over continuously moving packets; motion should explain the
reflector path, not imply a measured time series.

## Five-minute presentation story

| Time | Story and visual |
|---|---|
| 0:00–0:40 | Open with reported impact: GitHub.com was unavailable for five minutes and intermittently unavailable for four more. Pin the date, UTC times, and source link. State that GitHub reported no confidentiality or integrity impact. |
| 0:40–1:30 | Animate the mechanism with four labeled nodes: initiator, exposed memcached reflector, GitHub edge, Akamai. Show a small request with a spoofed source becoming many large UDP replies. Explain that the victim sees reflectors, not necessarily the initiating machine. Cite GitHub and Cloudflare. |
| 1:30–2:15 | Show the reported scale as two labeled values: 1.35 Tbps and 126.9 Mpps. Add that GitHub reported traffic across 1,000+ ASNs and tens of thousands of endpoints. Do not invent values between the documented timestamps. |
| 2:15–3:00 | Show the response timeline: anomaly detected at 17:21 UTC; traffic shifted toward Akamai beginning at 17:26; edge ACLs filtered after routes reconverged; full recovery reported at 17:30. Distinguish the facility's over-100-Gbps trigger from the reported 1.35-Tbps attack peak. |
| 3:00–4:00 | Switch to a panel labeled “FlowGuard lab model.” Show five fixed hosts, UDP echo victim on :9000, thresholds (100 victim pps, 30 pps/source, two sources, two consecutive observations), and ten-second temporary rule. Explain that the detector walkthrough uses simulated counters and saved results are a separate lab experiment. |
| 4:00–5:00 | Put the two mechanisms side by side: direct source-attributed UDP echo flood in FlowGuard versus spoofed-request UDP reflection through third-party memcached. Close with the teaching point: bind identities at the lab edge, treat source IP as a signal rather than attacker identity, use narrow expiring rules, verify rule and client outcomes, and report only what measurements support. State that current saved on/off probe results do not prove an availability improvement. |

## Sources and provenance

- [GitHub, “February 28th DDoS Incident Report”](https://github.blog/news-insights/company-news/ddos-incident-report/) — first-party incident date, impact, reported rates, timeline, and mitigation actions.
- [Cloudflare, “Memcrashed - Major amplification attacks from UDP port 11211”](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/) — network-operator observations and technical explanation of memcached reflection/amplification.
- [IETF RFC 2827 / BCP 38](https://www.rfc-editor.org/rfc/rfc2827.html) — ingress filtering against forged source prefixes and its stated limits.
- [IETF RFC 8955](https://www.rfc-editor.org/rfc/rfc8955.html) — BGP Flow Specification match fields and traffic-filtering actions.
- [D3 docs](https://d3js.org/), [uPlot project](https://github.com/leeoniya/uPlot), [Chart.js docs](https://www.chartjs.org/docs/latest/), [Cytoscape.js docs](https://js.cytoscape.org/), [Tabulator docs](https://www.tabulator.info/docs/), and [MDN Web Animations API](https://developer.mozilla.org/en-US/docs/Web/API/Element/animate) — capabilities cited in the browser-options section.
