# FlowGuard presentation guide

> **Advanced networking branch.** The dashboard now also offers pulsing,
> slow-ramp, flash-crowd, three-source and repeat-offender stories, four
> detectors, rate-limit/graduated responses, back-off and a bottleneck queue
> ("Tune the model"), plus an offline detector benchmark on the "Behind the
> scenes" page. Commands and talk tracks: [docs/SCENARIOS.md](docs/SCENARIOS.md)
> and the 10-minute advanced review in [docs/DEMO.md](docs/DEMO.md#advanced-review-10-minutes).
> Measured native bottleneck results: [docs/RESULTS.md](docs/RESULTS.md#m9-advanced-results).

The complete Windows/terminal/packet-capture runbook is
[WINDOWS_DEMO.md](WINDOWS_DEMO.md). It includes an eight-minute presentation
sequence, native Windows launchers, actual localhost filtering, exact Wireshark
filters, and a separate workflow for the original OpenFlow implementation in
an existing SDN lab.

## Start the offline dashboard

On this Mac, start the server from the project directory:

```sh
.venv/bin/python demo/server.py
```

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/). The server binds only to
localhost. The dashboard's JavaScript, D3 library, fonts, and icons are served
from the project; the presentation does not depend on a CDN or a Linux VM.
Press Ctrl-C in the terminal to stop the server.

The top navigation opens **The network**, **The real incident**, and **Behind
the scenes**. The `?` button opens the built-in presentation guide. Keyboard
shortcuts: Space plays or pauses, left/right arrows scrub, and F toggles full
screen.

## A five-minute walkthrough

### 1. Start with the interactive model

Choose **Interactive model**, leave mitigation ON, and play **The coordinated
flood**. The timeline begins with ordinary traffic, starts two 600 packets/s
sources at five seconds, passes generated one-second counters through the actual
`CounterTracker` and `TwoWindowDetector`, and models the configured temporary
rules. The first alert is at seven seconds. The modeled 10-second rules expire
and the detector can alert again if the sources continue.

The settings panel changes the rate and a hypothetical server capacity. Use the
ON/OFF mitigation switch and **Compare both outcomes** to show how the same
offered traffic affects the model. Capacity, server load, client success, and
latency are assumptions for this demonstration; they are not measurements from
the original lab. The model does not send attack traffic or contact Open
vSwitch.

The scenario selector includes six cases:

- **An ordinary day:** low source traffic and a protected 10 packets/s client.
- **The innocent burst:** one high window, which does not meet the consecutive-
  window rule.
- **The coordinated flood:** sustained high traffic from two sources.
- **The second wave:** repeated traffic shows temporary rule expiry and later
  redetection.
- **One very noisy source:** the configured detector requires at least two
  eligible sources.
- **Below the radar:** the aggregate remains under the victim threshold.

Packet desk rows in the interactive model are representative one-second flow
records. They are not a Wireshark capture or per-packet observations.

### 2. Compare with the recorded experiment

Switch to **Recorded experiment**. It loads the original matched files in
`results/m6-attack-off` and `results/m6-attack-on`, including controller
events, victim receive counters, and client probe rows. The historical runs
were recorded on 13 October 2026, before the current hardening changes.

The saved experiment used two sources sending 600 packets/s each for eight
seconds. In the attack-on run, the first alert was recorded about 1.55 seconds
after attack start and the first drop confirmation about 1.63 seconds after
start. In the selected matched window, victim-received attacker traffic was
about 1,200 packets/s without mitigation and zero with mitigation. The client
received 80/80 probes in both runs. Those measurements demonstrate filtering
in that recorded lab run; they do not demonstrate improved availability under
saturation, because the unmitigated trial also had no client loss.

Recorded charts and probe rows retain actual historical data. Fields such as
attack-relative time are derived from the saved timestamps and are identified
as derived by the dashboard.

### 3. Explain the real-world case

The incident page discusses GitHub's reported DDoS incident of 28 February
2018. The attack used spoofed UDP requests to exposed third-party memcached
servers, which reflected larger replies toward GitHub. The source addresses
visible at a victim can therefore be reflectors rather than the machine that
initiated the attack.

FlowGuard's lab is different: fixed hosts send direct UDP echo traffic to a
small service in a closed five-host topology. It does not include memcached
reflectors, spoofed Internet traffic, provider scrubbing, BGP rerouting, or
terabit-scale capacity. The case is context about mechanism and scale, not a
replay or proof of FlowGuard's behavior. GitHub's reported figures and response
timeline are in [its incident report](https://github.blog/news-insights/company-news/ddos-incident-report/);
Cloudflare's [memcached reflection explanation](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/)
describes the vector.

### 4. Finish with the live localhost check

Choose **Live UDP check** and run it. The dashboard starts the project's real
echo server bound to `127.0.0.1` on a temporary port, sends exactly five real
UDP probes using the existing probe script, displays the CSV and RTT summary,
then stops the service. This proves the local UDP echo path works. It does not
exercise the SDN switch or generate a flood.

## Command-line walkthroughs remain available

For the complete guided terminal demonstration on this Mac:

```sh
.venv/bin/python demo/terminal.py --step
```

For its real localhost OFF/ON comparison alone:

```sh
.venv/bin/python demo/live_lab.py
```

The new live comparison uses the actual detector classes on real forwarded
packet counters, the original echo service and the original probe program.
Temporary rules discard datagrams in a Python gateway. It checks real echo
replies, protected-client success, rule expiry and source recovery. Its CSV is
an application observation log; use a separate capture tool for PCAP. The
gateway demonstrates the policy on actual packets, while the full original
OpenFlow forwarding and ARP controls require the existing SDN lab.

These original CLI modes are still supported:

```sh
.venv/bin/python demo/run.py --scenario detector --step
.venv/bin/python demo/run.py --scenario recorded
.venv/bin/python demo/run.py --scenario loopback
```

`detector` uses simulated counters with the real detector classes. `recorded`
recalculates historical trial summaries. `loopback` runs ten real localhost
UDP probes, as before. The dashboard's live check is separate and uses five
probes.

The `bugs` CLI option keeps its historical name but now runs positive offline
regression checks:

```sh
.venv/bin/python demo/run.py --scenario bugs
```

The JSON result identifies the security and experiment-integrity suites.
Passing tests verify current code against mocked OpenFlow messages and saved
artifacts; they are not confirmation of hardening on a live switch. The
original 20 October upstream audit is preserved in [AUDIT.md](AUDIT.md) and
[`audit/reproductions-original.json`](audit/reproductions-original.json).
Use [`audit/reproduce.py`](audit/reproduce.py) to rerun the current focused
regressions. All 50 tests in the current full suite pass at this checked
revision:

```sh
.venv/bin/python -m unittest discover -s tests -v
```
