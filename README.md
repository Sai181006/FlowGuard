# FlowGuard

FlowGuard is a small SDN flood-detection lab with a native, offline presentation
for macOS and Windows. The dashboard uses a local Python HTTP server, vendored D3, and local
fonts. It binds to loopback and works without Linux, a VM, elevated privileges,
or external network access.

## Open the presentation

**Windows:** extract the complete `artifacts/FlowGuard-Windows-Demo.zip`, then
double-click **Start FlowGuard.cmd**. Double-click **Terminal Demo.cmd** for the
guided terminal presentation. Python 3.12+ is required; no pip packages are
needed for the native demos. See [WINDOWS_DEMO.md](WINDOWS_DEMO.md) for the
full rehearsal, Wireshark filters and original SDN implementation workflow.

**Mac:**

Double-click **Start FlowGuard.command** in this folder to start the server and
open your browser. Keep its terminal open during the presentation; Control+C
stops it. The launcher reuses an already running FlowGuard server.

Start the local server:

```sh
.venv/bin/python demo/server.py
```

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/) in a browser. The server
prints its address when it starts. Press Ctrl-C to stop it.

The dashboard has three modes:

- **Interactive model:** play the counter timeline, compare mitigation ON and
  OFF, and choose among six scenarios: normal traffic, a one-window burst, a
  sustained two-source load, repeated waves, one noisy source, and traffic
  below the victim threshold. The generated counters pass through the actual
  `CounterTracker` and `TwoWindowDetector` classes; the model sends no attack
  packets and installs no switch rules.
- **Recorded experiment:** inspect original `m6-attack-off` and
  `m6-attack-on` measurements, controller events, victim traces, and client
  probes. The recorded client results are 80/80 replies in each trial, with
  their original measured RTT rows.
- **Live UDP check:** send exactly five echo probes to a temporary service
  bound to `127.0.0.1`. The service stops after the check. This mode does not
  contact an SDN switch or send traffic outside this computer.

Use the mitigation switch to turn the modeled response ON or OFF and the
comparison control to inspect both outcomes. The settings panel changes the
source rate and the **assumed** server capacity. Press Space to play or pause,
use the left and right arrow keys to scrub, and press F for full screen. The `?`
button opens the presentation guide.

The packet desk's model rows are representative one-second flow records, not a
packet capture. Recorded mode keeps the original historical measurements.
Capacity, client success, and latency shown by the interactive model are
hypothetical; the recorded experiment did not measure server saturation. Both
recorded runs returned 80/80 client probes, so they do not demonstrate improved
availability under saturation.

The case-study page discusses GitHub's reported 28 February 2018 DDoS incident.
That event used spoofed UDP requests to third-party memcached reflectors; the
victim received reflected replies from those servers. FlowGuard's lab models a
direct UDP echo flood from fixed hosts to its own service. The GitHub case
provides context about reflection and scale; it is not a replay or validation
of this lab. See [GitHub's incident report](https://github.blog/news-insights/company-news/ddos-incident-report/)
and [Cloudflare's explanation of the memcached vector](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/).

## Setup and other commands

The native dashboard needs only Python's standard library at runtime. The
existing project environment and its test dependencies can be prepared with:

```sh
bash scripts/setup.sh
```

The original command-line demos remain available:

```sh
.venv/bin/python demo/run.py --scenario detector --step
.venv/bin/python demo/run.py --scenario recorded
.venv/bin/python demo/run.py --scenario loopback
```

The complete new terminal presentation includes a preflight, explained detector
walkthrough, saved OpenFlow evidence and an actual localhost OFF/ON comparison:

```sh
.venv/bin/python demo/terminal.py --step
```

For just real packet filtering, run `.venv/bin/python demo/live_lab.py`.
This reuses the original detector, echo server and probe, enforcing temporary
drops through a Python UDP gateway. It records actual received datagrams,
matching victim echo replies, client RTTs and recovery checks. It does not
install OpenFlow rules. The checked Mac run returned 230/230 client probes in
each mode and actually discarded 7,198 datagrams with mitigation ON. The new
Windows launchers and native runtime must still be rehearsed on Windows.

The full Mininet/Open vSwitch experiment requires a suitable Linux lab and is
outside the native dashboard workflow. This repository's current hardening has
unit coverage for mocked OpenFlow messages and saved experiment artifacts; it
has not been confirmed against a live switch runtime. The saved `m6` results
predate these hardening changes.

Run the complete current test suite with:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

At this checked revision, all 50 tests pass. The focused offline regression
runner is:

```sh
.venv/bin/python demo/run.py --scenario bugs
```

Despite the retained CLI name, it now runs positive security and experiment-
integrity regression checks. Its JSON output says what those checks cover. The
initial upstream audit evidence remains in [AUDIT.md](AUDIT.md) and
[`audit/reproductions-original.json`](audit/reproductions-original.json);
[`audit/reproduce.py`](audit/reproduce.py) now runs the current regressions.
The full original Mininet/Open vSwitch topology was not run on this Mac.
