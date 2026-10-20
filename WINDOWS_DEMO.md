# FlowGuard: Windows, terminal and packet-capture demonstration

## Recommended arrangement

Use **Windows + Python 3.12 or newer** for the dashboard and the new live
terminal lab. Add **Wireshark with Npcap** if it is already available, or prepare
it on the presentation laptop before going offline. Run everything on
`127.0.0.1`; no network access, Linux installation or virtual machine is needed
for this arrangement. Keep this Mac and the original recorded results as the
fallback until the Windows laptop has passed its own rehearsal.

There are three different things to show, with different evidence:

| Demonstration | What executes | What it establishes |
|---|---|---|
| Dashboard model | Original detector on generated counters; animated assumed outcomes | Explains thresholds, flow and tradeoffs |
| New native terminal lab | Original detector, original echo server and original probe; real UDP sockets; Python gateway actually discards selected datagrams | Live detection, selective filtering, client replies and rule expiry on localhost |
| Original SDN implementation | OS-Ken controller, OpenFlow 1.3, OVS and five Mininet hosts in an **existing** Linux lab | Real switch rule installation, switch counters and end-to-end lab behavior |

The native gateway demonstrates the detection and mitigation idea using real
packets. It does not emulate OpenFlow, run the full forwarding controller, or
reproduce the controller's Ethernet/ARP protections. Mininet uses Linux network
facilities; its official setup offers Linux installation or a Linux VM. Running
the original topology directly in native Windows is not the recommended route.
See the [Mininet installation guide](https://mininet.org/download/).

No Linux/WSL installation commands are included here. If no existing SDN lab
is available, present the native live lab and identify the original switch
evidence as recorded. Do not describe recorded results as a new live test.

## 1. Move the complete demo to Windows

Copy `artifacts/FlowGuard-Windows-Demo.zip` to the laptop and choose **Extract
All**. Work inside its extracted `FlowGuard` folder, for example
`C:\FlowGuard`. The package includes the local changes, fonts, D3, documentation
and original experiment files. A fresh clone of the upstream GitHub repository
does not include these local additions until they are published.

Python must already be installed before the offline presentation. The launchers
look for `py -3`, then `python`, and require Python 3.12+. They use the standard
library; **do not install `requirements.txt` for this native demonstration**.
Those requirements also describe the Linux SDN environment. The Mac's `.venv`
is deliberately excluded from the Windows package.

Open PowerShell in the extracted project folder:

```powershell
py -3 --version
py -3 demo/terminal.py --doctor
py -3 -m unittest tests.test_detection tests.test_demo_engine tests.test_live_lab -v
```

The portable subset contains 21 tests. It checks the detector, dashboard
engine/server protections, and real-socket forwarding/drop behavior without
Mininet or OS-Ken. If `py` is unavailable but `python` works, substitute
`python`, or use `scripts\python-windows.cmd` from Command Prompt.

Double-click **Start FlowGuard.cmd** for the dashboard. It opens
`http://127.0.0.1:8765/`; keep the terminal open. Ctrl+C stops it. An existing
FlowGuard dashboard on that port is reused.

Double-click **Terminal Demo.cmd** for the complete terminal presentation.
It pauses between sections and detector windows, allowing you to explain each
step. The equivalent command is:

```powershell
py -3 demo/terminal.py --step
```

For an automatic rehearsal without pauses:

```powershell
py -3 demo/terminal.py
```

## 2. Complete terminal presentation

The command runs three sections in order:

1. **Detector walkthrough.** Explain cumulative counter differences, rates,
   and two consecutive qualifying observations. The inputs in this section
   are generated, and the actual project detector computes the answers.
2. **Original SDN evidence.** Recalculate the saved OFF/ON experiment, then
   display the actual saved switch drop rules and controller events. Point to
   `actions=drop`, `priority=200`, `hard_timeout=10`, source, victim and port.
3. **Real localhost comparison.** Start a packet capture before pressing
   Enter for this section. The command runs mitigation OFF, then ON. Each trial
   lasts about 24 seconds at the defaults; both together take about 48 seconds.

For just the live comparison:

```powershell
py -3 demo/live_lab.py --mitigation compare
```

Or run two separate captures, choosing fresh output directories each time:

```powershell
py -3 demo/live_lab.py --mitigation off --output artifacts/rehearsal-off
py -3 demo/live_lab.py --mitigation on --output artifacts/rehearsal-on
```

The script rejects an existing output directory. Change the name for another
attempt. The source rate is bounded to 100–2,000 packets/s per source and the
attack phase to 4–30 seconds. There is no external target option.

### Understand the real socket path

All on-wire addresses are `127.0.0.1`. Ports identify local actors:

```text
client :19011 ─┐
source A :19021├──> gateway :19001 ──> backend :19002 ──> echo service :19000
source B :19022┘           <──────── actual echo reply path ────────────────
```

The detector sees logical labels `10.0.0.11`, `.21`, and `.22` mapped from
those known localhost source ports. These are **labels**, not separate source
IP addresses on the captured packets. This mapping is not source authentication.
The gateway is a UDP proxy: it forwards a permitted request from backend port
19002, matches the echoed payload to its original sender, and relays the reply.

Each trial follows this sequence:

| Approximate trial time | Action | What to point out |
|---|---|---|
| 0–2 s | Client sends 10 probes/s; sources send 2 packets/s each | Normal forwarding and real replies |
| 2–10 s | Each source offers 600 packets/s | The aggregate exceeds the detector's configured thresholds |
| Around 4 s | Second high observation generates an alert | Actual scheduling can shift this time; use the logged event |
| After alert, ON trial | Two temporary gateway drop rules are applied | Offered traffic continues; only selected datagrams are discarded |
| Around 14 s | Ten-second drop rules expire | The event log records actual expiry |
| 10–21 s | Flood has stopped; wait beyond the configured rule lifetime | Client keeps probing; no simulated server capacity is imposed |
| 21–23 s | Sources return to low-rate traffic | Echo replies prove source recovery after expiry |

The detector receives **forwarded cumulative counts**, like the service flows
in the original controller; dropped packets have separate counters. The live
gateway enforces its rule immediately after an actual detector decision. It
has no OpenFlow messaging delay, so its timing is not a switch-performance
benchmark.

### Read the terminal and evidence

The terminal prints rates, alert decisions, real cumulative drops, active rule
counts, expiry, recovery checks and an OFF/ON comparison. Results are written
under a unique `artifacts/terminal-runs/<timestamp>/` folder:

| File | Contents |
|---|---|
| `comparison.json` | Both trial summaries, provenance, platform and checks |
| `off/summary.json`, `on/summary.json` | Actual offered/forwarded/dropped counts, matching victim echo replies, client results and acceptance checks |
| `events.jsonl` in each mode | Timestamped samples, alerts, gateway rules, expiry and phases |
| `packets.csv` | Each actual datagram received at the gateway, its source port, payload prefix and forwarding/drop decision |
| `client.csv` | Original probe program's actual replies and measured RTTs |
| `victim.jsonl` | Original echo service's receive windows; its visible sender is the proxy on 127.0.0.1 |
| `server.log`, `client.log` | Subprocess startup and final probe counts |

`packets.csv` is an application observation log, **not PCAP**. Victim replies
are counted only when the real echo payload comes back from the expected
server port. A PASS requires complete client replies, an actual alert, expected
filtering, no client drops, expired rules, source recovery, no gateway errors,
and a matching echo for every forwarded request. Interrupted/failed runs are
marked accordingly and return a nonzero exit code.

The checked Mac run is saved in `artifacts/terminal-verified/`:

| Mode | Actual source ingress | Actual victim echo replies to sources | Gateway drops | Client |
|---|---:|---:|---:|---:|
| OFF | 9,616 | 9,616 | 0 | 230/230 |
| ON | 9,616 | 2,418 | 7,198 | 230/230 |

These totals include normal and recovery traffic. During the beginning of the
ON attack, packets are forwarded until the detector has enough observations.
Counts vary with OS scheduling. The fact that both clients succeed means this
run establishes filtering and isolation, not improved availability under
server saturation.

## 3. Wireshark: actual packet capture on Windows

Wireshark's Windows loopback instructions specify **Npcap** and the interface
named **Adapter for loopback traffic capture**. Select that interface; Wi-Fi or
Ethernet will not show this localhost path. The native terminal lab itself
needs no administrator privileges. Capturing may require elevated Wireshark
depending on the existing Npcap installation's access settings. See the
[official loopback guide](https://wiki.wireshark.org/CaptureSetup/Loopback).

Start a new capture before the live section. Enter this **capture filter** in
the capture options:

```text
udp and (port 19000 or port 19001 or port 19002 or port 19011 or port 19021 or port 19022)
```

Stop and save as `flowguard-off.pcapng` or `flowguard-on.pcapng` after the
corresponding run, or capture the entire comparison in one file. Avoid counting
all loopback packets as requests: the proxy and echo create several datagrams
for each successful transaction.

Use these **display filters** in the main packet view:

| What to show | Display filter |
|---|---|
| Source requests offered to gateway | `udp.dstport == 19001 && (udp.srcport == 19021 || udp.srcport == 19022)` |
| Source requests that reached the victim | `udp.dstport == 19000 && udp.payload contains "flowguard:"` |
| Protected client's requests | `udp.srcport == 19011 && udp.dstport == 19001` |
| Protected client's replies | `udp.srcport == 19001 && udp.dstport == 19011` |
| Every request received by victim | `udp.dstport == 19000` |

The payload filter uses the `udp.payload` field documented in Wireshark's
[UDP field reference](https://www.wireshark.org/docs/dfref/u/udp.html).

Capture filters use pcap syntax; display filters use Wireshark syntax. Do not
paste a display filter into the capture-filter box. The distinction is covered
by the [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html).

For the clearest graph, open **Statistics → I/O Graphs**, use a **1 second**
interval, **Packets** on the Y axis, and add three graph rows:

1. **Offered by sources**, using the first display filter above, copper.
2. **Reached victim**, using the second filter, plum.
3. **Protected client replies**, using the fourth filter, green.

Disable the unfiltered default graph. In the ON trial, the copper line should
remain high while the plum line falls after the decision; the green line
continues. In the OFF trial the source request lines stay close. Graph filters
and intervals are supported by the
[official I/O Graphs guide](https://www.wireshark.org/docs/wsug_html_chunked/ChStatIOGraphs.html).

Click a source request. Expand IP and UDP and inspect the payload containing
`flowguard:a1:attack` or `flowguard:a2:attack`. Click a client packet and inspect
`ddos-probe`. This demonstrates UDP ports, payloads and request/reply behavior.
Loopback has no physical Ethernet hop; do not expect an ARP exchange here.

A capture cannot label an application's internal action as “DROP.” Establish
that explanation by correlating continued gateway ingress, missing forwarded
copies, matching timestamps and the gateway's actual drop counter/log. Save the
PCAP alongside the evidence folder from that same run.

### Optional all-terminal capture with Dumpcap and TShark

In PowerShell, first list capture interfaces:

```powershell
& "$env:ProgramFiles\Wireshark\dumpcap.exe" -D
```

Use the number shown for the loopback capture adapter. The example asks you
to enter it instead of assuming an adapter number:

```powershell
$captureInterface = Read-Host "Number of the loopback capture adapter"
& "$env:ProgramFiles\Wireshark\dumpcap.exe" -i $captureInterface -f "udp and (port 19000 or port 19001 or port 19002 or port 19011 or port 19021 or port 19022)" -a duration:70 -w artifacts/flowguard-live.pcapng
```

While capture runs, start `py -3 demo/live_lab.py` in a second terminal. It takes
about 48 seconds, leaving time to switch windows. Stop the capture early with
Ctrl+C if needed. Dumpcap's `-D`, `-i`, `-f`, `-a` and `-w` flags are documented
in its [official manual](https://www.wireshark.org/docs/man-pages/dumpcap.html).

Inspect real victim-bound packets after capture:

```powershell
& "$env:ProgramFiles\Wireshark\tshark.exe" -r artifacts/flowguard-live.pcapng -Y "udp.dstport == 19000" -T fields -e frame.time_relative -e ip.src -e udp.srcport -e udp.dstport -e udp.length -e udp.payload
```

For only live application logs, no capture software is necessary. Open the
printed run folder and use PowerShell's `Get-Content <path> -Tail 5 -Wait` for
`events.jsonl` while that run is active, or `Import-Csv <path>` for its packet
and client CSVs. This is the reliable fallback when Npcap is absent.

## 4. Show the original implementation in an existing SDN lab

Use this optional route only if an existing Linux Mininet/OVS setup is already
available through WSL2 or SSH. Windows can be the presentation terminal. Merely
having WSL listed does not establish that its kernel, OVS and Mininet work.
Do not copy the Mac virtual environment to it, and do not run setup commands
that install Linux for this presentation.

Copy the full current project source into that lab. In a shell **inside the
existing Linux environment**, from the project root, select its already
prepared Python interpreter:

```sh
FLOWGUARD_LAB_PY="$(command -v python3)"
"$FLOWGUARD_LAB_PY" -c 'import mininet, os_ken; print("SDN Python packages available")'
command -v ovs-vsctl
command -v ovs-ofctl
sudo ovs-vsctl show
sudo "$FLOWGUARD_LAB_PY" topology/controller_smoke.py
```

If that Python lacks the existing packages, set `FLOWGUARD_LAB_PY` to the
absolute path of the lab's prepared Python instead. Stop here if the controller
smoke fails. It exercises host connectivity, echo probes, flow attribution,
OpenFlow 1.3 and controller reconnect. No such live switch integration check
has been performed on this Mac.

For two new isolated, logged runs, use a unique directory prefix:

```sh
FLOWGUARD_TRIAL="results/presentation-$(date +%Y%m%d-%H%M%S)"
sudo "$FLOWGUARD_LAB_PY" experiments/run_trial.py --mode attack-off --pps 600 --duration-s 8 --output "$FLOWGUARD_TRIAL-off"
sudo "$FLOWGUARD_LAB_PY" experiments/run_trial.py --mode attack-on --pps 600 --duration-s 8 --output "$FLOWGUARD_TRIAL-on"
"$FLOWGUARD_LAB_PY" experiments/analyze.py "$FLOWGUARD_TRIAL-off" "$FLOWGUARD_TRIAL-on"
```

The runner starts its own controller, switch, hosts, echo service, sources and
client, then cleans them up. Do not start a second controller manually on port
6653. It writes the actual installed flow tables during the attack and after
recovery, plus controller samples, victim counts and client CSVs.

In a second shell in the **same existing Linux environment**, while the ON run
is active:

```sh
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
tail -f "$FLOWGUARD_TRIAL-on/controller.jsonl"
```

Shell variables are local to their shell; set `FLOWGUARD_TRIAL` to the same
printed prefix in that second shell, or paste the actual path. The switch
exists only during the run. Find rules with cookie `0xdd05000000000005`,
`priority=200`, `udp`, victim `10.0.0.10`, destination port `9000`,
`hard_timeout=10`, and `actions=drop`. The source matches should be `.21` and
`.22`, not the protected client `.11`. Read the nonzero match counters and
compare the saved `flows-after-recovery.txt` after cleanup/recovery.

For packet capture in this route, capture the lab's OVS victim-side interface
inside Linux; Windows' loopback adapter is not a view of Mininet namespaces.
After the switch starts, confirm the interface exists with
`ip link show s1-eth1` (victim is switch port 1), then use a separate shell:

```sh
sudo tcpdump -i s1-eth1 -nn -s 0 -w artifacts/sdn-victim.pcap 'udp port 9000'
```

Stop capture with Ctrl+C before the run ends, or stop when the interface is
removed. Inspect the real file in Wireshark on Windows afterward. Capture
the OpenFlow control channel separately on the existing Linux loopback
interface with capture filter `tcp port 6653` if desired. Live capture is
optional; the original runner does not automatically create PCAP files.

Treat `drop_confirmed` in controller logs as the legacy name for a barrier
reply, which acknowledges ordering. Use actual flow readback, drop counters,
victim receive counts and client/recovery probes together to demonstrate
enforcement. Surface OpenFlow errors instead of relying only on that event.

## 5. An eight-minute presentation sequence

| Time | Screen | Say / demonstrate |
|---|---|---|
| 0:00–1:00 | Dashboard network | “A programmable switch reports traffic counters. FlowGuard watches sustained traffic to one UDP service.” |
| 1:00–2:00 | Model ON/OFF | Explain two sources, two high observations, protected client and temporary policy. Identify capacity as assumed. |
| 2:00–3:00 | Terminal detector + saved SDN rules | Show the implementation's decision code and saved OpenFlow fields. Identify historical evidence. |
| 3:00–4:30 | Live terminal OFF/ON | Start capture; show actual alert, rising drop counts, protected replies, expiry and recovery. |
| 4:30–5:30 | Wireshark I/O graph | Correlate offered versus victim-bound traffic and client replies. Inspect one real UDP payload. |
| 5:30–6:30 | Dashboard recorded mode | Show the original real switch measurements and 80/80 client replies in both modes. |
| 6:30–7:30 | Incident page | Explain GitHub's 2018 reflected memcached attack and why upstream filtering matters at that scale. |
| 7:30–8:00 | Implementation / limits | “This is a measured lab detector and scoped mitigation, not a new DDoS algorithm or proof of Internet-scale protection.” |

If the full existing SDN lab passes rehearsal, replace the native live section
with those fresh `run_trial.py` runs. Keep the native comparison as fallback.

## Troubleshooting and acceptance

- **Close another live lab** if ports 19000, 19001, 19002, 19011, 19021 or 19022
  are occupied. The dashboard on 8765 can stay running at the same time.
- **Wrong capture interface:** select Npcap loopback, not Wi-Fi/Ethernet.
- **No Npcap or permission:** use the real application logs and original saved
  switch evidence; do not present a manufactured capture as real traffic.
- **Run fails:** keep its failed summary, inspect the server/client logs and
  rerun into a fresh directory. Do not hide timeout or failed checks.
- **Rehearse offline on the actual Windows laptop:** doctor PASS, 21 portable
  tests PASS, dashboard assets load, live comparison PASS, and a saved PCAP
  if capture is part of the presentation. Keep the ZIP and Mac fallback ready.

The native program and full test suite were verified on this Mac. Python 3.12
compatibility was also checked here. A native Windows runtime, Npcap capture
and the revised controller on an actual OVS switch remain unverified until
they run on those systems.
