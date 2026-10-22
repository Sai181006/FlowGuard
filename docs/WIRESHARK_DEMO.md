# FlowGuard Wireshark review demo

This is a packet-level view of the **real, isolated Mininet trial**. The capture
records UDP requests and replies at ports of Open vSwitch `s1`; it does not
generate fake packets or capture traffic from your physical network.

| Wireshark interface name | Observation point | What it proves |
| --- | --- | --- |
| `a1-offered` | switch port connected to attacker `10.0.0.21` | attacker 1 continues sending |
| `a2-offered` | switch port connected to attacker `10.0.0.22` | attacker 2 continues sending |
| `client-offered` | switch port connected to client `10.0.0.11` | normal requests continue |
| `victim-received` | switch port connected to victim `10.0.0.10` | requests forwarded toward the victim |
| `client-reply-egress` | switch port connected to client `10.0.0.11` | UDP echo replies forwarded toward the client |

All five streams are saved in **one pcapng file**, with interface names that
Wireshark can filter. The first four streams contain IPv4 UDP requests to
`10.0.0.10:9000`; the fifth contains UDP echo replies from that service to
`10.0.0.11`. A request can appear at both its sender port and victim port, so
never treat the whole-file packet count as the number of unique requests.

## Option A: open the ready capture

On Windows, install [Wireshark](https://www.wireshark.org/download.html) if
needed. Choose **File → Open** and select:

```text
C:\Users\Sai\Documents\ChatGPT\cn_project\m7_publish\evidence\m7\flowguard-wireshark-sample.pcapng
```

The `cn_project` path is a Windows junction to the workspace folder named
`cn project`. Opening a saved capture does not require live capture permission
or a Wireshark installation inside Ubuntu.

This saved capture came from a real 8-second, 600-packets/s-per-attacker run.
The [capture summary](../evidence/m7/flowguard-wireshark-sample-summary.json)
reports 4,800 requests offered by each attacker, 90 by the client, and 1,594
requests seen on the victim-side port over the attack and recovery phases.
The revised capture also records 90 replies forwarded toward the client.
The terminal run independently reported 8,163 packets matched by the switch's
temporary drop rules. These counters are from different observation points
and should not be subtracted as if they measured the same interval and stage.

## Option B: make a fresh capture while showing the terminal demo

In **PowerShell**, run this exact command:

```powershell
wsl -d Ubuntu -u root --cd 'C:\Users\Sai\Documents\ChatGPT\cn_project\m7_publish' --exec python3 experiments/demo.py --pcap
```

The terminal prints the flood, alert, rule confirmation, drop counters, client
probe results, and a `Wireshark file:` path. The run takes about half a minute;
do not start another Mininet trial simultaneously. In Windows Wireshark,
open the printed file under
`C:\Users\Sai\Documents\ChatGPT\cn_project\m7_publish\results\...`.
The run also writes `capture-summary.json` in that same results folder.
Each run uses a fresh `demo-YYYYMMDD-HHMMSS` folder. The packet file is capped
at 64 MiB; the terminal warns if a custom high-rate run reaches the cap.

If Wireshark is not installed before the review, the terminal demo still runs;
use the saved capture on any Windows machine with Wireshark. If a prior
interrupted trial leaves Mininet interfaces behind, run `wsl -d Ubuntu -u root
--exec mn -c` once, then retry the demo.

## Three-minute Wireshark walkthrough

The **FlowGuard** configuration profile is already installed on this Windows
machine. In the main Wireshark window, click **Profile: Default** at the bottom
right and select **FlowGuard**. Reopen **Statistics → I/O Graphs** if it was
already open. This profile supplies the five named graph lines below. It leaves
your Default profile unchanged. On another machine, import the profile from
[`wireshark/FlowGuard`](../wireshark/FlowGuard) or add the filters manually.

1. Open the capture. In the packet list, apply this **display filter**:

   ```text
   frame.interface_name == "a1-offered" && ip.src == 10.0.0.21
   ```

   Select a packet and expand **Ethernet II**, **Internet Protocol Version 4**,
   and **User Datagram Protocol**. Point out the source `10.0.0.21`, victim
   destination `10.0.0.10`, and UDP destination port `9000`. The interface name
   means this request was observed entering the switch.

2. Clear the top display filter. Open **Statistics → I/O Graphs**. Set the
   interval to **1 second** and the graph unit to **packets per interval**.
   Add or edit graph rows with these filters; give each a different color:

   | Graph | Display filter for its graph row |
   | --- | --- |
   | Both attackers offered | `(frame.interface_name == "a1-offered" || frame.interface_name == "a2-offered") && (ip.src == 10.0.0.21 || ip.src == 10.0.0.22)` |
   | Attack reaching victim | `frame.interface_name == "victim-received" && (ip.src == 10.0.0.21 || ip.src == 10.0.0.22)` |
   | Client offered | `frame.interface_name == "client-offered" && ip.src == 10.0.0.11` |
   | Client reaching victim | `frame.interface_name == "victim-received" && ip.src == 10.0.0.11` |
   | Replies toward client | `frame.interface_name == "client-reply-egress" && ip.src == 10.0.0.10 && ip.dst == 10.0.0.11` |

   The attack-offered line stays high for eight seconds. The attack-at-victim
   line rises briefly, then falls after the controller's two high counter
   windows and the switch's rule confirmation. The attacker generators keep
   sending; the reduction is at the switch. The 10-packets/s client request
   and reply lines sit near the bottom on this scale. Temporarily hide the two
   attacker rows and click **Reset** to show the client lines clearly. The
   short later burst is the recovery probe after the rule timeout.

   In the included capture, the first two attack-offered bins contain about
   1,200 packets each. From the third bin through the eighth, attacker traffic
   is still about 1,200 per bin at ingress, while the victim-side capture has
   only about 10 requests per bin, all from the client. Exact bin edges may
   shift if Wireshark uses a different time origin.

3. Close the graph. Apply this filter to see only attacker packets that got
   through to the victim-side port:

   ```text
   frame.interface_name == "victim-received" && (ip.src == 10.0.0.21 || ip.src == 10.0.0.22)
   ```

   Compare with this filter to see the protected client's forwarded requests:

   ```text
   frame.interface_name == "victim-received" && ip.src == 10.0.0.11
   ```

   To show replies on the client-side switch link, use:

   ```text
   frame.interface_name == "client-reply-egress" && ip.src == 10.0.0.10 && ip.dst == 10.0.0.11
   ```

   The capture shows replies forwarded toward the client. The terminal's
   `80/80` attack-period replies and `10/10` recovery replies are the stronger
   evidence that the application actually received them.

## What to say during the combined demo

> “This is one private Mininet network. The red graph counts UDP requests from
> two attacker hosts as they enter the OpenFlow switch. The switch measures
> per-source traffic once per second. After two consecutive windows above the
> configured limits, the controller installs a short-lived rule for each
> attacker source to the victim's UDP service.”

> “The red offered line stays high because the attackers keep transmitting.
> The victim-side attacker line falls because the switch stops forwarding
> those matching packets. The client is a separate `10.0.0.11` flow; when I
> show its three lines, its requests still enter and reach the victim, and
> echo replies return toward the client. The terminal confirms 80 of 80
> replies during the attack and 10 of 10 after the rules expire.”

> “This demonstrates selective filtering in our controlled topology. The
> policy classifies traffic from packet rates and source IPs; it does not
> authenticate human users or resist IP spoofing. Our matched no-mitigation
> run also delivered all client replies, so we claim filtering, not a measured
> improvement in availability.”

The switch drop counters and rule lifecycle are in `controller.jsonl` and
`flows-during.txt` under the live run's results folder. The Wireshark graph
shows *where* requests and client replies went; the OpenFlow counters quantify
rule matches.

---

# Advanced packet analysis (feature/advanced-networking)

The sections below extend the walkthrough above for the new probe protocol,
the Lua dissector, the bottleneck experiments and the native lab. Field names
and filters were checked against [`wireshark/flowguard.lua`](../wireshark/flowguard.lua)
and the capture code. The dissector was verified on 22 October 2026 with
**real TShark 4.2.2** (Lua 5.2): it decodes the committed M7 sample (all
9,600 offered flood frames, 1,504 forwarded floods and 270 legacy probe
frames), the live M8 captures (in `results/m8-demo-original/flowguard.pcapng`
all 270 client probe frames decode as FGPB probes with `flowguard.crc_ok`
true: 90 offered, 90 at the victim, 90 replies), and a synthetic file of
FGPB probe/flood, bad-CRC, legacy, Mininet and native payloads
(`tests/test_wireshark_dissector.py`). The Wireshark
**GUI**, the `FlowGuard` profile's I/O graphs/buttons and Wireshark ≥ 4.4
(Lua 5.4) have not been opened on this branch.

## FlowGuard Lua dissector

The dissector registers a UDP **heuristic** (it recognises payloads on any
port) and decodes four payload families:

| Payload | Produced by | `flowguard.kind` | Info column |
|---|---|---|---|
| FGPB binary header, `msg_type` 1 | `traffic/probe.py` (default `--format binary`) | `probe` | `FGPB probe seq=7 session=0x1234abcd len=64 crc=ok` |
| FGPB binary header, `msg_type` 3 | `traffic/flood.py --format binary` | `flood` | `FGPB flood seq=… crc=ok` |
| `ddos-probe:<seq>:<ns>` | `probe.py --format text`; every recorded M4–M7 trial | `legacy_probe` | `FlowGuard legacy text probe seq=N` |
| `FLOWGUARD-LAB-ONLY:XXXX…` | `flood.py` default (Mininet floods) | `flood` | `FlowGuard Mininet lab flood (128 bytes)` |
| `flowguard:<src>:<phase>:<seq>:<ns>....` | native lab sources (`demo/live_lab.py`) | `native_flood` | `FlowGuard native lab a1 phase=attack seq=N` |

### Loading it

| Method | How |
|---|---|
| One-off | `wireshark -X lua_script:wireshark/flowguard.lua capture.pcapng` or `tshark -X lua_script:wireshark/flowguard.lua -r capture.pcapng -Y flowguard` |
| Linux permanent | `mkdir -p ~/.local/lib/wireshark/plugins && cp wireshark/flowguard.lua ~/.local/lib/wireshark/plugins/`, restart Wireshark |
| Windows permanent | copy `wireshark\flowguard.lua` to `%APPDATA%\Wireshark\plugins\`, restart Wireshark |
| Check it loaded | **Help → About Wireshark → Plugins** lists `flowguard.lua`; the display filter `flowguard` turns green |

If another dissector claims the port first, use **Analyze → Decode As… → UDP
port → FLOWGUARD**, or enable the UDP preference "Try heuristic
sub-dissectors first". The preference **FlowGuard → Validate CRC32** (on by
default) recomputes the CRC and adds the expert item `flowguard.crc.bad`.

### Installing the FlowGuard profile

Copy the folder [`wireshark/FlowGuard`](../wireshark/FlowGuard) into your
profiles directory (Linux `~/.config/wireshark/profiles/`, Windows
`%APPDATA%\Wireshark\profiles\`) and select **Profile: FlowGuard** in the
status bar. It provides seven I/O-graph lines (the five interface lines of
the walkthrough above plus "Probe requests offered" =
`flowguard.type == 1 && frame.interface_name == "client-offered"` and
"Probe replies to client" = `flowguard && frame.interface_name == "client-reply-egress"`)
and six filter buttons (Attack at victim, Client offered, Client replies,
FlowGuard CRC errors, Native post-queue, Native offered). The interface IDs
0–4 in the profile follow `experiments/packet_capture.py`
(a1-offered, a2-offered, client-offered, victim-received, client-reply-egress).

**The committed sample predates binary probes.** In
`evidence/m7/flowguard-wireshark-sample.pcapng` all 90 client requests and 90
replies are legacy `ddos-probe:` text and the floods are `FLOWGUARD-LAB-ONLY:`
text (checked by parsing the file). The dissector decodes them as
`legacy_probe` and `flood`, but every `flowguard.type`/`flowguard.seq`/
`flowguard.crc_ok` filter — and the two probe graph lines — are empty for that
file. Use `flowguard.kind == "legacy_probe"` and `flowguard.text_seq` there.
The live captures in `results/m8-demo-original/` and
`results/m8-bottleneck-compare/{off,on}/` contain FGPB probes, so every filter
below works on them. In the bottleneck OFF capture,
`flowguard.type == 1 && frame.interface_name == "victim-received"` shows only
34 of the 90 offered probes (24 attack-phase + 10 recovery) — the other 56
were tail-dropped by the `s1-eth1` queue.

## Which interface to capture

| Runtime | Capture point | How |
|---|---|---|
| Mininet / OVS | The pcapng written by `--pcap` (`results/<run>/flowguard.pcapng`): one file, five named interfaces | `sudo python3 experiments/demo.py --pcap` — FlowGuard's own `AF_PACKET` capture, no tcpdump needed |
| Mininet, manual | `s1-eth1` (victim side) in the root namespace | `sudo tcpdump -i s1-eth1 -nn -w victim.pcap 'udp port 9000'` |
| Native lab, Linux | `lo` | `sudo dumpcap -i lo -f 'udp portrange 19000-19022' -w native.pcapng` or Wireshark on `lo` |
| Native lab, Windows | Npcap "Adapter for loopback traffic capture" | see [WINDOWS_DEMO](../WINDOWS_DEMO.md) |

Where the Mininet streams sit relative to the bottleneck
(`topology/lab_topology.py`): `*-offered` are ingress taps on the senders'
switch ports, taken before OVS — before any drop rule, meter or queue.
`victim-received` is taken when the HTB/netem qdisc **dequeues** a frame for
`s1-eth1`, so it holds exactly the frames that survived the bottleneck,
timestamped after their queueing delay. A tail drop in the qdisc is visible
only in `qdisc.jsonl`, never in the capture.

## Capture filters vs display filters

Capture filters (BPF, applied by libpcap/Npcap while capturing; cannot see
FlowGuard fields): `udp port 9000`, `udp portrange 19000-19022`,
`tcp port 6653`. Display filters (Wireshark syntax, applied afterwards; can
use dissector fields):

| Purpose | Display filter |
|---|---|
| Everything the dissector recognised | `flowguard` |
| Flood datagrams only | `flowguard.kind == "flood"` |
| FGPB probe requests that reached the victim (post-bottleneck) | `flowguard.type == 1 && frame.interface_name == "victim-received"` |
| Corrupted probes | `flowguard.crc_ok == 0` (expert item `flowguard.crc.bad`) |
| One probe session | `flowguard.session == 0x1234abcd` |
| Sequence range around a loss | `flowguard.seq >= 40 && flowguard.seq <= 60 && frame.interface_name == "client-offered"` |
| Native lab: offered to the gateway (pre-queue) | `udp.dstport == 19001` |
| Native lab: forwarded to the victim (post-queue) | `udp.dstport == 19000` |
| Native lab: one source during the attack | `flowguard.source_name == "a1" && flowguard.phase == "attack"` |
| Native lab: protected client probes | `udp.srcport == 19011 && flowguard.kind == "probe"` |

Finding sequence gaps: Wireshark has no built-in "gap" filter for a custom
field. Filter `flowguard.type == 1 && frame.interface_name == "client-offered"`,
add `flowguard.seq` as a column (right-click the field → **Apply as Column**),
and compare with the same filter on `victim-received`; or export both with
`tshark … -T fields -e flowguard.seq` and diff the lists. Missing numbers on
`victim-received` are probes lost at a rule or the queue; `client.csv` marks
the same sequences `timeout`.

## Reading a bottleneck run

For any time bin of an I/O graph:

```text
offered (a1-offered + a2-offered + client-offered)
  − victim-received
  = packets dropped by FlowGuard rules / OVS meters  (controller.jsonl: drop_packet_delta,
                                                     ratelimit, meter_sample band_drop_delta)
  + packets dropped by the s1-eth1 queue            (qdisc.jsonl: root htb "drops")
  (± packets still queued at the bin edge, ≤ 50, shifted by ≤ ~136 ms)
```

With mitigation OFF the rule term is zero and the difference is the queue
loss; with mitigation ON, after confirmation, offered attack traffic stays
high while victim-received attack traffic falls to zero and the queue drains.
In the native lab the same identity holds with `udp.dstport == 19001`
(offered) and `udp.dstport == 19000` (delivered), and the gateway's
`packets.csv` labels every datagram `FORWARD`, `DROP`, `RL_PASS`, `RL_DROP`,
`QUEUE_TAIL_DROP` or `QUEUE_RED_DROP` — a capture cannot show those labels.

Note that each native transaction appears several times on `lo` (source →
gateway, gateway → victim, victim → gateway backend, gateway → source), so
never count all loopback packets as requests.

## Real packets vs simulated events

| You see | Is it a packet capture? |
|---|---|
| Wireshark on a `--pcap` file or on `lo` during `demo/live_lab.py` | **Yes**, real datagrams |
| Dashboard "Packet desk" rows | **No**; representative rows generated by the model |
| `experiments/demo.py` timeline lines (`ALERT`, `RULE`, `BLOCK`, `METER`, `EXPIRE`) | **No**; they are controller events from `controller.jsonl` (OpenFlow replies and decisions), not packets |
| Native lab `packets.csv` | Application log written by the gateway for each datagram it received; not PCAP |

## Capturing the OpenFlow control channel (unverified)

The controller listens on `127.0.0.1:6653` (`controller/run.py`), so the
OpenFlow messages themselves cross the Linux loopback during a Mininet run.
This has **not** been attempted on this branch; the steps are expected to work
with Wireshark's built-in `openflow_v4` dissector:

```bash
sudo dumpcap -i lo -f 'tcp port 6653' -w openflow.pcapng      # start before experiments/demo.py
```

| Display filter | Expected content |
|---|---|
| `tcp.port == 6653` | the whole control session |
| `openflow_v4.type == 14` | FLOW_MOD (forwarding, drop and metered rules) |
| `openflow_v4.type == 29` | METER_MOD (rate limit) |
| `openflow_v4.type == 18` / `== 19` | MULTIPART request / reply (flow stats every second, meter stats, meter features) |
| `openflow_v4.type == 20` / `== 21` | BARRIER request / reply (`drop_confirmed`, `ratelimit_confirmed`) |
| `openflow_v4.type == 1` | ERROR (meter fallback path) |
| `openflow_v4.type == 11` | FLOW_REMOVED (rule expiry) |

The numbers are the OpenFlow 1.3 message types from
`os_ken/ofproto/ofproto_v1_3.py`. If Wireshark does not dissect port 6653
automatically, use **Decode As… → TCP port 6653 → OpenFlow**. The field name `openflow_v4.type` was confirmed in TShark 4.2.2's field list
(`tshark -G fields`); the live capture itself remains unverified.
