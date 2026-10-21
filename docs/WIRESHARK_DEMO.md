# FlowGuard Wireshark review demo

This is a packet-level view of the **real, isolated Mininet trial**. The capture
records UDP requests at four ports of Open vSwitch `s1`; it does not generate
fake packets or capture traffic from your physical network.

| Wireshark interface name | Observation point | What it proves |
| --- | --- | --- |
| `a1-offered` | switch port connected to attacker `10.0.0.21` | attacker 1 continues sending |
| `a2-offered` | switch port connected to attacker `10.0.0.22` | attacker 2 continues sending |
| `client-offered` | switch port connected to client `10.0.0.11` | normal requests continue |
| `victim-received` | switch port connected to victim `10.0.0.10` | requests forwarded toward the victim |

All four streams are saved in **one pcapng file**, with interface names that
Wireshark can filter. Only IPv4 UDP requests addressed to `10.0.0.10:9000`
are included. Each request can appear at both its sender port and victim port,
so never treat the whole-file packet count as the number of unique requests.

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
reports 4,800 requests offered by each attacker, 90 by the client, and 1,669
requests seen on the victim-side port over the attack and recovery phases.
The terminal run independently reported 8,133 packets matched by the switch's
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

   The attack-offered line stays high for eight seconds. The attack-at-victim
   line rises briefly, then falls after the controller's two high counter
   windows and the switch's rule confirmation. The attacker generators keep
   sending; the reduction is at the switch. The 10-packets/s client lines
   sit near the bottom on this scale, so temporarily hide the two attacker
   rows to show that client traffic still reaches the victim. A later short
   client burst is the recovery probe after the rule timeout.

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

   The terminal's `80/80` attack-period replies and `10/10` recovery replies
   are the stronger evidence that the application client succeeded. The
   capture shows forwarded *requests* only, not UDP echo replies.

## What to say during the combined demo

> “This is one private Mininet network. The red graph counts UDP requests from
> two attacker hosts as they enter the OpenFlow switch. The switch measures
> per-source traffic once per second. After two consecutive windows above the
> configured limits, the controller installs a short-lived rule for each
> attacker source to the victim's UDP service.”

> “The red offered line stays high because the attackers keep transmitting.
> The victim-side attacker line falls because the switch stops forwarding
> those matching packets. The client is a separate `10.0.0.11` flow; when I
> show its two lines, its requests still enter and reach the victim. The
> terminal confirms 80 of 80 replies during the attack and 10 of 10 after
> the rules expire.”

> “This demonstrates selective filtering in our controlled topology. The
> policy classifies traffic from packet rates and source IPs; it does not
> authenticate human users or resist IP spoofing. Our matched no-mitigation
> run also delivered all client replies, so we claim filtering, not a measured
> improvement in availability.”

The switch drop counters and rule lifecycle are in `controller.jsonl` and
`flows-during.txt` under the live run's results folder. The Wireshark graph
shows *where* requests went; the OpenFlow counters quantify rule matches.
