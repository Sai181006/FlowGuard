# M3 controller smoke-test evidence — 2026-10-11

## Commands

```powershell
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/Sai/Desktop/ddos && python3 -m unittest discover -s tests -v'
wsl -d Ubuntu -u root -- python3 /mnt/c/Users/Sai/Desktop/ddos/topology/controller_smoke.py
```

## Results observed in Ubuntu WSL2

- Four focused unit tests passed: topology host mapping, source/destination-specific UDP match, ARP match separation, and no broad rule for other IPv4 traffic.
- Open vSwitch reported `fail_mode=secure` and connected to OS-Ken on `127.0.0.1:6653` using OpenFlow 1.3.
- `pingall`: **20/20 received** (0% loss).
- UDP echo: client **10/10**, `a1` **3/3**, `a2` **3/3** (16/16 initial probes).
- Six UDP forwarding flows were visible: client→victim, victim→client, a1→victim, victim→a1, a2→victim, and victim→a2. All had nonzero counters after a short counter-settling delay.
- The switch had 15 lab-only packet-in rules (ARP, ICMP, UDP for each of five hosts) and a default drop rule.
- After the controller process restarted, old UDP flows were absent. The client then received **3/3** more echo replies, and the controller logged fresh UDP flow installation.
- Final line: `M3 controller smoke test: PASS`.

Representative switch flow lines from the verified run:

```text
cookie=0xdd05000000000003, n_packets=9, n_bytes=667, idle_timeout=30, priority=100,udp,in_port=2,dl_src=02:00:00:00:00:11,dl_dst=02:00:00:00:00:10,nw_src=10.0.0.11,nw_dst=10.0.0.10 actions=output:1
cookie=0xdd05000000000003, n_packets=2, n_bytes=148, idle_timeout=30, priority=100,udp,in_port=3,dl_src=02:00:00:00:00:21,dl_dst=02:00:00:00:00:10,nw_src=10.0.0.21,nw_dst=10.0.0.10 actions=output:1
cookie=0xdd05000000000003, n_packets=2, n_bytes=148, idle_timeout=30, priority=100,udp,in_port=4,dl_src=02:00:00:00:00:22,dl_dst=02:00:00:00:00:10,nw_src=10.0.0.22,nw_dst=10.0.0.10 actions=output:1
```

This verifies forwarding and attributable counters. It does not measure attack detection or mitigation.
