# M2 smoke-test evidence — 2026-10-07

## Environment

Ubuntu 26.04 LTS in WSL2; kernel `6.18.33.2-microsoft-standard-WSL2`; Python 3.14.4. Installed Ubuntu packages: `mininet 2.3.0-1.1build1`, `openvswitch-switch 3.7.1-2`, `python3-os-ken 4.1.1-1ubuntu2`. Open vSwitch service reported `active`; `import os_ken` succeeded.

## Command

```powershell
wsl -d Ubuntu -u root -- python3 /mnt/c/Users/Sai/Desktop/ddos/topology/smoke.py
```

## Observed output

```text
hosts: victim=10.0.0.10, client=10.0.0.11, a1=10.0.0.21, a2=10.0.0.22, a3=10.0.0.23
bridge protocols: [OpenFlow13]
OpenFlow 1.3 query: success
*** Ping: testing ping reachability
a1 -> a2 a3 client victim
a2 -> a1 a3 client victim
a3 -> a1 a2 client victim
client -> a1 a2 a3 victim
victim -> a1 a2 a3 client
*** Results: 0% dropped (20/20 received)
ping loss: 0%
timestamp_utc,sequence,status,rtt_ms
2026-10-07T13:39:59.451071+00:00,1,ok,0.174
2026-10-07T13:39:59.551213+00:00,2,ok,0.283
2026-10-07T13:39:59.651449+00:00,3,ok,0.569
2026-10-07T13:39:59.751684+00:00,4,ok,0.227
2026-10-07T13:39:59.852239+00:00,5,ok,0.234
2026-10-07T13:39:59.952740+00:00,6,ok,0.550
2026-10-07T13:40:00.052995+00:00,7,ok,0.245
2026-10-07T13:40:00.153724+00:00,8,ok,0.325
2026-10-07T13:40:00.254153+00:00,9,ok,0.632
2026-10-07T13:40:00.354677+00:00,10,ok,0.593
sent=10 received=10 loss=0.0%
M2 smoke test: PASS
```

After the script exited, `wsl -d Ubuntu -u root -- ovs-vsctl list-br` returned no bridges. The test used bridge mode and therefore does not demonstrate OS-Ken controller forwarding, detection, or mitigation.
