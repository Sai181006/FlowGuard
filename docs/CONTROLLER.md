# M3 OS-Ken controller forwarding

The Ubuntu `python3-os-ken` package used by this project does not install `osken-manager`. The project launcher calls OS-Ken's application manager directly and listens only on `127.0.0.1:6653`. Open vSwitch connects in secure mode with OpenFlow 1.3.

## Reproduce the verified test

From the repository root in Ubuntu WSL:

```bash
python3 -m unittest discover -s tests -v
sudo python3 topology/controller_smoke.py
```

The integration script starts the controller and Mininet network, verifies switch connection, pings all hosts, starts the victim UDP echo server, probes from the legitimate client and two other lab hosts, inspects flow counters, restarts the controller, and verifies stale-flow cleanup and restored forwarding. It shuts down the processes and topology in `finally`.

To start only the controller in Ubuntu WSL:

```bash
sudo python3 controller/run.py
```

Keep that terminal open while connecting the Mininet switch to `127.0.0.1:6653`. The controller alone does not start a topology. Stop it with Ctrl+C. If an interrupted Mininet run leaves devices behind, use `sudo mn -c`.

## Forwarding behavior

- The table-miss rule drops unrelated packets. Fifteen higher-priority punt rules send ARP, ICMP, and UDP packets from the five configured MAC/IP pairs to the controller until forwarding rules are learned. The controller also checks IPv4 source/MAC consistency.
- It learns each MAC's ingress port from packet-in messages. Unknown destinations are flooded inside the isolated switch; known destinations receive packet-out forwarding and protocol-specific flow rules.
- UDP forwarding rules have priority 100, a 30-second idle timeout, and cookie `0xdd05000000000003`. Each rule matches ingress port, source/destination MAC, IPv4 source/destination, and protocol 17. These are the counters M4 will poll.
- ARP and ICMP forwarding rules have priority 20 and a different cookie. No broad IPv4 rule can bypass UDP attribution.
- On a switch reconnect, the controller clears this app's old rules and learned MAC state, then reinstalls the table-miss rule. The M3 test confirms the rules rebuild when probes resume.

The controller does **not** detect attacks or install mitigation rules yet. See [M3 evidence](../evidence/m3/SMOKE.md) for measured test results and observed flow entries. OS-Ken API references: [application model](https://docs.openstack.org/os-ken/latest/os_ken_app_api.html), [OpenFlow 1.3 messages](https://docs.openstack.org/os-ken/latest/ofproto_v1_3_ref.html).
