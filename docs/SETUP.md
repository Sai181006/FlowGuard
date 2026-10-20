# M2 lab setup and smoke test

This setup was prepared for the existing **Ubuntu 26.04 LTS WSL2** installation on the Windows host. Mininet requires root for network namespaces. The M2 smoke test uses Open vSwitch in standalone bridge mode because the project controller belongs to M3; the same topology requests OpenFlow 1.3 and checks that the switch accepts an OpenFlow 1.3 query.

## Installed lab packages

Inside Ubuntu WSL, install the distribution packages:

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch python3-os-ken
```

The versions installed and checked on 2026-10-07 were Ubuntu 26.04 LTS, Linux `6.18.33.2-microsoft-standard-WSL2`, Python 3.14.4, Mininet 2.3.0, Open vSwitch 3.7.1, and OS-Ken 4.1.1 (Ubuntu package). Open vSwitch's systemd service was active. Exact package revisions can be checked with `dpkg -s mininet openvswitch-switch python3-os-ken`.

## Run from Ubuntu WSL

From the repository root:

```bash
sudo python3 topology/smoke.py
```

The script starts exactly one OVS switch and five private hosts, queries the bridge with OpenFlow 1.3, pings between hosts, starts the victim UDP echo service, sends ten probes from the legitimate client, and tears down the lab in `finally` even if a check fails. Its expected final line is `M2 smoke test: PASS`.

The verified run is recorded in [M2 smoke evidence](../evidence/m2/SMOKE.md): 20/20 host pings and 10/10 UDP echo replies succeeded, and no OVS bridge remained afterward.

To explore the topology interactively without a controller:

```bash
sudo mn --custom topology/lab_topology.py --topo ddos --switch ovsbr --controller none
```

At the `mininet>` prompt, use `nodes`, `net`, `pingall`, and `exit`. If an interrupted run leaves Mininet devices behind, clean up with:

```bash
sudo mn -c
```

## Scope of this smoke test

Bridge mode verifies the topology and victim service; it does **not** verify controller forwarding, detection, or mitigation. The M3 test uses an OS-Ken-controlled OpenFlow switch instead. There is no NAT or external link in `DDoSTopo`, and the probe only accepts a target inside `10.0.0.0/24` or `127.0.0.1`.

M3 controller forwarding is now implemented; use the [controller guide](CONTROLLER.md) for its startup and verification commands.

Installation guidance: [Mininet INSTALL](https://github.com/mininet/mininet/blob/master/INSTALL), [Open vSwitch Ubuntu packages](https://docs.openvswitch.org/en/stable/intro/install/distributions/).
