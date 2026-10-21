"""The isolated one-switch, five-host Mininet topology for the SDN lab."""

from mininet.topo import Topo


HOSTS = {
    "victim": ("10.0.0.10/24", "02:00:00:00:00:10"),
    "client": ("10.0.0.11/24", "02:00:00:00:00:11"),
    "a1": ("10.0.0.21/24", "02:00:00:00:00:21"),
    "a2": ("10.0.0.22/24", "02:00:00:00:00:22"),
    "a3": ("10.0.0.23/24", "02:00:00:00:00:23"),
}

# Mininet assigns switch ports in host insertion order. Keep this mapping
# explicit so the controller can bind each permitted identity to its link.
HOST_PORTS = {name: port for port, name in enumerate(HOSTS, start=1)}


class DDoSTopo(Topo):
    """Single OVS switch and lab hosts; no NAT or external links."""

    def build(self):
        switch = self.addSwitch("s1", protocols="OpenFlow13")
        for name, (address, mac) in HOSTS.items():
            host = self.addHost(name, ip=address, mac=mac)
            self.addLink(host, switch, port2=HOST_PORTS[name])


# Allows `mn --custom topology/lab_topology.py --topo ddos`.
topos = {"ddos": DDoSTopo}
