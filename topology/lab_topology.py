"""The isolated one-switch, five-host Mininet topology for the SDN lab.

Optional bottleneck (used by ``experiments/run_trial.py --bottleneck-mbit``)
---------------------------------------------------------------------------
Without a bottleneck every link is a plain veth pair and the client is never
congested: the recorded M6 trials received 80/80 replies even with mitigation
off. ``DDoSTopo(bottleneck={"mbit": 0.5, "queue_packets": 50, "red": False})``
turns only the victim link into a Mininet ``TCLink`` so that availability can
differ between mitigation OFF and ON.

Which side is shaped (verified against mininet/link.py and mininet/net.py):

* ``Topo.addLink(host, switch, ...)`` stores ``node1=victim, node2=s1``;
  ``Mininet.buildFromTopo`` calls ``Mininet.addLink(**info)``, which uses the
  per-link ``cls`` (``cls = self.link if cls is None else cls``), so no global
  ``link=TCLink`` is needed and the other four links stay plain ``Link``.
* ``Link.__init__`` builds ``intf1`` on node1 with ``params1`` and ``intf2`` on
  node2 with ``params2``. ``params2`` therefore configures ``s1-eth1``, the
  switch port facing the victim. A qdisc only shapes *egress*, so only traffic
  that OVS transmits toward the victim (requests from client and attackers)
  is limited; the victim's replies leave through other switch ports unshaped.
* ``TCLink`` makes both ends ``TCIntf``. The victim end gets no shaping
  parameters, so ``TCIntf.config`` only runs ``ethtool -K victim-eth0 gro off
  tx on rx on`` and returns before touching tc.
* ``TCIntf.config`` on ``s1-eth1`` (``bwCmds`` + ``delayCmds``) runs, in the
  root namespace where the OVS ports live::

      tc qdisc add dev s1-eth1 root handle 5:0 htb default 1
      tc class add dev s1-eth1 parent 5:0 classid 5:1 htb rate <bw>Mbit burst 15k
      [red only] tc qdisc add dev s1-eth1 parent 5:1 handle 6: red limit 1000000
                 min 30000 max 35000 avpkt 1500 burst 20 bandwidth <bw>mbit probability 1
      tc qdisc add dev s1-eth1 parent 5:1 (or 6: for red) handle 10: netem limit <queue_packets>

  The HTB class is the rate limiter; the netem leaf (no delay, no loss) is
  the packet FIFO whose ``limit`` is the tail-drop queue length. HTB's
  ``default 1`` sends every frame (UDP, ICMP and ARP alike) to class 5:1.
  OVS and Mininet "fight over" qdiscs, so ``OVSSwitch.batchStartup`` re-applies
  ``TCIntf.config`` after adding the ports; run_trial checks the result with
  ``tc -s -j qdisc show dev s1-eth1`` after ``net.start()``.

* RED caveat: Mininet hard-codes RED thresholds of min 30000 / max 35000 bytes
  (avpkt 1500). With 170-byte flood frames RED only starts dropping when the
  average backlog exceeds about 176 packets, so with ``queue_packets`` below
  about 200 the netem tail-drop acts first and ``red`` behaves like ``fifo``.

Sizing of the default preset (0.5 Mbit/s, 50 packets): a text flood frame is
14 (Ethernet) + 20 (IPv4) + 8 (UDP) + 128 (payload) = 170 bytes, so two
attackers at 600 pps offer 2 x 600 x 170 x 8 = 1.63 Mbit/s. 0.5 Mbit/s carries
about 0.5e6 / (170 x 8) = 367 pps, so roughly 70 % of all requests toward the
victim, including the client's 10 pps probes, are tail-dropped while the flood
is forwarded (mitigation OFF). The worst-case queueing delay is about
50 x 170 x 8 / 0.5e6 = 136 ms, below the probe's 500 ms timeout, so probe
loss measures drops rather than late replies. HTB's 15 kB burst lets roughly
90 frames through at line rate when the queue first fills. Pings, ARP and the
prime probes also pass this qdisc but are never congested.

Detection is unaffected: the controller's rates come from OpenFlow flow
counters, which count packets when OVS matches them on ingress, before the
egress qdisc. The victim's own echo statistics (victim.jsonl) and the
``victim-received`` capture stream, however, are post-bottleneck.

Packet capture (``--pcap``) relative to the qdisc: OVS outputs a frame with
``dev_queue_xmit(s1-eth1)``, which enqueues it into the HTB/netem tree (a
tail-drop happens here and is counted only by the qdisc). When HTB later
dequeues it, ``sch_direct_xmit -> dev_hard_start_xmit -> xmit_one`` first calls
``dev_queue_xmit_nit``, which hands a copy to every ETH_P_ALL AF_PACKET socket
bound to s1-eth1, and only then ``veth_xmit``. The ``victim-received`` stream
therefore holds exactly the frames that survived the bottleneck, timestamped
after their queueing delay. The ``*-offered`` streams are ingress taps on the
senders' switch ports (``__netif_receive_skb_core`` runs ptype_all taps before
OVS's rx handler), i.e. before any drop rule, meter or queue.
"""

from mininet.link import TCLink
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

# Switch-side interface of the victim link: the only shaped egress queue.
VICTIM_SWITCH_INTF = f"s1-eth{HOST_PORTS['victim']}"
BOTTLENECK_PRESET = {"mbit": 0.5, "queue_packets": 50, "red": False}
BOTTLENECK_MBIT_RANGE = (0.05, 100.0)
QUEUE_PACKETS_RANGE = (5, 1000)


def bottleneck_params(bottleneck):
    """Validate a bottleneck dict and return the TCIntf params for s1-eth1."""
    if not isinstance(bottleneck, dict) or set(bottleneck) - {"mbit", "queue_packets", "red"}:
        raise ValueError("bottleneck must be a dict with mbit, queue_packets and red")
    mbit = bottleneck.get("mbit")
    queue = bottleneck.get("queue_packets", BOTTLENECK_PRESET["queue_packets"])
    red = bottleneck.get("red", False)
    if (isinstance(mbit, bool) or not isinstance(mbit, (int, float))
            or not BOTTLENECK_MBIT_RANGE[0] <= mbit <= BOTTLENECK_MBIT_RANGE[1]):
        raise ValueError("bottleneck mbit must be between 0.05 and 100")
    if (isinstance(queue, bool) or not isinstance(queue, int)
            or not QUEUE_PACKETS_RANGE[0] <= queue <= QUEUE_PACKETS_RANGE[1]):
        raise ValueError("bottleneck queue_packets must be an integer between 5 and 1000")
    if not isinstance(red, bool):
        raise ValueError("bottleneck red must be true or false")
    return {"bw": float(mbit), "max_queue_size": queue, "enable_red": red}


class DDoSTopo(Topo):
    """Single OVS switch and lab hosts; no NAT or external links."""

    def build(self, bottleneck=None):
        shaped = bottleneck_params(bottleneck) if bottleneck is not None else None
        switch = self.addSwitch("s1", protocols="OpenFlow13")
        for name, (address, mac) in HOSTS.items():
            host = self.addHost(name, ip=address, mac=mac)
            if shaped is not None and name == "victim":
                # node1=host, node2=switch: params2 shapes s1-eth1 egress only.
                self.addLink(host, switch, port2=HOST_PORTS[name], cls=TCLink, params2=shaped)
            else:
                self.addLink(host, switch, port2=HOST_PORTS[name])


# Allows `mn --custom topology/lab_topology.py --topo ddos`.
topos = {"ddos": DDoSTopo}
