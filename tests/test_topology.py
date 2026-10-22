"""DDoSTopo stays unchanged by default and shapes only s1-eth1 with a bottleneck."""

import unittest
from types import SimpleNamespace

try:
    from mininet.link import TCIntf, TCLink
    from topology.lab_topology import (BOTTLENECK_PRESET, HOST_PORTS, HOSTS, VICTIM_SWITCH_INTF,
                                       DDoSTopo)
except ImportError as exc:  # Mininet is only installed in the lab VM / .deps
    MININET_ERROR = exc
else:
    MININET_ERROR = None


@unittest.skipIf(MININET_ERROR is not None, f"mininet is not importable: {MININET_ERROR}")
class TopologyTests(unittest.TestCase):
    def _links(self, topo):
        return {info["node1"]: info for _, _, info in topo.links(withInfo=True)}

    def test_default_topology_is_unchanged(self):
        topo = DDoSTopo()
        self.assertEqual(HOST_PORTS, {"victim": 1, "client": 2, "a1": 3, "a2": 4, "a3": 5})
        self.assertEqual(sorted(topo.hosts()), sorted(HOSTS))
        links = self._links(topo)
        self.assertEqual(set(links), set(HOSTS))
        for name, info in links.items():
            self.assertEqual(info["node2"], "s1")
            self.assertEqual(info["port2"], HOST_PORTS[name])
            self.assertNotIn("cls", info)
            self.assertNotIn("params2", info)
        self.assertEqual(topo.nodeInfo("s1")["protocols"], "OpenFlow13")

    def test_bottleneck_shapes_only_the_switch_side_of_the_victim_link(self):
        topo = DDoSTopo(bottleneck=BOTTLENECK_PRESET)
        links = self._links(topo)
        victim = topo.linkInfo("victim", "s1")
        self.assertIs(victim["cls"], TCLink)
        # node1 is the host, node2 the switch: params2 configures s1-eth1.
        self.assertEqual((victim["node1"], victim["node2"], victim["port2"]), ("victim", "s1", 1))
        self.assertEqual(victim["params2"], {"bw": 0.5, "max_queue_size": 50, "enable_red": False})
        self.assertNotIn("params1", victim)
        self.assertEqual(VICTIM_SWITCH_INTF, "s1-eth1")
        for name, info in links.items():
            self.assertEqual(info["port2"], HOST_PORTS[name])
            if name != "victim":
                self.assertNotIn("cls", info)
                self.assertNotIn("params2", info)

    def test_red_and_validation(self):
        topo = DDoSTopo(bottleneck={"mbit": 2, "queue_packets": 300, "red": True})
        self.assertEqual(topo.linkInfo("victim", "s1")["params2"],
                         {"bw": 2.0, "max_queue_size": 300, "enable_red": True})
        for bad in ({"mbit": 0.01}, {"mbit": 0.5, "queue_packets": 4}, {"mbit": 0.5, "red": "yes"},
                    {"mbit": True}, {"mbit": 0.5, "extra": 1}, "0.5"):
            with self.assertRaises(ValueError):
                DDoSTopo(bottleneck=bad)

    def test_installed_mininet_builds_htb_with_a_netem_queue(self):
        """The qdisc tree that TCIntf.config will create for the params above."""
        fake = SimpleNamespace(bwParamMax=TCIntf.bwParamMax, node=SimpleNamespace(name="s1"))
        bw_cmds, parent = TCIntf.bwCmds(fake, bw=0.5)
        self.assertEqual(bw_cmds, ["%s qdisc add dev %s root handle 5:0 htb default 1",
                                   "%s class add dev %s parent 5:0 classid 5:1 htb "
                                   "rate 0.500000Mbit burst 15k"])
        self.assertEqual(parent, " parent 5:1 ")
        delay_cmds, _ = TCIntf.delayCmds(parent, max_queue_size=50)
        self.assertEqual(delay_cmds, ["%s qdisc add dev %s  parent 5:1  handle 10: netem limit 50"])
        red_cmds, red_parent = TCIntf.bwCmds(fake, bw=0.5, enable_red=True)
        self.assertIn("red limit 1000000 min 30000 max 35000 avpkt 1500", red_cmds[-1])
        self.assertEqual(red_parent, " parent 6: ")


if __name__ == "__main__":
    unittest.main()
