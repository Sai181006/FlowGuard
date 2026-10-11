"""Run a bounded M2 smoke test using OVS bridge mode (no SDN controller yet)."""

import subprocess
import sys
import time
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSBridge

from lab_topology import DDoSTopo, HOSTS


ROOT = Path(__file__).resolve().parents[1]


def run():
    net = Mininet(topo=DDoSTopo(), controller=None, switch=OVSBridge)
    server = None
    try:
        net.start()
        print("hosts:", ", ".join(f"{name}={net.get(name).IP()}" for name in HOSTS), flush=True)

        bridge_protocols = subprocess.run(
            ["ovs-vsctl", "get", "bridge", "s1", "protocols"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        print("bridge protocols:", bridge_protocols, flush=True)
        if "OpenFlow13" not in bridge_protocols:
            raise RuntimeError("s1 did not enable OpenFlow 1.3")
        subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "show", "s1"], check=True, stdout=subprocess.DEVNULL)
        print("OpenFlow 1.3 query: success", flush=True)

        loss = net.pingAll()
        print(f"ping loss: {loss:.0f}%", flush=True)
        if loss != 0:
            raise RuntimeError("host connectivity smoke test failed")

        server = net.get("victim").popen(
            [sys.executable, "-u", str(ROOT / "traffic" / "echo_server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.3)
        if server.poll() is not None:
            raise RuntimeError(f"echo server exited early: {server.stderr.read().decode(errors='replace')}")

        probe = net.get("client").popen(
            [sys.executable, str(ROOT / "traffic" / "probe.py"), "--count", "10", "--interval-ms", "100"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output, _ = probe.communicate(timeout=20)
        print(output.decode(errors="replace"), end="", flush=True)
        if probe.returncode != 0:
            raise RuntimeError(f"UDP echo probe failed with exit code {probe.returncode}")
        print("M2 smoke test: PASS", flush=True)
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=3)
        net.stop()


if __name__ == "__main__":
    run()
