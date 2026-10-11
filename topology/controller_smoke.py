"""Exercise OS-Ken forwarding and inspect attributable UDP switch flows."""

import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from lab_topology import DDoSTopo


ROOT = Path(__file__).resolve().parents[1]


def start_controller(log_file):
    return subprocess.Popen(
        [sys.executable, "-u", str(ROOT / "controller" / "run.py")],
        cwd=ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )


def wait_until(predicate, timeout, message):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise RuntimeError(message)


def run_probe(host, count):
    process = host.popen(
        [sys.executable, str(ROOT / "traffic" / "probe.py"), "--count", str(count), "--interval-ms", "100"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output, _ = process.communicate(timeout=20)
    text = output.decode(errors="replace")
    print(f"{host.name} probe:\n{text}", end="", flush=True)
    if process.returncode != 0:
        raise RuntimeError(f"{host.name} probe failed")


def run():
    with tempfile.TemporaryFile() as controller_log:
        controller = start_controller(controller_log)
        net = Mininet(topo=DDoSTopo(), controller=None, switch=OVSSwitch)
        server = None
        try:
            time.sleep(1)
            if controller.poll() is not None:
                raise RuntimeError("OS-Ken controller exited before switch startup")
            net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
            net.start()
            if not net.waitConnected(timeout=10):
                raise RuntimeError("switch did not connect to OS-Ken")
            print("switch connected to OS-Ken on 127.0.0.1:6653", flush=True)
            print("bridge fail mode:", subprocess.check_output(["ovs-vsctl", "get", "bridge", "s1", "fail_mode"], text=True).strip(), flush=True)

            loss = net.pingAll()
            print(f"ping loss: {loss:.0f}%", flush=True)
            if loss != 0:
                raise RuntimeError("pingall failed under OS-Ken forwarding")

            server = net.get("victim").popen(
                [sys.executable, "-u", str(ROOT / "traffic" / "echo_server.py")],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.3)
            if server.poll() is not None:
                raise RuntimeError("echo server exited early")
            for name, count in (("client", 10), ("a1", 3), ("a2", 3)):
                run_probe(net.get(name), count)

            time.sleep(0.5)  # Give OVS time to publish counters for the last probe.
            flows = subprocess.check_output(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"], text=True)
            udp_lines = [line.strip() for line in flows.splitlines() if "cookie=0xdd05000000000003" in line.lower()]
            punt_lines = [line.strip() for line in flows.splitlines() if "cookie=0xdd05000000000004" in line.lower()]
            if len(punt_lines) != 15:
                raise RuntimeError(f"expected 15 lab-only punt rules; found {len(punt_lines)}")
            if not any("cookie=0xdd05000000000001" in line.lower() and "actions=drop" in line for line in flows.splitlines()):
                raise RuntimeError("default drop rule is missing")
            print("lab-only punt rules: 15; default drop: present", flush=True)
            print("UDP flow count:", len(udp_lines), flush=True)
            for line in udp_lines:
                print("FLOW", line, flush=True)
            for source in ("10.0.0.11", "10.0.0.21", "10.0.0.22"):
                if not any(
                    source in line
                    and "10.0.0.10" in line
                    and re.search(r"\budp\b", line)
                    and re.search(r"n_packets=[1-9]", line)
                    for line in udp_lines
                ):
                    raise RuntimeError(f"missing attributable UDP forward flow for {source}")
            if subprocess.check_output(["ovs-vsctl", "get", "bridge", "s1", "protocols"], text=True).strip() != "[OpenFlow13]":
                raise RuntimeError("bridge is not restricted to OpenFlow 1.3")

            controller.terminate()
            controller.wait(timeout=3)
            wait_until(lambda: not net.get("s1").connected(), 5, "switch did not notice controller stop")
            controller = start_controller(controller_log)
            wait_until(lambda: net.get("s1").connected(), 10, "switch did not reconnect")
            time.sleep(0.3)
            after_reconnect = subprocess.check_output(
                ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"], text=True
            )
            if "cookie=0xdd05000000000003" in after_reconnect.lower():
                raise RuntimeError("stale UDP flows survived controller reconnect")
            print("controller reconnect: stale UDP flows cleared", flush=True)
            run_probe(net.get("client"), 3)
            print("controller reconnect: forwarding restored", flush=True)
            print("M3 controller smoke test: PASS", flush=True)
        finally:
            if server is not None and server.poll() is None:
                server.terminate()
                server.wait(timeout=3)
            net.stop()
            if controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=3)
            controller_log.seek(0)
            log_text = controller_log.read().decode(errors="replace")
            print("controller log:\n" + log_text, flush=True)


if __name__ == "__main__":
    run()
