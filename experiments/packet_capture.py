"""Capture lab UDP requests from switch ports in one Wireshark-ready pcapng file.

This uses Linux packet sockets so the review demo needs no tcpdump or dumpcap
inside WSL. Each pcapng interface represents one observation point: a sender's
switch ingress or the victim's switch egress.
"""

import json
import selectors
import socket
import struct
import threading
import time
from pathlib import Path


ETH_P_ALL = 0x0003
SNAPLEN = 256
MAX_BYTES = 64 * 1024 * 1024
VICTIM_IP = socket.inet_aton("10.0.0.10")
VICTIM_PORT = 9000


def _pad(data):
    return data + b"\0" * (-len(data) % 4)


def _option(code, value):
    return struct.pack("<HH", code, len(value)) + _pad(value)


def _block(kind, body):
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def _is_lab_request(packet):
    """Keep IPv4 UDP requests to the lab echo service, excluding ARP/replies."""
    if len(packet) < 42 or packet[12:14] != b"\x08\x00":
        return False
    ip = 14
    header_length = (packet[ip] & 0x0F) * 4
    if packet[ip] >> 4 != 4 or header_length < 20 or len(packet) < ip + header_length + 8:
        return False
    if packet[ip + 9] != 17 or packet[ip + 16:ip + 20] != VICTIM_IP:
        return False
    # Noninitial IPv4 fragments do not contain the UDP header.
    if int.from_bytes(packet[ip + 6:ip + 8], "big") & 0x1FFF:
        return False
    return int.from_bytes(packet[ip + header_length + 2:ip + header_length + 4], "big") == VICTIM_PORT


class PacketCapture:
    """Write packets observed at named Linux interfaces to one pcapng file."""

    def __init__(self, path, interfaces):
        self.path = Path(path)
        self.interfaces = list(interfaces.items())
        self.counts = {name: 0 for name, _ in self.interfaces}
        self.truncated = False
        self._selector = selectors.DefaultSelector()
        self._stop = threading.Event()
        self._thread = None
        self._file = None
        self._error = None
        self._closed = False
        self._interface_ids = {name: index for index, (name, _) in enumerate(self.interfaces)}

    def start(self):
        if self._thread is not None:
            raise RuntimeError("capture already started")
        try:
            self._file = self.path.open("wb")
            self._file.write(_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
            for name, device in self.interfaces:
                body = struct.pack("<HHI", 1, 0, SNAPLEN)
                body += _option(2, name.encode("utf-8"))
                body += _option(3, f"FlowGuard {name} on {device}".encode("utf-8"))
                body += _option(0, b"")
                self._file.write(_block(1, body))
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                try:
                    sock.bind((device, 0))
                    self._selector.register(sock, selectors.EVENT_READ, name)
                except BaseException:
                    sock.close()
                    raise
            self._thread = threading.Thread(target=self._run, name="flowguard-packet-capture", daemon=True)
            self._thread.start()
        except BaseException:
            self._close()
            raise
        return self

    def _run(self):
        try:
            while not self._stop.is_set():
                for key, _ in self._selector.select(timeout=0.1):
                    packet = key.fileobj.recv(65535)
                    if not _is_lab_request(packet):
                        continue
                    captured = packet[:SNAPLEN]
                    timestamp_us = time.time_ns() // 1000
                    interface_id = self._interface_ids[key.data]
                    body = struct.pack("<IIIII", interface_id, timestamp_us >> 32,
                                       timestamp_us & 0xFFFFFFFF, len(captured), len(packet))
                    record = _block(6, body + _pad(captured))
                    if self._file.tell() + len(record) > MAX_BYTES:
                        self.truncated = True
                        self._stop.set()
                        break
                    self._file.write(record)
                    self.counts[key.data] += 1
        except BaseException as exc:
            self._error = exc
            self._stop.set()

    def stop(self):
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                raise RuntimeError("packet capture thread did not stop")
            self._thread = None
        self._close()
        if self._error is not None:
            raise RuntimeError("packet capture failed") from self._error
        return {"file": self.path.name, "interfaces": dict(self.interfaces),
                "requests_seen": self.counts, "truncated": self.truncated,
                "bytes": self.path.stat().st_size}

    @property
    def active(self):
        return self._thread is not None

    def _close(self):
        if self._closed:
            return
        for key in self._selector.get_map().values():
            key.fileobj.close()
        self._selector.close()
        if self._file is not None:
            self._file.close()
            self._file = None
        self._closed = True


def switch_ports(net):
    switch = net.get("s1")
    ports = {}
    for name, host in (("a1-offered", "a1"), ("a2-offered", "a2"),
                       ("client-offered", "client"), ("victim-received", "victim")):
        links = switch.connectionsTo(net.get(host))
        if len(links) != 1:
            raise RuntimeError(f"expected one switch link to {host}; found {len(links)}")
        ports[name] = links[0][0].name
    return ports


def save_summary(path, summary):
    Path(path).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
