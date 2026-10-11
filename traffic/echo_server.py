"""Small UDP echo service for the private Mininet lab."""

import argparse
import ipaddress
import signal
import socket


LAB_NETWORK = ipaddress.ip_network("10.0.0.0/24")
STOP = False


def lab_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid IP address") from exc
    if address not in LAB_NETWORK and address != ipaddress.ip_address("127.0.0.1"):
        raise argparse.ArgumentTypeError("address must be in 10.0.0.0/24 or 127.0.0.1")
    return str(address)


def request_stop(_signum, _frame):
    global STOP
    STOP = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", type=lab_address, default="10.0.0.10")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.bind, args.port))
        sock.settimeout(0.5)
        print(f"UDP echo listening on {args.bind}:{args.port}", flush=True)
        while not STOP:
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            sock.sendto(data, peer)


if __name__ == "__main__":
    main()
