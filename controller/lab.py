"""Fixed addresses of the isolated FlowGuard lab, shared by every component.

Kept free of OS-Ken and Mininet imports so the offline dashboard, native lab
and unit tests can use the same identities as the OpenFlow controller.
"""

LAB_MAC_TO_IP = {
    "02:00:00:00:00:10": "10.0.0.10",
    "02:00:00:00:00:11": "10.0.0.11",
    "02:00:00:00:00:21": "10.0.0.21",
    "02:00:00:00:00:22": "10.0.0.22",
    "02:00:00:00:00:23": "10.0.0.23",
}
LAB_MAC_TO_PORT = {
    "02:00:00:00:00:10": 1,
    "02:00:00:00:00:11": 2,
    "02:00:00:00:00:21": 3,
    "02:00:00:00:00:22": 4,
    "02:00:00:00:00:23": 5,
}
LAB_IPS = frozenset(LAB_MAC_TO_IP.values())
LAB_IP_TO_MAC = {address: mac for mac, address in LAB_MAC_TO_IP.items()}
VICTIM_IP = "10.0.0.10"
CLIENT_IP = "10.0.0.11"
VICTIM_PORT = 9000
VICTIM_SWITCH_PORT = LAB_MAC_TO_PORT[LAB_IP_TO_MAC[VICTIM_IP]]
