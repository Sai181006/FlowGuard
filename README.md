# FlowGuard: SDN DDoS detection and mitigation

FlowGuard demonstrates a two-source UDP flood in a **private Mininet network**. An OS-Ken controller polls Open vSwitch counters, attributes the flood to its sources, and installs 10-second OpenFlow drop rules for those sources while a legitimate client keeps probing the same victim service.

For a start-to-finish explanation of the network, detector, rules, evidence, and review presentation, read the [complete project guide](docs/PROJECT_EXPLAINED.md).

## Review in one command

Follow [the setup and live demo guide](docs/DEMO.md), then run this from the repository root in Ubuntu WSL:

```bash
sudo python3 experiments/demo.py
```

The command starts the controller, five-host topology, legitimate probe, bounded two-source traffic, and recovery check. It prints the alert, rule confirmation, rule expiry, and probe results as a review timeline. Each run saves its evidence in a new `results/demo-*` folder and tears down Mininet automatically.

## What the measured results show

In the matched 600-packets/s-per-source trials, the switch confirmed mitigation in 1.634 seconds and victim-received attacker traffic fell to zero in complete post-confirmation windows. The legitimate client received 80/80 replies with mitigation. It also received 80/80 without mitigation, so **improved service availability was not demonstrated**. See [results and limitations](docs/RESULTS.md) and the [saved comparison chart](results/m6-rate-comparison.png).

The traffic generator is fixed to `10.0.0.10:9000` inside the Mininet topology and enforces a maximum of 2,000 packets/s per source for 30 seconds. The topology has no NAT or external link. The project supports this IPv4 UDP lab scenario; it is not a production DDoS defense.

The course [PDF report](reports/FlowGuard_BCSE308P_Project_Report.pdf) and [editable Word report](reports/FlowGuard_BCSE308P_Project_Report.docx) are included. Team names and registration details are intentionally blank for the owner to fill before submission.
