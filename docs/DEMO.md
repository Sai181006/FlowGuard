# FlowGuard setup and review demonstration

## Architecture in 30 seconds

```text
   a1 10.0.0.21 ──┐
   a2 10.0.0.22 ──┼── s1 (Open vSwitch, OpenFlow 1.3) ── victim 10.0.0.10:9000
   a3 10.0.0.23 ──┤                 │
client 10.0.0.11 ─┘            OS-Ken controller
                            poll → detect → drop rules
```

All five hosts are Mininet namespaces on one private switch. The controller polls per-source UDP forwarding counters each second. It alerts after two consecutive high windows with at least two high-rate sources, then installs precise 10-second rules for those sources. The client's probes use the same UDP echo service as the attack.

## Clean Ubuntu WSL setup

Use Ubuntu WSL2 with systemd and Python 3. The verified environment was Ubuntu 26.04 LTS, Python 3.14.4, Mininet 2.3.0, Open vSwitch 3.7.1, and Ubuntu's OS-Ken 4.1.1 package. In Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y git mininet openvswitch-switch python3-os-ken
sudo systemctl start openvswitch-switch
git clone https://github.com/Sai181006/FlowGuard.git
cd FlowGuard
python3 -m unittest discover -s tests -v
sudo python3 topology/controller_smoke.py
```

The controller smoke test checks the OpenFlow connection, all host pings, UDP probes, attributable flow counters, and reconnection. Its final line should be `M3 controller smoke test: PASS`. If Mininet reports stale interfaces after an interrupted run, use `sudo mn -c` before retrying. Do not run two trials at once; they use the same switch and controller port.

For the existing Windows workspace, the project path inside Ubuntu is `/mnt/c/Users/Sai/Documents/ChatGPT/cn project/ddos_publish`. From PowerShell, start Ubuntu with `wsl -d Ubuntu`, then `cd` to that path before running the commands below.

## Live review: about 45 seconds

From the repository root in Ubuntu:

```bash
sudo python3 experiments/demo.py
```

The command generates a new `results/demo-YYYYMMDD-HHMMSS` folder. The default traffic is **two sources at 600 packets/s each for eight seconds**. It prints an `ALERT` line with both source addresses and their rates, a `BLOCK` line when the switch confirms the rules, `EXPIRE` lines with blocked-packet counts, and a final summary with detection latency, probe success, and zero remaining drop rules. Normal connectivity and three initial probes per participating host are checked before the flood. The run lasts longer than eight seconds because it waits for rule expiry and tests recovery.

Talk track while the command runs:

1. **Normal service:** “The controller first verifies 20/20 host pings and primes the UDP echo flows. The legitimate client is `10.0.0.11`; the victim is `10.0.0.10:9000`.”
2. **Flood and detection:** “Two private hosts send fixed-size UDP packets. The switch counters rise; after two high windows, the controller names both senders and reports packets per second.”
3. **Mitigation:** “The switch confirms a higher-priority drop rule for each attacker, matched to that source and the victim service. The legitimate client has a separate forwarding flow.”
4. **Recovery:** “The 10-second rules expire. The final probe succeeds and the recovery flow-table dump contains no attack drop rules.”
5. **Honest conclusion:** “The attack stream is filtered, but this lab did not show a gain in service availability because the client already received every reply in the unmitigated trial.”

For a slower review, a new run can use `--duration-s 12`. The runner caps duration at 30 seconds and per-source rate at 2,000 packets/s; the destination is fixed inside the lab.

## Show the evidence after the live run

Replace `<run>` with the folder printed by the demo:

```bash
python3 experiments/analyze.py results/<run>
grep 'cookie=0xdd05000000000005' results/<run>/flows-during.txt
grep 'cookie=0xdd05000000000005' results/<run>/flows-after-recovery.txt
```

The first `grep` should find two drop rules with the attacker source addresses and no output actions. The recovery `grep` should print nothing. The analyzer shows client and recovery probe counts, event counts, latency, and remaining rule count. Raw events are in `controller.jsonl`; switch flow tables, victim receive counts, client CSV, and generator records are in the same folder.

For a matched comparison, run two additional trials sequentially:

```bash
sudo python3 experiments/run_trial.py --mode attack-off --output results/review-off --pps 600 --duration-s 8
sudo python3 experiments/run_trial.py --mode attack-on --output results/review-on --pps 600 --duration-s 8
python3 experiments/analyze.py results/review-off results/review-on
```

Use fresh output folder names when repeating these commands. The [saved chart](../results/m6-rate-comparison.png) and [measured results](RESULTS.md) are ready for a review where time permits only one live trial. A five-minute benign baseline can be reproduced with `sudo python3 experiments/run_trial.py --mode baseline --output results/review-baseline`.

The [course PDF report](../reports/FlowGuard_BCSE308P_Project_Report.pdf) and [editable Word report](../reports/FlowGuard_BCSE308P_Project_Report.docx) contain the measured results and limitations. Team names and registration details remain blank for the owner to fill before submission.

The clean committed-source rehearsal and its observed output are recorded in [M7 evidence](../evidence/m7/RESULTS.md).

## Questions reviewers may ask

- **Why two sources and two windows?** The detector is designed for a distributed flood and avoids acting on one short burst. Both thresholds are in `config/detector.json`.
- **How do you know the switch applied the rule?** The controller records a barrier confirmation, and the saved OpenFlow flow table shows each priority-200 drop rule. Expiry events include blocked-packet counters.
- **What stayed available?** The legitimate client's echo probes succeeded before, during, and after the mitigated attack. In the matched unmitigated trial they also succeeded, so availability improvement is unproven.
- **What is outside scope?** TCP SYN floods, spoofed addresses, multiple switches, public-network traffic, and production performance.
