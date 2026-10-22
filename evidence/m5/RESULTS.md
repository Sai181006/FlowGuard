# M5 mitigation and recovery evidence — 2026-10-13

## Commands

Run as root in Ubuntu WSL from this checkout:

```bash
python3 -m unittest discover -s tests -v
python3 experiments/run_trial.py --mode mitigation --output results/m5-mitigation --pps 600 --duration-s 8
python3 experiments/run_trial.py --mode mitigation-repeat --output results/m5-repeat --pps 600 --duration-s 8
python3 experiments/analyze.py results/m5-mitigation
```

## Single-wave result

- Nine focused tests passed, including a check that the mitigation match specifies IPv4, UDP, attacker source, victim destination and UDP port 9000, and rejects the protected client and non-lab sources.
- The controller alerted on `10.0.0.21` and `10.0.0.22` 2.061 seconds after the generators' start records. Its barrier confirmation arrived at 2.131 seconds.
- Open vSwitch showed exactly two priority-200 UDP drop rules, each matching one attacker, `10.0.0.10:9000`, and a 10-second hard timeout. During the captured flow-table sample the rules counted 1,000 and 916 dropped packets.
- The saved victim receive trace shows zero attacker packets/s in five complete one-second windows after rule confirmation. The legitimate client received 80/80 echo replies during the attack and 10/10 recovery replies.
- Both drop rules emitted removal events roughly 4.07 seconds after the eight-second attack ended; none remained in the recovery flow table.

## Repeated-wave result

Two identical eight-second waves were separated by a 12-second recovery interval. Each wave generated one attributed alert and exactly two drop requests, followed by one barrier confirmation and two removal events. There were no concurrent duplicate drop requests. The legitimate client received 80/80 replies in each wave; no drop rule remained after either recovery interval.

The raw controller and victim JSONL, probe CSVs, generator logs, flow tables and trial metadata are under `results/m5-mitigation/` and `results/m5-repeat/`. The generator start record precedes its first send by a small amount, so latencies approximate first-packet latency. M6 makes the matched disabled/enabled performance comparison.
