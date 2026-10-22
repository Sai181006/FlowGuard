# M9 native localhost lab evidence

Real runs of `demo/live_lab.py` on Linux (Ubuntu 24.04, Python 3.12.3, 21 October 2026):
real UDP datagrams on 127.0.0.1, the project's detectors, and FlowGuard's
userspace gateway, token bucket and bottleneck queue. No OpenFlow switch and no
kernel qdisc are involved. Each folder was produced under `results/native-wp4-*`
and copied here unchanged, except that the large per-datagram `packets.csv`
files (about 3 MB each) were left out of the repository.

| Folder | Command (all with `--mitigation compare` unless noted) |
| --- | --- |
| `m9-native-original-final` | `python3 demo/live_lab.py` (original behaviour, no bottleneck) |
| `m9-native-bottleneck` | `--bottleneck-pps 300 --queue-packets 50` |
| `m9-native-ratelimit` | `--bottleneck-pps 300 --queue-packets 50 --action rate_limit` |
| `m9-native-red-ewma-warm` | `--bottleneck-pps 300 --queue-packets 50 --queue-discipline red --detector ewma` |
| `m9-native-cusum` | `--bottleneck-pps 300 --queue-packets 50 --detector cusum` |
| `m9-native-entropy` | `--bottleneck-pps 300 --queue-packets 50 --detector entropy` |
| `m9-native-graduated-waves` | `--mitigation on --bottleneck-pps 300 --queue-packets 50 --action graduated --backoff --waves 3` |

Each mode folder holds `summary.json` (checks, per-phase client metrics,
queue statistics, effective configuration), `events.jsonl` (detector samples,
alerts, rule installation and expiry), `client.csv` (every probe), and
`victim.jsonl` (per-second datagrams received by the echo server). Compare runs
also contain `comparison.json` with the OFF/ON availability table.
