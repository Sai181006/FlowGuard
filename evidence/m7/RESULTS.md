# M7 clean-export rehearsal — 20 October 2026

The rehearsal used only committed files from implementation/documentation commit `30c67bf`. `git archive --format=zip HEAD` produced a fresh export outside either working checkout; no untracked logs or local Python cache were copied. The export was opened in Ubuntu WSL2 and run from its root. This verifies a clean source export; it is not a network clone from GitHub.

Environment: Ubuntu 26.04 LTS in WSL2, Python 3.14.4, Mininet `2.3.0-1.1build1`, Open vSwitch `3.7.1-2`, OS-Ken `4.1.1-1ubuntu2`.

## Commands and observed output

```bash
python3 -m unittest discover -s tests -v
sudo python3 topology/controller_smoke.py
sudo python3 experiments/demo.py --output results/m7-clean-rehearsal
python3 experiments/analyze.py results/m7-clean-rehearsal
```

| Check | Observed |
| --- | --- |
| Unit tests | 9 passed |
| Controller smoke test | `M3 controller smoke test: PASS`; 20/20 pings, 16/16 initial UDP probes, six attributable UDP flows, 3/3 probes after reconnect |
| Demo phases shown live | `NORMAL`, `FLOOD`, `ALERT`, `BLOCK`, `EXPIRE`, review summary |
| Detection | Both `10.0.0.21` and `10.0.0.22` attributed; alert at 1.851 s |
| Switch confirmation | Both drop rules confirmed at 1.914 s |
| Legitimate client | 80/80 replies during attack; 10/10 after recovery |
| Recovery | Two removal events; zero attack drop rules in recovery flow table |

The saved flow-table dump showed two priority-200, UDP, source/victim/port-specific `actions=drop` entries during the attack. The recovery dump showed none. The controller recorded one alert, two drop requests, one barrier confirmation, and two rule removals. All traffic remained inside the fixed five-host topology.

The existing course PDF report was readable as 10 pages and included the recorded 1.555 s alert, 1.634 s confirmation, 80/80 probe result, and availability limitation from the earlier matched M6 trials. A link audit of the clean export checked 52 local Markdown references and found zero missing targets.

This rehearsal supports the [live demo guide](../../docs/DEMO.md). It does not change the M6 finding: improved service availability was not demonstrated because the unmitigated client also received all replies.
