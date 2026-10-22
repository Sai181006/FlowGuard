# M6 controlled comparison evidence — 2026-10-13

The full method, target comparison, chart, limitations and reproduction commands are in [the results report](../../docs/RESULTS.md). The raw trial directories are `results/m6-attack-off/`, `results/m6-attack-on/`, and `results/m6-high-off/`; `results/m6-summary.json` is regenerated from them and the five-minute `results/m4-baseline/` run.

The matched 600-packets/s-per-attacker trials each lasted eight seconds. The enabled run alerted on both sources in 1.555 seconds and confirmed its drop rules in 1.634 seconds. Victim-received attacker rate in the defined complete post-confirmation windows was 1,199.956 packets/s without mitigation and zero with it. Legitimate probes succeeded 80/80 in both runs. Both rules expired and were absent in the recovery flow table.

At 2,000 packets/s per attacker without mitigation, the legitimate client still succeeded 80/80. This exploratory run confirms the limitation that service-availability improvement was not observed in this lab. No trial failed ambiguously or required repetition; the M5 repeated-wave test separately verified reactivation after expiry.
