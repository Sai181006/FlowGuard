# M4 monitoring and detection evidence — 2026-10-13

## Commands

Run as root in Ubuntu WSL from this checkout:

```bash
python3 -m unittest discover -s tests -v
python3 experiments/run_trial.py --mode detection --output results/m4-detection --pps 600 --duration-s 8
python3 experiments/run_trial.py --mode baseline --output results/m4-baseline
python3 experiments/analyze.py results/m4-detection results/m4-baseline
```

The topology has no NAT or external link. The load generator has a fixed destination of `10.0.0.10:9000`, a maximum of 2,000 packets/s per host, and a maximum duration of 30 seconds.

## Verified detector behavior

- Nine focused tests passed, including counter reset, missing-flow, short-burst, protected-client and precise drop-match checks.
- The controller sampled the relevant UDP forwarding flows once per second. During the two-source trial, live rates were approximately 600 packets/s for each attacker, agreeing with the configured generator rate.
- With mitigation disabled, the two sources `10.0.0.21` and `10.0.0.22` generated one alert 2.305 seconds after the first generator start record. No drop rule was requested. The legitimate client received 80/80 probes and 10/10 recovery probes.
- The five-minute normal trial included 600 probes each from the client and `a1` plus a simultaneous 0.6-second, 70-packets/s burst from `a1` and `a2`. Both normal senders received 600/600 replies. The controller produced zero alerts and zero drop requests across 307 samples.
- The maximum sustained victim rate outside the brief burst was 5.998 packets/s; the maximum sustained source rate was 2.999 packets/s. Including the burst, the highest observed victim sample was 39.929 packets/s. Applying the plan's calibration floors leaves the configured thresholds at 100 victim packets/s and 30 packets/s per source.

The generator start timestamp is logged immediately before its first send, so the reported alert latency approximates first-packet latency. The raw JSONL, probe CSVs, flow dumps and metadata are under `results/m4-detection/` and `results/m4-baseline/`.

## Scope

M4 demonstrates attributed detection without mitigation. The M5 rule lifecycle and M6 matched comparison are recorded separately.
