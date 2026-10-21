# Detector benchmark

Provenance: simulated per-second counters with seeded Poisson noise fed to the real detector classes; no network traffic.
Seeds 20 (base 1729), 600 pps per attacker, configuration digest `634c9b74126d`. Regenerate with `python3 experiments/benchmark_detectors.py --roc`; verify with `--check`.

## Detection rate (median latency) and false-positive runs

Attack scenarios show the share of runs with an alert during the attack and the median latency from attack start. Benign scenarios (no alert wanted) show runs with any alert.

| scenario | threshold | ewma | cusum | entropy |
|---|---|---|---|---|
| normal (benign) | FP 0/20 | FP 0/20 | FP 0/20 | FP 0/20 |
| burst (benign) | FP 0/20 | FP 0/20 | FP 0/20 | FP 0/20 |
| sustained | 100% (2 s) | 100% (2 s) | 100% (2 s) | 100% (2 s) |
| waves | 100% (2 s) | 100% (2 s) | 100% (2 s) | 100% (2 s) |
| single-source | 0% | 100% (2 s) | 100% (2 s) | 100% (2 s) |
| low-rate | 40% (13 s) | 100% (2 s) | 100% (2 s) | 100% (2 s) |
| pulsing | 0% | 0% | 100% (3 s) | 0% |
| ramp | 100% (8 s) | 55% (5 s) | 100% (3 s) | 10% (5 s) |
| flash-crowd (benign) | FP 20/20 | FP 15/20 | FP 20/20 | FP 0/20 |
| three-source | 100% (2 s) | 100% (2 s) | 100% (2 s) | 100% (2 s) |
| repeat-offender | 100% (2 s) | 100% (2 s) | 100% (2 s) | 100% (2 s) |

## Latency and source attribution

| detector | scenario | p95 latency s | FP rate / benign window | alert-active rate (benign) | source TP | source FP | source FN |
|---|---|---|---|---|---|---|---|
| threshold | normal | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| threshold | burst | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| threshold | sustained | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| threshold | waves | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| threshold | single-source | - | 0.0000 | 0.0000 | 0 | 0 | 20 |
| threshold | low-rate | 18 | 0.0000 | 0.0000 | 16 | 0 | 24 |
| threshold | pulsing | - | 0.0000 | 0.0000 | 0 | 0 | 40 |
| threshold | ramp | 9 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| threshold | flash-crowd | - | 0.0367 | 0.3733 | 0 | 60 | 0 |
| threshold | three-source | 2 | 0.0000 | 0.0000 | 60 | 0 | 0 |
| threshold | repeat-offender | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| ewma | normal | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| ewma | burst | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| ewma | sustained | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| ewma | waves | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| ewma | single-source | 2 | 0.0000 | 0.0000 | 20 | 0 | 0 |
| ewma | low-rate | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| ewma | pulsing | - | 0.0000 | 0.0000 | 0 | 0 | 40 |
| ewma | ramp | 6 | 0.0000 | 0.0000 | 21 | 0 | 19 |
| ewma | flash-crowd | - | 0.0250 | 0.3617 | 0 | 41 | 0 |
| ewma | three-source | 2 | 0.0000 | 0.0000 | 60 | 0 | 0 |
| ewma | repeat-offender | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| cusum | normal | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| cusum | burst | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| cusum | sustained | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| cusum | waves | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| cusum | single-source | 2 | 0.0000 | 0.0000 | 20 | 0 | 0 |
| cusum | low-rate | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| cusum | pulsing | 3 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| cusum | ramp | 4 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| cusum | flash-crowd | - | 0.0333 | 0.5267 | 0 | 60 | 0 |
| cusum | three-source | 2 | 0.0000 | 0.0000 | 60 | 0 | 0 |
| cusum | repeat-offender | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| entropy | normal | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| entropy | burst | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| entropy | sustained | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| entropy | waves | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| entropy | single-source | 2 | 0.0000 | 0.0000 | 20 | 0 | 0 |
| entropy | low-rate | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |
| entropy | pulsing | - | 0.0000 | 0.0000 | 0 | 0 | 40 |
| entropy | ramp | 5 | 0.0000 | 0.0000 | 3 | 0 | 37 |
| entropy | flash-crowd | - | 0.0000 | 0.0000 | 0 | 0 | 0 |
| entropy | three-source | 2 | 0.0000 | 0.0000 | 60 | 0 | 0 |
| entropy | repeat-offender | 2 | 0.0000 | 0.0000 | 40 | 0 | 0 |

## Operating points (one knob per detector)

TPR: attack runs detected. FPR: benign runs (normal, burst, flash-crowd) with any alert.

| detector | knob | value | TPR | FPR |
|---|---|---|---|---|
| threshold | source_pps | 10 | 0.675 | 0.333 |
| threshold | source_pps | 20 | 0.675 | 0.333 |
| threshold | source_pps | 30 (shipped) | 0.675 | 0.333 |
| threshold | source_pps | 50 | 0.625 | 0.000 |
| threshold | source_pps | 100 | 0.625 | 0.000 |
| ewma | detectors.ewma.k_sigma | 2 | 0.875 | 0.333 |
| ewma | detectors.ewma.k_sigma | 3 | 0.875 | 0.333 |
| ewma | detectors.ewma.k_sigma | 4 (shipped) | 0.819 | 0.250 |
| ewma | detectors.ewma.k_sigma | 6 | 0.756 | 0.067 |
| ewma | detectors.ewma.k_sigma | 8 | 0.750 | 0.050 |
| cusum | detectors.cusum.threshold_h | 2 | 1.000 | 0.667 |
| cusum | detectors.cusum.threshold_h | 4 | 1.000 | 0.450 |
| cusum | detectors.cusum.threshold_h | 6 (shipped) | 1.000 | 0.333 |
| cusum | detectors.cusum.threshold_h | 8 | 1.000 | 0.333 |
| cusum | detectors.cusum.threshold_h | 12 | 1.000 | 0.333 |
| entropy | detectors.entropy.kl_threshold_bits | 0.1 | 0.850 | 0.000 |
| entropy | detectors.entropy.kl_threshold_bits | 0.25 | 0.831 | 0.000 |
| entropy | detectors.entropy.kl_threshold_bits | 0.5 (shipped) | 0.762 | 0.000 |
| entropy | detectors.entropy.kl_threshold_bits | 1 | 0.669 | 0.000 |
| entropy | detectors.entropy.kl_threshold_bits | 2 | 0.144 | 0.000 |

## Interpretation

- **threshold** detects >=90% of runs in: sustained, waves, ramp, three-source, repeat-offender; misses (<50%): single-source, low-rate, pulsing; false-alarm runs on benign scenarios: flash-crowd (20/20).
- **ewma** detects >=90% of runs in: sustained, waves, single-source, low-rate, three-source, repeat-offender; misses (<50%): pulsing; false-alarm runs on benign scenarios: flash-crowd (15/20).
- **cusum** detects >=90% of runs in: sustained, waves, single-source, low-rate, pulsing, ramp, three-source, repeat-offender; misses (<50%): none; false-alarm runs on benign scenarios: flash-crowd (20/20).
- **entropy** detects >=90% of runs in: sustained, waves, single-source, low-rate, three-source, repeat-offender; misses (<50%): pulsing, ramp; false-alarm runs on benign scenarios: none.

These figures come from a model: Poisson-noised per-second counters, no queueing, packet loss or polling jitter, and mitigation disabled so every detector sees the whole attack. They compare detector logic, not end-to-end lab performance.
