# Validation record — 20 October 2026

The offline dashboard and local hardening were checked on macOS/Apple Silicon
with CPython 3.14.6. No Linux, VM, live switch, or external attack traffic was
used. The real-world case was researched with GPT-6 Luna at Max using primary
sources; source claims and their limits are recorded in `RESEARCH.md`.

## Automated checks

- **50/50 native unit tests pass.** These cover detector rates and persistence,
  source/port identity, ARP checks, protected-service accounting, ingress bypass
  rejection, configuration bounds, mitigation reconciliation, topology ports,
  experiment collisions and validation, repeat-wave analysis, deterministic
  dashboard scenarios, historical data preservation, secure asset routes, and
  localhost request protections. Five new native-lab tests additionally cover
  actual socket forwarding/echo, actual discard before the backend, unknown
  source rejection, protected-client handling, disabled policy and rule expiry.
- The focused audit runner passes **41 security and experiment-integrity
  regressions** and writes `audit/reproductions.json`.
- Python compilation, JavaScript syntax (`node --check`), shell syntax, and
  `git diff --check` pass.
- All 100 HTML IDs are unique. All 13 required runtime resources, including the
  eight local fonts, return HTTP 200. There are zero external runtime assets.
  `artifacts/offline-asset-check.json` records the result.
- The original tracked `results/` files remain unchanged. The computed original
  M6 comparison still matches the saved summary exactly. Repeat-wave analysis
  now succeeds on the original `results/m5-repeat` data.

## Browser checks

Checked through the actual local dashboard, including desktop and narrow-screen
layouts:

| Check | Observed result |
|---|---|
| Sustained model, mitigation on, t=9s | 10 packets/s delivered; 1,200 dropped; 100% modeled client success |
| Same inputs, mitigation off | 1,210 packets/s forwarded; zero dropped; modeled overload at the explicitly assumed 1,000 packets/s capacity |
| Normal scenario | No alert or drop; 14 packets/s baseline |
| Single-window burst | No mitigation after the isolated high observation |
| Repeat waves | Temporary rule behavior, expiry, and redetection appear on the timeline |
| One source | 612 packets/s total at the default rate; no two-source alert |
| Below victim threshold | 90 packets/s; no alert |
| Attack rate changed to 1,200 per source | At t=9s, 2,400 packets/s are modeled as dropped |
| Recorded experiment | 80/80 original client replies in each run; measured and derived values labeled |
| First recorded drop sample | An em dash marks an unknown interval rate, rather than pretending the first baseline measures zero |
| Real localhost check | 5/5 replies received; the app showed actual measured RTTs and stopped the service |
| Packet desk | Filtering, layer inspection, actual recorded probe inspection, and labeled JSON trace export work |
| Research story | Case navigation, published-response milestone controls, source links, and scope boundary work |
| Explainers | Node explanations, ARP/protocol tabs, guide dialog, and home navigation work |
| Narrow-screen layout | Compact readable topology; no document-level horizontal overflow at 375px |
| Browser console | No error messages during the tested flows |

`artifacts/flowguard-dashboard.png` is a screenshot of the completed interface.
`artifacts/export-example.json` is an example of the model's explicitly labeled
trace export, not a packet capture.

## What remains unverified

The complete Windows terminal runbook and launchers are prepared, but no native
Windows machine was available for execution. The 21-test portable subset passes
on Python 3.12 on this Mac without installing its SDN dependencies. Wireshark,
Dumpcap and Npcap are not installed here. A real `tcpdump` attempt on `lo0`
was denied because this account could not open the BPF capture device. No PCAP
was produced or fabricated. The Wireshark procedure needs rehearsal on the
presentation laptop with its existing capture driver/access settings.

The strengthened OpenFlow controller has not been run against a live
Mininet/Open vSwitch network. Native message-level tests do not replace that
integration check. The original historical runs predate the fixes. Barrier
replies do not independently establish installed-rule correctness; an actual
switch test should correlate errors, inspect rules, and measure victim traffic.

Server saturation, Internet-scale attack resistance, reflection/amplification,
upstream filtering, real-client availability improvements, and unknown hosts
are not established by this demo. Interactive-model capacity and response
figures are assumptions. Recorded results prove filtering in their measured
lab setup; the original client also had zero loss without mitigation.

## Recheck

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python audit/reproduce.py
node --check dashboard/app.js
.venv/bin/python demo/server.py
```

## Real native terminal comparison

`demo/live_lab.py` completed both OFF and ON trials on macOS with the original
detector, echo service and probe. The gateway handled actual loopback UDP
datagrams; enforcement occurred in Python userspace. Every forwarded request
had a matching echo reply. Both sources received replies again after rule
expiry, and every acceptance check passed in both modes.

| Measured quantity | OFF | ON |
|---|---:|---:|
| Source packets received by gateway | 9,616 | 9,616 |
| Matching victim echo replies to those source packets | 9,616 | 2,418 |
| Datagrams actually discarded by gateway | 0 | 7,198 |
| Protected-client replies | 230/230 | 230/230 |
| Active drop rules after recovery | 0 | 0 |
| Gateway errors | 0 | 0 |

Evidence is retained in `artifacts/terminal-verified/comparison.json` and each
mode's event JSONL, packet observation CSV, original probe CSV and echo-service
receive windows. These figures include baseline and recovery traffic; they are
not post-mitigation-only rates. The test establishes live selective filtering
on localhost, not OpenFlow enforcement or saturation protection.

The complete automatic `demo/terminal.py` presentation also passed using
`python3.12 -S` on this Mac: preflight, detector walkthrough, historical switch
readback and both fresh live packet trials. `-S` disables site packages.
`artifacts/terminal-python312.txt` retains its console transcript; it again
returned 230/230 client replies per mode and 7,198 actual ON-mode drops.

The fresh Windows package includes these historical Mac observations, the
complete source and local assets, but no virtual environment. Its manifest
records per-file SHA-256 values; `artifacts/package-check.json` records ZIP
integrity and the ZIP's digest. Windows `.cmd` files use CRLF line endings in
the archive. The package is a transfer artifact, not a Windows runtime test.
