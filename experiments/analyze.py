"""Derive reproducible FlowGuard metrics from the saved raw trial files."""

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTACKERS = ("10.0.0.21", "10.0.0.22")


def jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def events(trial):
    return jsonl(trial / "controller.jsonl")


def flood_start(trial):
    return min(jsonl(trial / f"attack-{name}.jsonl")[0]["monotonic_s"] for name in ("a1", "a2"))


def probe_counts(path):
    rows = list(csv.reader(path.read_text(encoding="utf-8").splitlines()))
    measured = [row for row in rows[1:] if len(row) >= 3 and row[1].isdigit()]
    return {"sent": len(measured), "received": sum(row[2] == "ok" for row in measured)}


def attacker_windows(trial, from_s=0, until_s=None):
    started = flood_start(trial)
    result = []
    for row in jsonl(trial / "victim.jsonl"):
        relative = row["window_start_s"] - started
        if relative < from_s or (until_s is not None and relative + row["elapsed_s"] > until_s):
            continue
        result.append({"relative_s": relative,
                       "pps": sum(row["by_source"].get(source, 0) for source in ATTACKERS) / row["elapsed_s"]})
    return result


def average_rate(windows):
    return sum(row["pps"] for row in windows) / len(windows) if windows else None


def summarize_trial(path):
    path = Path(path)
    meta = json.loads((path / "metadata.json").read_text())
    records = events(path)
    alerts = [row for row in records if row["type"] == "alert"]
    requested = [row for row in records if row["type"] == "drop_requested"]
    confirmed = [row for row in records if row["type"] == "drop_confirmed"]
    removed = [row for row in records if row["type"] == "drop_removed"]
    result = {"mode": meta["mode"], "status": meta["status"], "ping_loss_percent": meta["ping_loss_percent"],
              "samples": sum(row["type"] == "sample" for row in records),
              "alerts": len(alerts), "drop_requests": len(requested), "drop_confirmations": len(confirmed),
              "drop_removals": len(removed)}
    if meta["mode"] == "baseline":
        result["normal_client"] = probe_counts(path / "normal-client.csv")
        result["normal_a1"] = probe_counts(path / "normal-a1.csv")
        burst_start = min(jsonl(path / f"burst-{name}.jsonl")[0]["monotonic_s"] for name in ("a1", "a2"))
        normal_samples = [row for row in records if row["type"] == "sample"
                          and abs(row["monotonic_s"] - burst_start) > 3]
        result["normal_max_victim_pps"] = max((row["victim_pps"] for row in normal_samples), default=0)
        result["normal_max_source_pps"] = max((max(row["source_pps"].values(), default=0)
                                                for row in normal_samples), default=0)
        result["observed_max_victim_pps_with_burst"] = max((row["victim_pps"] for row in records
                                                              if row["type"] == "sample"), default=0)
        return result
    started = flood_start(path)
    result["attack_start_monotonic_s"] = started
    result["first_alert_latency_s"] = alerts[0]["monotonic_s"] - started if alerts else None
    result["first_alert_sources"] = sorted(alerts[0]["sources"]) if alerts else []
    result["first_drop_confirmation_latency_s"] = confirmed[0]["monotonic_s"] - started if confirmed else None
    result["client"] = probe_counts(path / "client.csv")
    result["recovery_client"] = probe_counts(path / "recovery-client.csv")
    result["drop_rules_after_recovery"] = sum("cookie=0xdd05000000000005" in line.lower()
                                               for line in (path / "flows-after-recovery.txt").read_text().splitlines())
    result["attacker_windows"] = attacker_windows(path, 0, meta["duration_s"])
    result["attacker_mean_pps_all_windows"] = average_rate(result["attacker_windows"])
    result["removed_after_attack_s"] = [row["monotonic_s"] - meta["attack_end_monotonic_s"] for row in removed]
    return result


def compare(off, on):
    off = Path(off)
    on = Path(on)
    off_summary = summarize_trial(off)
    on_summary = summarize_trial(on)
    from_s = max(0, on_summary["first_drop_confirmation_latency_s"] or 0) + 0.5
    duration = min(json.loads((off / "metadata.json").read_text())["duration_s"],
                   json.loads((on / "metadata.json").read_text())["duration_s"])
    off_rate = average_rate(attacker_windows(off, from_s, duration))
    on_rate = average_rate(attacker_windows(on, from_s, duration))
    reduction = None if not off_rate else 100 * (1 - on_rate / off_rate)
    return {"attack_off": off_summary, "attack_on": on_summary, "comparison_start_s": from_s,
            "unmitigated_attacker_pps": off_rate, "mitigated_attacker_pps": on_rate,
            "victim_attacker_rate_reduction_percent": reduction,
            "legitimate_success_with_mitigation_percent": 100 * on_summary["client"]["received"] / on_summary["client"]["sent"]}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trials", nargs="+", type=Path)
    args = parser.parse_args()
    if len(args.trials) == 2:
        print(json.dumps(compare(*args.trials), indent=2))
    else:
        for trial in args.trials:
            print(json.dumps(summarize_trial(trial), indent=2))
