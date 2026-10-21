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


def flood_start(trial, wave=None):
    suffix = f"-wave{wave}" if wave is not None else ""
    return min(jsonl(trial / f"attack-{name}{suffix}.jsonl")[0]["monotonic_s"]
               for name in ("a1", "a2"))


def probe_counts(path):
    rows = list(csv.reader(path.read_text(encoding="utf-8").splitlines()))
    measured = [row for row in rows[1:] if len(row) >= 3 and row[1].isdigit()]
    return {"sent": len(measured), "received": sum(row[2] == "ok" for row in measured)}


def attacker_windows(trial, from_s=0, until_s=None, wave=None):
    started = flood_start(trial, wave=wave)
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


def drop_rule_count(path):
    return sum("cookie=0xdd05000000000005" in line.lower()
               for line in Path(path).read_text(encoding="utf-8").splitlines())


def repeat_wave_intervals(trial, waves):
    intervals = []
    for wave in waves:
        number = wave["number"]
        attack_logs = [jsonl(trial / f"attack-{name}-wave{number}.jsonl") for name in ("a1", "a2")]
        starts = [rows[0]["monotonic_s"] for rows in attack_logs if rows and rows[0].get("event") == "start"]
        ends = [rows[-1]["monotonic_s"] for rows in attack_logs if rows and rows[-1].get("event") == "stop"]
        if len(starts) != 2 or len(ends) != 2:
            raise ValueError(f"repeat wave {number} is missing an attacker start or stop record")
        intervals.append({"number": number, "start": min(starts), "end": max(ends)})
    return intervals


def summarize_repeat_trial(path, meta, records):
    path = Path(path)
    waves = meta.get("waves")
    if not isinstance(waves, list) or not waves:
        raise ValueError("mitigation-repeat metadata must contain wave records")
    numbers = [wave.get("number") for wave in waves]
    if numbers != list(range(1, len(waves) + 1)):
        raise ValueError("mitigation-repeat wave numbers must be sequential from 1")
    intervals = repeat_wave_intervals(path, waves)
    ordered_starts = [interval["start"] for interval in intervals]
    if ordered_starts != sorted(ordered_starts):
        raise ValueError("mitigation-repeat attack intervals are out of order")

    results = []
    for index, (wave, interval) in enumerate(zip(waves, intervals)):
        number = interval["number"]
        started = interval["start"]
        ended = interval["end"]
        next_start = intervals[index + 1]["start"] if index + 1 < len(intervals) else float("inf")
        wave_events = [row for row in records
                       if started <= row.get("monotonic_s", float("inf")) <= ended]
        alerts = [row for row in wave_events if row["type"] == "alert"]
        confirmations = [row for row in wave_events if row["type"] == "drop_confirmed"]
        requests = [row for row in wave_events if row["type"] == "drop_requested"]
        removals = [row for row in records if row["type"] == "drop_removed"
                    and ended <= row.get("monotonic_s", float("inf")) < next_start]
        attacker_rows = attacker_windows(path, 0, meta["duration_s"], wave=number)
        after_file = path / f"flows-after-wave{number}.txt"
        during_file = path / f"flows-during-wave{number}.txt"
        results.append({
            "number": number,
            "attack_start_monotonic_s": started,
            "attack_end_monotonic_s": ended,
            "first_alert_latency_s": alerts[0]["monotonic_s"] - started if alerts else None,
            "first_alert_sources": sorted(alerts[0]["sources"]) if alerts else [],
            "first_drop_confirmation_latency_s": (
                confirmations[0]["monotonic_s"] - started if confirmations else None
            ),
            "alerts": len(alerts),
            "drop_requests": len(requests),
            "drop_confirmations": len(confirmations),
            "drop_removals": len(removals),
            "client": probe_counts(path / f"client-wave{number}.csv"),
            "drop_rules_during_wave": drop_rule_count(during_file),
            "drop_rules_after_wave": drop_rule_count(after_file),
            "attacker_windows": attacker_rows,
            "attacker_mean_pps_all_windows": average_rate(attacker_rows),
            "removed_after_attack_s": [row["monotonic_s"] - ended for row in removals],
        })

    recovery_path = path / "recovery-client.csv"
    after_last_wave = path / f"flows-after-wave{len(waves)}.txt"
    result = {"waves": results, "recovery_client": probe_counts(recovery_path),
              "drop_rules_after_recovery": drop_rule_count(after_last_wave)}
    if "recovery_probe_exit" in meta:
        result["recovery_probe_exit"] = meta["recovery_probe_exit"]
    return result


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
    if meta["mode"] == "mitigation-repeat":
        result.update(summarize_repeat_trial(path, meta, records))
        return result
    started = flood_start(path)
    result["attack_start_monotonic_s"] = started
    result["first_alert_latency_s"] = alerts[0]["monotonic_s"] - started if alerts else None
    result["first_alert_sources"] = sorted(alerts[0]["sources"]) if alerts else []
    result["first_drop_confirmation_latency_s"] = confirmed[0]["monotonic_s"] - started if confirmed else None
    result["client"] = probe_counts(path / "client.csv")
    result["recovery_client"] = probe_counts(path / "recovery-client.csv")
    result["drop_rules_after_recovery"] = drop_rule_count(path / "flows-after-recovery.txt")
    result["attacker_windows"] = attacker_windows(path, 0, meta["duration_s"])
    result["attacker_mean_pps_all_windows"] = average_rate(result["attacker_windows"])
    result["removed_after_attack_s"] = [row["monotonic_s"] - meta["attack_end_monotonic_s"] for row in removed]
    return result


def compare(off, on):
    off = Path(off)
    on = Path(on)
    off_meta = json.loads((off / "metadata.json").read_text(encoding="utf-8"))
    on_meta = json.loads((on / "metadata.json").read_text(encoding="utf-8"))
    valid_pairs = {("attack-off", "attack-on"), ("detection", "mitigation")}
    pair = (off_meta.get("mode"), on_meta.get("mode"))
    if pair not in valid_pairs:
        raise ValueError("compare requires a matched single-wave attack-off/on or detection/mitigation pair")
    for label, meta in ((pair[0], off_meta), (pair[1], on_meta)):
        if meta.get("status") != "completed":
            raise ValueError(f"{label} trial must have completed successfully")
        if meta.get("execution_status", "completed") != "completed":
            raise ValueError(f"{label} trial execution did not complete")
        validation = meta.get("validation")
        if validation is not None and (
                not isinstance(validation, dict) or validation.get("status") != "passed"):
            raise ValueError(f"{label} trial validation did not pass")
    if off_meta.get("mitigation_enabled") is not False or on_meta.get("mitigation_enabled") is not True:
        raise ValueError("comparison trials must disable mitigation for off and enable it for on")
    for key in ("pps_per_attacker", "duration_s", "config"):
        if key not in off_meta or key not in on_meta:
            raise ValueError(f"comparison trials must include {key}")
        if off_meta.get(key) != on_meta.get(key):
            raise ValueError(f"comparison trials must match {key}")
    if off_meta.get("ping_loss_percent") != on_meta.get("ping_loss_percent"):
        raise ValueError("comparison trials must have matching baseline ping loss")
    if off_meta.get("ping_loss_percent") != 0:
        raise ValueError("comparison trials require zero baseline ping loss")
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
