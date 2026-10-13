"""Write the M6 summary and a dependency-free SVG comparison chart."""

import json
from pathlib import Path

from analyze import compare, summarize_trial


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def chart(off, on, output):
    series = [
        ("Mitigation off", "#2459A6", off["attacker_windows"]),
        ("Mitigation on", "#D4552D", on["attacker_windows"]),
    ]
    left, top, width, height = 90, 70, 980, 500
    maximum = 1400
    def point(row):
        x = left + (row["relative_s"] + 0.5) / 8 * width
        y = top + height - row["pps"] / maximum * height
        return f"{x:.1f},{y:.1f}"
    lines = ['<svg xmlns="http://www.w3.org/2000/svg" width="1180" height="700" viewBox="0 0 1180 700">',
             '<rect width="1180" height="700" fill="white"/>',
             '<text x="90" y="38" font-family="Arial" font-size="24" font-weight="bold">Victim-received attacker traffic</text>',
             '<text x="90" y="64" font-family="Arial" font-size="15">Two sources, 600 packets/s each, eight seconds per trial</text>']
    for value in (0, 400, 800, 1200):
        y = top + height - value / maximum * height
        lines.append(f'<line x1="{left}" x2="{left+width}" y1="{y:.1f}" y2="{y:.1f}" stroke="#D6DCE5"/>')
        lines.append(f'<text x="{left-14}" y="{y+5:.1f}" text-anchor="end" font-family="Arial" font-size="15">{value}</text>')
    for second in (0, 2, 4, 6, 8):
        x = left + second / 8 * width
        lines.append(f'<text x="{x:.1f}" y="{top+height+28}" text-anchor="middle" font-family="Arial" font-size="15">{second}</text>')
    lines.append(f'<line x1="{left}" x2="{left+width}" y1="{top+height}" y2="{top+height}" stroke="#2C3440" stroke-width="2"/>')
    lines.append(f'<text x="{left+width/2}" y="{top+height+62}" text-anchor="middle" font-family="Arial" font-size="16">Seconds after attack start</text>')
    lines.append(f'<text transform="translate(26,{top+height/2}) rotate(-90)" text-anchor="middle" font-family="Arial" font-size="16">Attacker packets per second</text>')
    for index, (label, color, rows) in enumerate(series):
        if rows:
            lines.append(f'<polyline points="{" ".join(point(row) for row in rows)}" fill="none" stroke="{color}" stroke-width="4"/>')
            for row in rows:
                x, y = point(row).split(",")
                lines.append(f'<circle cx="{x}" cy="{y}" r="5" fill="{color}"/>')
        x = 650 + index * 215
        lines.append(f'<line x1="{x}" x2="{x+34}" y1="645" y2="645" stroke="{color}" stroke-width="4"/>')
        lines.append(f'<text x="{x+44}" y="650" font-family="Arial" font-size="15">{label}</text>')
    lines.append('</svg>')
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    baseline = summarize_trial(RESULTS / "m4-baseline")
    comparison = compare(RESULTS / "m6-attack-off", RESULTS / "m6-attack-on")
    high = summarize_trial(RESULTS / "m6-high-off")
    summary = {"baseline": baseline, "matched_comparison": comparison,
               "maximum_bounded_load_without_mitigation": high,
               "environment": {"os": "Ubuntu 26.04 LTS in WSL2", "kernel": "6.18.33.2-microsoft-standard-WSL2",
                               "python": "3.14.4", "mininet": "2.3.0-1.1build1",
                               "openvswitch": "3.7.1-2", "os_ken": "4.1.1-1ubuntu2",
                               "cpu": "12th Gen Intel Core i5-12450HX, 12 logical CPUs visible to WSL2",
                               "wsl_mem_total_kb": 7981708}}
    (RESULTS / "m6-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    chart(comparison["attack_off"], comparison["attack_on"], RESULTS / "m6-rate-comparison.svg")
    print(json.dumps({"baseline_alerts": baseline["alerts"],
                      "detection_latency_s": comparison["attack_on"]["first_alert_latency_s"],
                      "mitigation_latency_s": comparison["attack_on"]["first_drop_confirmation_latency_s"],
                      "attack_rate_reduction_percent": comparison["victim_attacker_rate_reduction_percent"],
                      "legitimate_success_percent": comparison["legitimate_success_with_mitigation_percent"],
                      "high_load_client": high["client"]}, indent=2))


if __name__ == "__main__":
    main()
