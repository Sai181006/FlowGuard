"""Render the verified M6 rate comparison as a PNG for the course report."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from analyze import compare


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
DATA = compare(RESULTS / "m6-attack-off", RESULTS / "m6-attack-on")
IMAGE = RESULTS / "m6-rate-comparison.png"


def font(size, bold=False):
    windows_font = Path(r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf")
    linux_font = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else
                      "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    for candidate in (windows_font, linux_font):
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


im = Image.new("RGB", (1400, 800), "white")
draw = ImageDraw.Draw(im)
left, top, width, height = 130, 110, 1130, 550
scale = 1400
draw.text((left, 30), "Victim received attacker traffic", font=font(28, True), fill="#1B2739")
draw.text((left, 68), "Two sources at 600 packets/s each, eight seconds per trial", font=font(18), fill="#4D5C6B")
for value in (0, 400, 800, 1200):
    y = top + height - value / scale * height
    draw.line((left, y, left + width, y), fill="#D7DEE8", width=2)
    draw.text((left - 75, y - 10), str(value), font=font(18), fill="#36485D")
for second in (0, 2, 4, 6, 8):
    x = left + second / 8 * width
    draw.text((x - 8, top + height + 18), str(second), font=font(18), fill="#36485D")
draw.line((left, top + height, left + width, top + height), fill="#273748", width=3)
draw.text((left + width / 2 - 100, top + height + 62), "Seconds after attack start", font=font(18), fill="#273748")
draw.text((25, top + height / 2 - 20), "packets/s", font=font(18), fill="#273748")
confirmed = DATA["attack_on"]["first_drop_confirmation_latency_s"]
confirm_x = left + confirmed / 8 * width
for dash_y in range(top, top + height, 16):
    draw.line((confirm_x, dash_y, confirm_x, min(dash_y + 8, top + height)), fill="#8C98A8", width=2)
draw.text((confirm_x + 10, top + 8), f"Rule confirmed at {confirmed:.2f} s", font=font(16), fill="#526171")
for name, color, rows in (
    ("Mitigation off", "#2459A6", DATA["attack_off"]["attacker_windows"]),
    ("Mitigation on", "#D4552D", DATA["attack_on"]["attacker_windows"]),
):
    points = [(left + (row["relative_s"] + 0.5) / 8 * width,
               top + height - row["pps"] / scale * height) for row in rows]
    draw.line(points, fill=color, width=5, joint="curve")
    for x, y in points:
        draw.ellipse((x - 6, y - 6, x + 6, y + 6), fill=color)
    legend_x = 800 if name.endswith("off") else 1050
    draw.line((legend_x, 74, legend_x + 38, 74), fill=color, width=5)
    draw.text((legend_x + 50, 62), name, font=font(18), fill="#273748")
im.save(IMAGE)
print(IMAGE)
