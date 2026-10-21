"""Render a bottleneck OFF/ON availability comparison as a PNG for the report.

Usage: python3 experiments/render_availability_png.py results/<off> results/<on> [--output PNG]

Three bar pairs, all taken from analyze.compare: client probe loss during the
attack, client RTT p95, and the mean backlog of the s1-eth1 bottleneck queue.
Pillow is optional: the data preparation works without it, and rendering
fails with a clear message when it is missing.
"""

import argparse
import sys
from pathlib import Path

EXPERIMENTS = str(Path(__file__).resolve().parent)
if EXPERIMENTS not in sys.path:
    sys.path.insert(0, EXPERIMENTS)
from analyze import compare  # noqa: E402

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # Pillow is only needed for the image itself.
    Image = ImageDraw = ImageFont = None


ROOT = Path(__file__).resolve().parents[1]
OFF_COLOR = "#2459A6"
ON_COLOR = "#D4552D"


def availability_panels(comparison):
    """Return [(title, unit, off value, on value)] from an analyze.compare result."""
    table = comparison["availability"]
    off_qdisc = comparison["attack_off"].get("qdisc") or {}
    on_qdisc = comparison["attack_on"].get("qdisc") or {}
    return [
        ("Client probe loss", "%", table["off_client_loss_percent"], table["on_client_loss_percent"]),
        ("Client RTT p95", "ms", table["off_rtt_p95_ms"], table["on_rtt_p95_ms"]),
        ("Mean queue backlog", "bytes", off_qdisc.get("mean_backlog_bytes"), on_qdisc.get("mean_backlog_bytes")),
    ]


def font(size, bold=False):
    windows_font = Path(r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf")
    linux_font = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else
                      "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    for candidate in (windows_font, linux_font):
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def label(value, unit):
    if value is None:
        return "n/a"
    return f"{value:.1f}{unit}" if unit == "%" else f"{value:.1f} {unit}" if unit == "ms" else f"{value:.0f}"


def render(comparison, image_path):
    if Image is None:
        raise RuntimeError("Pillow is not installed; run: python3 -m pip install pillow")
    table = comparison["availability"]
    bottleneck = comparison["attack_on"].get("bottleneck") or {}
    im = Image.new("RGB", (1400, 800), "white")
    draw = ImageDraw.Draw(im)
    draw.text((70, 30), "Client availability with mitigation off and on", font=font(28, True), fill="#1B2739")
    subtitle = (f"Victim link shaped to {bottleneck['mbit']:g} Mbit/s, {bottleneck['queue_packets']}-packet "
                f"{bottleneck.get('qdisc', 'fifo')} queue" if bottleneck else "No bottleneck configured")
    verdict = ("availability improvement measured" if table["improved"]
               else "no availability improvement measured")
    draw.text((70, 68), f"{subtitle}; loss reduction {table['loss_reduction_points']:.1f} points: {verdict}",
              font=font(18), fill="#4D5C6B")
    panels = availability_panels(comparison)
    panel_width, top, height = 400, 170, 470
    for index, (title, unit, off_value, on_value) in enumerate(panels):
        left = 70 + index * (panel_width + 50)
        draw.text((left, top - 50), f"{title} ({unit})", font=font(20, True), fill="#273748")
        draw.line((left, top + height, left + panel_width, top + height), fill="#273748", width=3)
        values = [value for value in (off_value, on_value) if value is not None]
        scale = max(values) * 1.15 if values and max(values) > 0 else 1
        for slot, (name, color, value) in enumerate((("OFF", OFF_COLOR, off_value), ("ON", ON_COLOR, on_value))):
            x0 = left + 50 + slot * 170
            if value is not None:
                y0 = top + height - value / scale * height
                draw.rectangle((x0, y0, x0 + 120, top + height), fill=color)
                draw.text((x0, y0 - 28), label(value, unit), font=font(18), fill="#273748")
            else:
                draw.text((x0 + 30, top + height - 30), "n/a", font=font(18), fill="#8C98A8")
            draw.text((x0 + 40, top + height + 14), name, font=font(18), fill="#36485D")
    im.save(image_path)
    return image_path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("off", type=Path, help="attack-off trial folder")
    parser.add_argument("on", type=Path, help="attack-on trial folder")
    parser.add_argument("--output", type=Path, default=None,
                        help="PNG path (default: <on folder>/../availability-comparison.png)")
    args = parser.parse_args()
    image = args.output or args.on.resolve().parent / "availability-comparison.png"
    try:
        print(render(compare(args.off, args.on), image))
    except (RuntimeError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
