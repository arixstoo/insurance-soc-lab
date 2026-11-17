#!/usr/bin/env python3
"""Render the GitHub social preview (1280x640) -> docs/img/social-preview.png.

    python scripts/make_social_preview.py

The figures are counted from the repository (rules XML, detection cases, Sigma rules, simulator
scenarios), never typed by hand; the dashboard is docs/img/soc-overview.png. Pillow only.
Upload it in the repository settings (Settings -> General -> Social preview).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml
from PIL import Image, ImageDraw, ImageFilter

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_demo_gif import font  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
W, H = 1280, 640
BG, FG, DIM, ACCENT, GREEN = "#0d1117", "#e6edf3", "#8b949e", "#58a6ff", "#3fb950"


def figures() -> dict[str, int]:
    rules = re.findall(r'<rule id="(\d+)"[^>]*level="(\d+)"', (ROOT / "detection/rules/insurco_rules.xml")
                       .read_text(encoding="utf-8"))
    cases = yaml.safe_load((ROOT / "detection/tests/cases.yaml").read_text(encoding="utf-8"))
    cases = cases["cases"] if isinstance(cases, dict) else cases
    scenarios = re.findall(r'^\s*Scenario\("(\w+)"',
                           (ROOT / "simulator/src/insurco_sim/scenarios.py").read_text(encoding="utf-8"), re.M)
    return {
        "rules": len(rules),
        "alerting": sum(int(level) >= 3 for _, level in rules),
        "cases": len(cases),
        "sigma": len(list((ROOT / "detection/sigma/rules").rglob("*.yml"))),
        "scenarios": len(scenarios),
    }


def wazuh_version() -> str:
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    m = re.search(r"^WAZUH_VERSION=(\S+)", env, re.M)
    return m[1] if m else "4.x"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shot", type=Path, default=ROOT / "docs/img/soc-overview.png")
    parser.add_argument("--out", type=Path, default=ROOT / "docs/img/social-preview.png")
    args = parser.parse_args(argv)
    f = figures()

    img = Image.new("RGB", (W, H), BG)
    # dashboard on the right, tilted out of the frame, darkened so the text stays readable
    shot = Image.open(args.shot).convert("RGB")
    shot = shot.resize((720, int(shot.height * 720 / shot.width)), Image.LANCZOS).crop((0, 0, 720, 520))
    shadow = Image.new("RGBA", (shot.width + 40, shot.height + 40), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle([20, 20, shot.width + 20, shot.height + 20], 14, fill=(0, 0, 0, 170))
    shadow = shadow.filter(ImageFilter.GaussianBlur(12))
    img.paste(shadow, (800, 80), shadow)
    img.paste(shot, (820, 100))
    # left edge of the screenshot fades into the background: mask 255 (all BG) at x=0 -> 0 at the right
    fade = Image.linear_gradient("L").rotate(-90, expand=True).resize((220, H))
    img.paste(Image.new("RGB", (220, H), BG), (800, 0), fade)

    d = ImageDraw.Draw(img)
    x = 64
    d.text((x, 70), "insurance-soc-lab", fill=FG, font=font(58))
    d.text((x, 150), "A one-command SOC lab for an insurer", fill=ACCENT, font=font(27))
    d.text((x, 195), f"Wazuh {wazuh_version()} · simulated + real hosts · Docker", fill=DIM, font=font(20))

    rows = [
        (f"{f['rules']}", f"custom Wazuh rules ({f['alerting']} alerting)"),
        (f"{f['cases']}", "detection cases on the real engine"),
        (f"{f['sigma']}", "Sigma rules, checked against the same cases"),
        (f"{f['scenarios']}", "attack scenarios, end-to-end tested in CI"),
    ]
    y = 270
    for value, label in rows:
        d.text((x, y), value, fill=GREEN, font=font(42))
        d.text((x + 90, y + 14), label, fill=FG, font=font(21))
        y += 66
    d.text((x, H - 70), "runbooks · webhook alerts · active response · threat intel · ATT&CK",
           fill=DIM, font=font(18))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    img.save(args.out, optimize=True)
    print(f"{args.out.name}: {W}x{H}, {args.out.stat().st_size // 1024} KiB, figures {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
