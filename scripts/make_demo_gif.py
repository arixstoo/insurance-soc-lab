#!/usr/bin/env python3
"""Render the README demo GIF from a RECORDED run: terminal transcripts + dashboard screenshots.

    # 1. record a run on the lab (any shell), e.g.
    make up      > out/demo/up.txt 2>&1
    make status  > out/demo/status.txt 2>&1
    python scripts/screenshot_dashboards.py --from now-2h        # after injecting the scenarios
    # 2. render
    python scripts/make_demo_gif.py out/demo/up.txt out/demo/status.txt   # -> docs/img/demo.gif

Nothing is invented: the terminal frames replay the transcripts line by line (long runs of
identical compose lines are shortened), then the dashboard screenshots are shown. Pillow only.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
W, H = 960, 540
PAD = 18
BG, FG, DIM, GREEN, RED, PROMPT = "#0d1117", "#c9d1d9", "#8b949e", "#3fb950", "#f85149", "#58a6ff"
FONTS = ["consola.ttf", "C:/Windows/Fonts/consola.ttf", "DejaVuSansMono.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "Menlo.ttc"]


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for name in FONTS:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def clean(lines: list[str]) -> list[str]:
    """Drop shell timing lines and ANSI codes; keep the transcript otherwise as recorded."""
    out = []
    for line in lines:
        line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line.rstrip())
        if re.fullmatch(r"(real|user|sys)\s+\S+", line.strip()):
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return out


def colour(line: str) -> str:
    stripped = line.strip()
    if stripped in ("OK",) or stripped.endswith((" Healthy", " rejected", " active", " ok")):
        return GREEN
    if re.search(r"\b(FAIL|ERROR|NOT READY)\b", stripped) or stripped.endswith(" accepted"):
        return RED
    if stripped.startswith("=="):
        return PROMPT
    return FG


class Terminal:
    def __init__(self, title: str, size: int = 15):
        self.title = title
        self.font = font(size)
        self.line_h = size + 5
        self.rows = (H - 2 * PAD - 26) // self.line_h
        self.lines: list[tuple[str, str]] = []

    def frame(self, cursor: bool = False) -> Image.Image:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, 26], fill="#161b22")
        for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
            d.ellipse([12 + i * 18, 8, 22 + i * 18, 18], fill=c)
        d.text((W // 2, 13), self.title, fill=DIM, font=self.font, anchor="mm")
        y = 26 + PAD
        visible = self.lines[-self.rows:]
        for text, fill in visible:
            d.text((PAD, y), text[:110], fill=fill, font=self.font)
            y += self.line_h
        if cursor and visible:
            last = visible[-1][0][:110]
            x = PAD + int(d.textlength(last, font=self.font)) + 2
            d.rectangle([x, y - self.line_h + 2, x + 8, y - 4], fill=FG)
        return img

    def type_command(self, cmd: str, frames: list, durations: list) -> None:
        self.lines.append(("$ ", PROMPT))
        for i in [*range(0, len(cmd), 2), len(cmd)]:
            self.lines[-1] = ("$ " + cmd[:i], PROMPT)
            frames.append(self.frame(cursor=True))
            durations.append(45)
        frames.append(self.frame(cursor=True))
        durations.append(400)

    def print_lines(self, lines: list[str], frames: list, durations: list, per_frame: int = 2,
                    delay: int = 90) -> None:
        for i in range(0, len(lines), per_frame):
            for line in lines[i:i + per_frame]:
                self.lines.append((line, colour(line)))
            frames.append(self.frame())
            durations.append(delay)


def terminal_palette() -> Image.Image:
    """Fixed palette for the terminal frames: each theme colour blended into the background in
    16 steps (anti-aliased text). An adaptive palette drops rare colours such as the final OK."""
    def rgb(hex_colour: str) -> tuple[int, int, int]:
        return tuple(int(hex_colour[i:i + 2], 16) for i in (1, 3, 5))

    bg = rgb(BG)
    colours = []
    for c in (FG, DIM, GREEN, RED, PROMPT, "#161b22", "#ff5f56", "#ffbd2e", "#27c93f"):
        fg = rgb(c)
        colours += [tuple(round(b + (f - b) * k / 15) for b, f in zip(bg, fg, strict=True)) for k in range(16)]
    flat = [v for colour in colours[:256] for v in colour]
    pal = Image.new("P", (1, 1))
    pal.putpalette(flat + [0] * (768 - len(flat)))
    return pal


def shorten_compose(lines: list[str], keep: int = 3) -> list[str]:
    """Shorten runs of the same compose verb (Running / Waiting ...) to `keep` lines + a count,
    and a BuildKit log (`#n ...` lines) to one line that says how long it was."""
    out: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("#"):
            j = i
            while j < len(lines) and (lines[j].startswith("#") or not lines[j].strip()):
                j += 1
            out.append(f"   ... {j - i} lines of image build output")
            i = j
            continue
        m = re.match(r"\s*Container \S+\s+(\w+)$", lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        j = i
        while j < len(lines) and re.match(rf"\s*Container \S+\s+{m[1]}$", lines[j]):
            j += 1
        run = lines[i:j]
        out.extend(run if len(run) <= keep + 1 else run[:keep] + [f"   ... {len(run) - keep} more {m[1]}"])
        i = j
    return out


def screenshot_frames(path: Path, caption: str, tf: ImageFont.ImageFont) -> list[Image.Image]:
    """The dashboard at full width, shown from the top, then scrolled down once."""
    shot = Image.open(path).convert("RGB")
    scale = W / shot.width
    shot = shot.resize((W, int(shot.height * scale)), Image.LANCZOS)
    tops = [0] if shot.height <= H - 30 else [0, min(shot.height - (H - 30), (H - 30) // 2 * 2)]
    frames = []
    for top in tops:
        img = Image.new("RGB", (W, H), "#ffffff")
        img.paste(shot.crop((0, top, W, top + H - 30)), (0, 0))
        d = ImageDraw.Draw(img)
        d.rectangle([0, H - 30, W, H], fill=BG)
        d.text((W // 2, H - 15), caption, fill=FG, font=tf, anchor="mm")
        frames.append(img)
    return frames


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("up", type=Path, help="transcript of `make up`")
    parser.add_argument("status", type=Path, help="transcript of `make status` (scripts/lab_status.py)")
    parser.add_argument("--shots", type=Path, nargs="*",
                        default=[ROOT / "docs/img/soc-overview.png", ROOT / "docs/img/insurer-security.png"])
    parser.add_argument("--out", type=Path, default=ROOT / "docs/img/demo.gif")
    args = parser.parse_args(argv)

    frames: list[Image.Image] = []
    durations: list[int] = []
    term = Terminal("insurance-soc-lab")
    term.type_command("make up", frames, durations)
    up = shorten_compose(clean(args.up.read_text(encoding="utf-8", errors="replace").splitlines()))
    term.print_lines(up, frames, durations)
    durations[-1] = 1500

    term.lines.append(("", FG))
    term.type_command("make status", frames, durations)
    status = clean(args.status.read_text(encoding="utf-8", errors="replace").splitlines())
    term.print_lines(status, frames, durations, per_frame=3, delay=110)
    durations[-1] = 3000

    n_terminal = len(frames)
    tf = font(15)
    for shot in args.shots:
        name = shot.stem.replace("-", " ").title().replace("Soc", "SOC")
        for img in screenshot_frames(shot, f"https://localhost - InsurCo - {name}", tf):
            frames.append(img)
            durations.append(2600)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    pal = terminal_palette()
    frames = [f.quantize(palette=pal, dither=Image.Dither.NONE) if i < n_terminal
              else f.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
              for i, f in enumerate(frames)]
    frames[0].save(args.out, save_all=True, append_images=frames[1:], duration=durations, loop=0,
                   optimize=True, disposal=1)
    print(f"{args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}: "
          f"{len(frames)} frames, {sum(durations) / 1000:.1f} s, {args.out.stat().st_size // 1024} KiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
