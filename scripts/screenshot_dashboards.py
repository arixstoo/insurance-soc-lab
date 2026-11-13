#!/usr/bin/env python3
"""Screenshot the InsurCo dashboards with a headless browser (README images).

    pip install playwright && playwright install chromium     # once (or --channel msedge)
    python scripts/screenshot_dashboards.py                     # -> docs/img/*.png
    python scripts/screenshot_dashboards.py --from now-2h --channel msedge

Logs in through the security plugin's /auth/login endpoint with the admin password
from .env, opens each dashboard, waits until every panel reports
`data-render-complete`, and takes a full-page PNG. The browser talks to
https://localhost only; it skips certificate checks because the certificate is issued
to `wazuh.dashboard`, not `localhost` (the Python scripts verify it against the lab CA).
For a lab-local tool that is an accepted shortcut, not a pattern to copy.

Inject the scenarios first (`insurco-sim inject <name>` for each) so every panel has data.
"""

from __future__ import annotations

import argparse
import re
import sys

from indexer_client import ROOT, indexer_password, read_env

DASHBOARDS = {"soc-overview": "insurco-soc-overview", "insurer-security": "insurco-insurer-security"}
OUT = ROOT / "docs" / "img"
HIDE = ".euiGlobalToastList, .euiToast { display: none !important; }"


def lab_tz() -> str:
    tz = read_env().get("LAB_TZ", "Africa/Algiers")
    return tz if re.fullmatch(r"[A-Za-z]+(/[A-Za-z0-9_+-]+)+|UTC", tz) else "UTC"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="https://localhost")
    parser.add_argument("--from", dest="time_from", default="now-24h", help="time range start (default now-24h)")
    parser.add_argument("--channel", default=None, help="browser channel, e.g. msedge or chrome")
    parser.add_argument("--width", type=int, default=1680)
    parser.add_argument("--timeout", type=int, default=90, help="seconds per dashboard")
    args = parser.parse_args(argv)

    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeout
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright missing: pip install playwright && playwright install chromium", file=sys.stderr)
        return 2

    password = indexer_password()
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=args.channel)
        context = browser.new_context(ignore_https_errors=True, timezone_id=lab_tz(),
                                      viewport={"width": args.width, "height": 1000}, device_scale_factor=1)
        login = context.request.post(f"{args.url}/auth/login", headers={"osd-xsrf": "true"},
                                     data={"username": "admin", "password": password})
        if not login.ok:
            print(f"login failed: HTTP {login.status}", file=sys.stderr)
            return 1
        page = context.new_page()
        for name, dash_id in DASHBOARDS.items():
            url = (f"{args.url}/app/dashboards#/view/{dash_id}"
                   f"?_g=(refreshInterval:(pause:!t,value:0),time:(from:{args.time_from},to:now))")
            page.goto(url)
            page.wait_for_selector("[data-shared-items-count]", timeout=args.timeout * 1000)
            page.add_style_tag(content=HIDE)
            try:
                page.wait_for_function(
                    """() => {
                        const c = document.querySelector('[data-shared-items-count]');
                        const want = Number(c.getAttribute('data-shared-items-count'));
                        return document.querySelectorAll('[data-render-complete="true"]').length >= want;
                    }""",
                    timeout=args.timeout * 1000,
                )
            except PlaywrightTimeout:
                path = OUT / f"{name}.timeout.png"
                page.screenshot(path=str(path), full_page=True)
                print(f"{name}: panels not rendered after {args.timeout}s, see {path}", file=sys.stderr)
                return 1
            page.wait_for_load_state("networkidle")
            # The vislib heatmap reports render-complete before it draws: wait until the number
            # of chart shapes has not changed for 3 s (or the timeout).
            page.wait_for_function(
                """() => {
                    const n = document.querySelectorAll('svg rect, svg path, svg circle').length;
                    const now = Date.now();
                    if (window.__shapes !== n) { window.__shapes = n; window.__since = now; return false; }
                    return now - window.__since >= 3000;
                }""",
                polling=500,
                timeout=args.timeout * 1000,
            )
            empty = page.locator("text=No results found").count()
            path = OUT / f"{name}.png"
            page.screenshot(path=str(path), full_page=True)
            print(f"{name}: {path.relative_to(ROOT).as_posix()}" + (f"  ({empty} empty panel(s)!)" if empty else ""))
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
