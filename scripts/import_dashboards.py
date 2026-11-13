#!/usr/bin/env python3
"""Import the InsurCo dashboards (dashboards/*.ndjson) into the running lab (idempotent).

    python scripts/import_dashboards.py            # make up / lab.ps1 up run it after startup
    python scripts/import_dashboards.py --wait 300 # wait up to 5 min for the dashboard

Uses the Dashboards saved-objects API (`POST /api/saved_objects/_import?overwrite=true`)
as the indexer `admin` user, over TLS verified against the lab CA. Objects have fixed
ids, so a second run overwrites them in place instead of adding copies; edits made in
the UI are replaced by the version in git (rebuild the files with build_dashboards.py).

The "hour of day" scripted field is computed in the lab time zone: LAB_TZ (environment
or .env) replaces the default Africa/Algiers when it is an IANA zone name. A POSIX TZ
string (as the e2e workflow uses) cannot be read by Java, so the default is kept.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import uuid

from indexer_client import ROOT, dashboard_request, indexer_password, read_env

SOURCE = ROOT / "dashboards"
DEFAULT_TZ = "Africa/Algiers"
IANA = re.compile(r"[A-Za-z]+(/[A-Za-z0-9_+-]+)+|UTC")


def lab_tz() -> str:
    tz = os.environ.get("LAB_TZ") or read_env().get("LAB_TZ") or DEFAULT_TZ
    return tz if IANA.fullmatch(tz) else DEFAULT_TZ


def with_tz(ndjson: str, tz: str) -> str:
    return ndjson.replace(f"ZoneId.of('{DEFAULT_TZ}')", f"ZoneId.of('{tz}')")


def multipart(filename: str, content: str) -> tuple[bytes, str]:
    boundary = f"insurco-{uuid.uuid4().hex}"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/ndjson\r\n\r\n"
            f"{content}\r\n--{boundary}--\r\n")
    return body.encode("utf-8"), f"multipart/form-data; boundary={boundary}"


def wait_for_dashboard(password: str, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            status, body = dashboard_request("GET", "/api/status", "admin", password, timeout=10)
            state = body.get("status", {}).get("overall", {}).get("state") if isinstance(body, dict) else None
            if status == 200 and state == "green":
                return
            reason = f"HTTP {status}, state {state}"
        except OSError as exc:
            reason = str(exc)
        if time.monotonic() > deadline:
            raise SystemExit(f"dashboard not ready after {seconds}s ({reason})")
        time.sleep(5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wait", type=int, default=180, help="seconds to wait for the dashboard (default 180)")
    args = parser.parse_args(argv)

    files = sorted(SOURCE.glob("*.ndjson"))
    if not files:
        print(f"no .ndjson file in {SOURCE}", file=sys.stderr)
        return 1
    password = indexer_password()
    wait_for_dashboard(password, args.wait)
    tz = lab_tz()

    failed = 0
    for path in files:
        body, content_type = multipart(path.name, with_tz(path.read_text(encoding="utf-8"), tz))
        status, result = dashboard_request("POST", "/api/saved_objects/_import?overwrite=true", "admin",
                                           password, body, content_type=content_type)
        if status == 200 and isinstance(result, dict) and result.get("success"):
            print(f"{path.name}: {result.get('successCount', 0)} saved objects imported")
            continue
        failed += 1
        errors = result.get("errors", result) if isinstance(result, dict) else result
        print(f"{path.name}: import failed: HTTP {status} {errors}", file=sys.stderr)
    if not failed:
        print(f"hour-of-day field in {tz}; open https://localhost -> Dashboards -> InsurCo - ...")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
