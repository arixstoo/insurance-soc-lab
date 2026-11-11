#!/usr/bin/env python3
"""Run the detection test cases against a real Wazuh manager.

For each case, the log lines are sent in order to one `wazuh-logtest` session
inside a throwaway `wazuh/wazuh-manager` container that has our rules mounted.
The rule fired by the last line is compared with the expected rule id.

Rules that use <time> depend on the manager clock, so the runner starts the
manager with a TZ that makes its local time 12:00 ("day") or 02:00 ("night").

Usage:
    python detection/tests/run_tests.py
    python detection/tests/run_tests.py --keep      # leave containers running
    python detection/tests/run_tests.py -k brute    # only cases whose name matches
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "detection" / "rules" / "insurco_rules.xml"
CASES = ROOT / "detection" / "tests" / "cases.yaml"
DEFAULT_IMAGE = f"wazuh/wazuh-manager:{os.environ.get('WAZUH_VERSION', '4.14.9')}"
LOGTEST = "/var/ossec/bin/wazuh-logtest"
SOCKET = "/var/ossec/queue/sockets/logtest"
CLOCK_HOURS = {"day": 12, "night": 2}

# Git Bash on Windows rewrites "/var/..." arguments into Windows paths.
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}


@dataclass
class Case:
    name: str
    lines: list[str]
    expect: str | None = None
    expect_not: str | None = None
    clock: str = "day"


def posix_tz_for_hour(target_hour: int, now: dt.datetime | None = None) -> str:
    """Return a POSIX TZ string whose local hour is `target_hour` right now.

    POSIX offsets are inverted: "LAB-3" means UTC+3. No tzdata is needed.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    offset = (target_hour - now.hour) % 24
    if offset > 14:  # keep the offset inside the valid -12..+14 range
        offset -= 24
    return f"LAB{-offset:+d}" if offset else "UTC"


def render(line: str) -> str:
    now = dt.datetime.now()
    return line.replace("{ts}", now.strftime("%b %d %H:%M:%S")).replace(
        "{apache_ts}", now.strftime("%d/%b/%Y:%H:%M:%S +0100")
    )


def docker(*args: str, stdin: str | None = None, check: bool = True) -> str:
    result = subprocess.run(
        ["docker", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=ENV,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed:\n{result.stderr}")
    return result.stdout + result.stderr


def start_manager(clock: str, image: str) -> str:
    name = f"islab-test-{clock}"
    docker("rm", "-f", name, check=False)
    tz = posix_tz_for_hour(CLOCK_HOURS[clock])
    docker(
        "run", "-d", "--name", name, "-e", f"TZ={tz}",
        "-v", f"{RULES}:/var/ossec/etc/rules/insurco_rules.xml:ro",
        image,
    )
    deadline = time.time() + 240
    while time.time() < deadline:
        if "ready" in docker("exec", name, "sh", "-c", f"test -S {SOCKET} && echo ready", check=False):
            errors = docker("exec", name, "sh", "-c",
                            "grep -iE 'insurco|rules.*(error|invalid)' /var/ossec/logs/ossec.log || true")
            if "ERROR" in errors or "CRITICAL" in errors:
                raise RuntimeError(f"Manager rejected the rules:\n{errors}")
            return name
        time.sleep(3)
    raise RuntimeError(f"{name}: rule engine did not start in time")


def last_rule_id(output: str) -> str | None:
    blocks = output.split("**Phase 1")
    match = re.search(r"Phase 3: Completed filtering \(rules\)\.\s+id: '(\d+)'", blocks[-1])
    return match.group(1) if match else None


def run_case(container: str, case: Case) -> tuple[bool, str]:
    payload = "\n".join(render(line) for line in case.lines) + "\n"
    fired = last_rule_id(docker("exec", "-i", container, LOGTEST, stdin=payload, check=False))
    if case.expect is not None and fired != case.expect:
        return False, f"expected {case.expect}, got {fired}"
    if case.expect_not is not None and fired == case.expect_not:
        return False, f"{case.expect_not} must not fire"
    return True, f"fired {fired}"


def load_cases(pattern: str | None) -> list[Case]:
    raw = yaml.safe_load(CASES.read_text(encoding="utf-8"))["cases"]
    cases = [Case(**item) for item in raw]
    if pattern:
        cases = [c for c in cases if re.search(pattern, c.name, re.IGNORECASE)]
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--keep", action="store_true", help="do not remove containers")
    parser.add_argument("-k", dest="pattern", help="regex filter on case names")
    args = parser.parse_args()

    cases = load_cases(args.pattern)
    containers: dict[str, str] = {}
    failures = 0
    try:
        for clock in sorted({c.clock for c in cases}):
            print(f"[*] starting manager ({clock} clock)...", flush=True)
            containers[clock] = start_manager(clock, args.image)
        for case in cases:
            ok, detail = run_case(containers[case.clock], case)
            failures += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {case.name}  ({detail})", flush=True)
    finally:
        if not args.keep:
            for name in containers.values():
                docker("rm", "-f", name, check=False)

    print(f"\n{len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
