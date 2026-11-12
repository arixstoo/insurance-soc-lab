#!/usr/bin/env python3
"""Run the detection test cases against a real Wazuh manager.

For each case, the log lines are sent in order to one `wazuh-logtest` session
inside a throwaway `wazuh/wazuh-manager` container. The container gets the lab's
own manager configuration, decoders, CDB lists and rules, exactly as in compose.
The rule fired by the last line is compared with the expected rule id.

Rules that use <time> depend on the manager clock, so the runner starts the
manager with a TZ that makes its local time 12:00 ("day") or 02:00 ("night").

Cases with `at:` (seconds offsets, one per line) test time windows (timeframe,
frequency, ignore). They run on the replay image (detection/replay/), whose clock
is moved to each line's simulated time, so "11 minutes later" takes no real time.

Usage:
    python detection/tests/run_tests.py
    python detection/tests/run_tests.py --keep      # leave containers running
    python detection/tests/run_tests.py -k brute    # only cases whose name matches
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "detection" / "rules" / "insurco_rules.xml"
DECODERS = ROOT / "detection" / "decoders" / "0005-insurco_decoders.xml"
LISTS = ROOT / "detection" / "lists"
MANAGER_CONF = ROOT / "stack" / "config" / "wazuh_cluster" / "wazuh_manager.conf"
REPLAY_DIR = ROOT / "detection" / "replay"
CASES = ROOT / "detection" / "tests" / "cases.yaml"
WAZUH_VERSION = os.environ.get("WAZUH_VERSION", "4.14.9")
DEFAULT_IMAGE = f"wazuh/wazuh-manager:{WAZUH_VERSION}"
REPLAY_IMAGE = f"insurance-soc-lab/replay:{WAZUH_VERSION}"
LOGTEST = "/var/ossec/bin/wazuh-logtest"
SOCKET = "/var/ossec/queue/sockets/logtest"
PYTHON = "/var/ossec/framework/python/bin/python3"
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
    at: list[float] | None = None
    note: str = ""

    @property
    def timed(self) -> bool:
        return self.at is not None


# ----------------------------------------------------------------------------- coverage

def rule_ids(path: Path = RULES) -> list[str]:
    """Every rule id defined in the rules file, in file order."""
    return [rule.get("id") for rule in ET.parse(path).getroot().iter("rule")]


def load_raw_cases(path: Path = CASES) -> list[dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["cases"]


def coverage(ids: list[str], raw_cases: list[dict]) -> dict[str, dict[str, list[str]]]:
    """For each rule id, the names of its positive (`expect`) and negative (`expect_not`) cases."""
    result = {rid: {"positive": [], "negative": []} for rid in ids}
    for case in raw_cases:
        if case.get("expect") in result:
            result[case["expect"]]["positive"].append(case["name"])
        if case.get("expect_not") in result:
            result[case["expect_not"]]["negative"].append(case["name"])
    return result


# ----------------------------------------------------------------------------- engine

def posix_tz_for_hour(target_hour: int, now: dt.datetime | None = None) -> str:
    """Return a POSIX TZ string whose local hour is `target_hour` right now.

    POSIX offsets are inverted: "LAB-3" means UTC+3. No tzdata is needed.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    offset = (target_hour - now.hour) % 24
    if offset > 14:  # keep the offset inside the valid -12..+14 range
        offset -= 24
    return f"LAB{-offset:+d}" if offset else "UTC"


def render(line: str, when: dt.datetime | None = None) -> str:
    when = when or dt.datetime.now()
    return line.replace("{ts}", when.strftime("%b %d %H:%M:%S")).replace(
        "{apache_ts}", when.strftime("%d/%b/%Y:%H:%M:%S +0100")
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


def lab_mounts(lists: Path = LISTS) -> list[str]:
    """The same manager configuration, decoders, lists and rules as docker-compose.yml."""
    return [
        "-v", f"{MANAGER_CONF}:/wazuh-config-mount/etc/ossec.conf:ro",
        "-v", f"{lists}:/wazuh-config-mount/etc/lists/insurco:ro",
        "-v", f"{DECODERS}:/var/ossec/etc/decoders/{DECODERS.name}:ro",
        "-v", f"{RULES}:/var/ossec/etc/rules/insurco_rules.xml:ro",
    ]


def build_replay_image(image: str = REPLAY_IMAGE) -> str:
    docker("build", "-q", "--build-arg", f"WAZUH_VERSION={WAZUH_VERSION}", "-t", image, str(REPLAY_DIR))
    return image


def start_manager(name: str, image: str, env: list[str], lists: Path = LISTS) -> str:
    docker("rm", "-f", name, check=False)
    docker("run", "-d", "--name", name, *env, *lab_mounts(lists), image)
    deadline = time.time() + 240
    while time.time() < deadline:
        if "ready" in docker("exec", name, "sh", "-c", f"test -S {SOCKET} && echo ready", check=False):
            errors = docker("exec", name, "sh", "-c",
                            "grep -iE 'insurco|rules.*(error|invalid)|decoder.*error|lists?.*error' "
                            "/var/ossec/logs/ossec.log || true")
            if "ERROR" in errors or "CRITICAL" in errors:
                raise RuntimeError(f"{name}: manager rejected the configuration:\n{errors}")
            return name
        time.sleep(3)
    logs = docker("exec", name, "sh", "-c", "tail -20 /var/ossec/logs/ossec.log", check=False)
    raise RuntimeError(f"{name}: rule engine did not start in time\n{logs}")


def last_rule_id(output: str) -> str | None:
    blocks = output.split("**Phase 1")
    match = re.search(r"Phase 3: Completed filtering \(rules\)\.\s+id: '(\d+)'", blocks[-1])
    return match.group(1) if match else None


class TimedClock:
    """Simulated start times for timed cases: one day apart, so time only moves forward."""

    def __init__(self) -> None:
        tomorrow = dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=1)
        self.next_day = dt.datetime.combine(tomorrow, dt.time(), tzinfo=dt.timezone.utc)

    def start(self, clock: str) -> dt.datetime:
        start = self.next_day + dt.timedelta(hours=CLOCK_HOURS[clock])
        self.next_day += dt.timedelta(days=1)
        return start


def run_case(container: str, case: Case, timed_clock: TimedClock | None = None) -> tuple[bool, str]:
    if case.timed:
        assert timed_clock is not None
        start = timed_clock.start(case.clock)
        records = []
        for offset, line in zip(case.at, case.lines, strict=True):
            when = start + dt.timedelta(seconds=offset)
            records.append(f"{when.timestamp():.3f}\t{render(line, when.replace(tzinfo=None))}")
        out = docker("exec", "-i", "-e", "LD_PRELOAD=", container, PYTHON, "/replay/driver.py",
                     stdin="\n".join(records) + "\n", check=False)
        results = [json.loads(row) for row in out.splitlines() if row.startswith("{")]
        if len(results) != len(case.lines) or "error" in results[-1]:
            return False, f"replay failed: {out.strip()[-300:]}"
        fired = results[-1]["rule"]
    else:
        payload = "\n".join(render(line) for line in case.lines) + "\n"
        fired = last_rule_id(docker("exec", "-i", container, LOGTEST, stdin=payload, check=False))
    if case.expect is not None and fired != case.expect:
        return False, f"expected {case.expect}, got {fired}"
    if case.expect_not is not None and fired == case.expect_not:
        return False, f"{case.expect_not} must not fire"
    return True, f"fired {fired}"


def load_cases(pattern: str | None) -> list[Case]:
    cases = []
    for item in load_raw_cases():
        known = {k: item[k] for k in ("name", "lines", "expect", "expect_not", "clock", "at", "note") if k in item}
        cases.append(Case(**known))
    for case in cases:
        if case.timed and len(case.at) != len(case.lines):
            raise ValueError(f"{case.name}: `at` needs one offset per line")
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
        for clock in sorted({c.clock for c in cases if not c.timed}):
            print(f"[*] starting manager ({clock} clock)...", flush=True)
            tz = posix_tz_for_hour(CLOCK_HOURS[clock])
            containers[clock] = start_manager(f"islab-test-{clock}", args.image, ["-e", f"TZ={tz}"])
        timed_clock = None
        if any(c.timed for c in cases):
            print("[*] building and starting the replay manager (timed cases)...", flush=True)
            image = build_replay_image()
            containers["timed"] = start_manager(
                "islab-test-timed", image, ["-e", "TZ=UTC", "-e", "LD_PRELOAD=/usr/local/lib/clockshim.so"])
            timed_clock = TimedClock()
        for case in cases:
            container = containers["timed" if case.timed else case.clock]
            ok, detail = run_case(container, case, timed_clock)
            failures += not ok
            tag = " [timed]" if case.timed else ""
            print(f"  {'PASS' if ok else 'FAIL'}  {case.name}{tag}  ({detail})", flush=True)
    finally:
        if not args.keep:
            for name in containers.values():
                docker("rm", "-f", name, check=False)

    print(f"\n{len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
