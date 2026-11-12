#!/usr/bin/env python3
"""lab-traffic: scripted test traffic against the lab's REAL hosts (compose profile `real`).

Defensive test harness: it produces genuine sshd / nginx / pgaudit log lines so the
detection rules can be checked on real logs. It only talks to the three lab containers
below, and refuses to run if a name resolves outside the lab-real network (10.20.60.0/24,
an internal Docker network with no route out).

    lab-traffic list [--json]      jobs and the custom rules each one should raise
    lab-traffic ssh                failed then successful logins (sshpass), lab test accounts
    lab-traffic web                the `real: true` web requests of cases.yaml (curl)
    lab-traffic db                 normal queries, an allow-listed extract, a bulk export (psql)
    lab-traffic all                the three, in that order
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

LAB_NETWORK = ipaddress.ip_network("10.20.60.0/24")
HOSTS = {"ssh": "real-linux-01", "web": "real-web-01", "db": "real-db-01"}
SECRETS = Path(os.environ.get("LAB_SECRETS", "/run/lab-secrets"))
CASES = Path(os.environ.get("LAB_CASES", "/etc/lab-traffic/cases.yaml"))
USER_AGENT = "lab-traffic/1.0 (insurance-soc-lab test client)"
REQUEST = re.compile(r'"(?:GET|POST|HEAD) (\S+) HTTP/1\.[01]"')
SENSITIVE_TABLES = ["clients", "policies", "claims", "payments", "beneficiaries"]

# Custom rules each job must raise on the real host (day clock; see docs/real-services.md).
# "One event, one alert": the request / read that completes a correlation raises the
# correlation rule instead of its own, so every kind is sent more than once.
EXPECTED = {
    "ssh": ["100100", "100101"],
    "web": None,  # computed from the `real: true` cases of cases.yaml, plus 100129
    # 100137 = 100131's twin on the real audit trail; 100132 counts both
    "db": ["100137", "100132"],
}


def lab_host(job: str) -> str:
    """The job's target, only if it is a lab-real container."""
    name = HOSTS[job]
    address = ipaddress.ip_address(socket.gethostbyname(name))
    if address not in LAB_NETWORK:
        sys.exit(f"refusing to run: {name} resolves to {address}, outside the lab network {LAB_NETWORK}")
    return name


def secret(name: str) -> str:
    return (SECRETS / name).read_text(encoding="utf-8").strip()


def say(job: str, text: str) -> None:
    print(f"[{job}] {text}", flush=True)


# ----------------------------------------------------------------------------- ssh

def ssh_login(host: str, user: str, password: str) -> bool:
    """One password login with sshpass, running `true`. True if the login was accepted."""
    result = subprocess.run(
        ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
         "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10", f"{user}@{host}", "true"],
        env={**os.environ, "SSHPASS": password}, capture_output=True, text=True, check=False)
    return result.returncode == 0


def job_ssh() -> int:
    host = lab_host("ssh")
    password = secret("ssh-test")
    ok = ssh_login(host, "lab.ops", password)
    say("ssh", f"normal login lab.ops: {'accepted' if ok else 'REFUSED'}")
    failures = sum(not ssh_login(host, "lab.tester", f"wrong-password-{i}") for i in range(1, 7))
    say("ssh", f"6 wrong passwords for lab.tester: {failures} refused")
    success = ssh_login(host, "lab.tester", password)
    say("ssh", f"right password for lab.tester: {'accepted' if success else 'REFUSED'}")
    return 0 if ok and failures == 6 and success else 1


# ----------------------------------------------------------------------------- web

def real_web_cases(path: Path = CASES) -> tuple[list[str], list[str], list[str]]:
    """(benign paths, attack paths, rules the attacks expect) from the `real: true` cases."""
    benign: list[str] = []
    attacks: list[str] = []
    rules: list[str] = []
    for case in yaml.safe_load(path.read_text(encoding="utf-8"))["cases"]:
        if not case.get("real"):
            continue
        paths = [m.group(1) for line in case["lines"] if (m := REQUEST.search(line))]
        if not paths:
            continue
        if "expect" in case:
            attacks += [p for p in paths if p not in attacks]
            rules.append(case["expect"])
        else:
            benign += [p for p in paths if p not in benign]
    return benign, attacks, sorted(set(rules))


def web_expected() -> list[str]:
    _, attacks, rules = real_web_cases()
    # 5 or more attacks from one address in 5 minutes: campaign correlation
    return sorted(set(rules) | ({"100129"} if len(attacks) * 2 >= 5 else set()))


def http_get(host: str, path: str) -> str:
    """One GET sent exactly as written: no dot-segment squashing, no URL globbing."""
    result = subprocess.run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--path-as-is", "--globoff",
         "--max-time", "10", "-A", USER_AGENT, f"http://{host}{path}"],
        capture_output=True, text=True, check=False)
    return result.stdout.strip() or f"curl exit {result.returncode}"


def job_web() -> int:
    host = lab_host("web")
    benign, attacks, _ = real_web_cases()
    if not attacks:
        say("web", f"no `real: true` attack case in {CASES}")
        return 1
    for path in benign:
        say("web", f"{http_get(host, path)}  {path}")
    for round_ in (1, 2):  # every kind twice (one event, one alert)
        for path in attacks:
            say("web", f"{http_get(host, path)}  {path}  (malformed, round {round_})")
    return 0


# ----------------------------------------------------------------------------- db

def psql(host: str, role: str, password_file: str, sql: str, out: Path | None = None) -> int:
    """Run one statement as `role`; returns the number of rows written (or -1 on error)."""
    command = ["psql", "-X", "-q", "-A", "-t", "-F", ",", "-v", "ON_ERROR_STOP=1",
               f"host={host} dbname=insurco user={role} connect_timeout=10", "-c", sql]
    if out:
        command += ["-o", str(out)]
    result = subprocess.run(command, env={**os.environ, "PGPASSWORD": secret(password_file)},
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        return -1
    text = out.read_text(encoding="utf-8") if out else result.stdout
    return len([line for line in text.splitlines() if line])


def job_db() -> int:
    host = lab_host("db")
    ok = True
    # The claims portal: one record at a time (stays a level-0 audit event)
    for client_id in (12, 345, 678):
        n = psql(host, "portal_app", "db-portal", f"SELECT id, full_name, city FROM clients WHERE id = {client_id}")
        n2 = psql(host, "portal_app", "db-portal",
                  f"SELECT c.id, c.status FROM claims c JOIN policies p ON p.id = c.policy_id "
                  f"WHERE p.client_id = {client_id}")
        say("db", f"portal_app: client {client_id} -> {n} row, its claims -> {n2} rows")
        ok &= n >= 0 and n2 >= 0
    # ... and updates the status of one claim (a WRITE line, never a bulk read)
    n = psql(host, "portal_app", "db-portal", "UPDATE claims SET status = 'approved' WHERE id = 42")
    say("db", f"portal_app: claim 42 approved ({'ok' if n >= 0 else 'FAILED'})")
    ok &= n >= 0
    with tempfile.TemporaryDirectory(prefix="lab-export-") as tmp:
        # Scheduled BI extract by the allow-listed service account: must stay quiet
        for table in SENSITIVE_TABLES:
            n = psql(host, "svc_reporting", "db-reporting", f"SELECT * FROM {table}", Path(tmp, f"bi-{table}.csv"))
            say("db", f"svc_reporting extract {table}: {n} rows (allow-listed)")
            ok &= n >= 100
        # Bulk export by a person: 5 sensitive tables in a row
        for table in SENSITIVE_TABLES:
            n = psql(host, "lab_analyst", "db-analyst", f"SELECT * FROM {table}", Path(tmp, f"{table}.csv"))
            say("db", f"lab_analyst export {table}: {n} rows")
            ok &= n >= 100
    return 0 if ok else 1


# ----------------------------------------------------------------------------- cli

JOBS = {"ssh": job_ssh, "web": job_web, "db": job_db}


def listing() -> list[dict]:
    return [{"name": job, "host": HOSTS[job], "expected_rules": EXPECTED[job] or web_expected()} for job in JOBS]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lab-traffic", description=__doc__.splitlines()[0])
    parser.add_argument("job", choices=[*JOBS, "all", "list"])
    parser.add_argument("--json", action="store_true", help="list: machine-readable output")
    args = parser.parse_args(argv)
    if args.job == "list":
        jobs = listing()
        if args.json:
            print(json.dumps(jobs))
        else:
            for job in jobs:
                print(f"{job['name']:4} -> {job['host']:14} expects {', '.join(job['expected_rules'])}")
        return 0
    rc = 0
    for job in (JOBS if args.job == "all" else [args.job]):
        rc |= JOBS[job]()
    return rc


if __name__ == "__main__":
    sys.exit(main())
