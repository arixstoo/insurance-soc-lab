#!/usr/bin/env python3
"""Health check of the running lab: containers, agents, credentials, retention, custom rules fired.

    python scripts/lab_status.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter

from indexer_client import indexer_password, request

MANAGER = os.environ.get("ISLAB_MANAGER", "islab-wazuh.manager-1")
EXPECTED_AGENTS = {"srv-linux-01", "srv-web-01", "srv-db-01", "ws-claims-01"}
# Compose profile `real` (docs/real-services.md): expected too when its containers run
REAL_AGENTS = {"real-linux-01", "real-web-01", "real-db-01"}
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}
ISM_POLICY = "insurco-alerts-retention"
# Public wazuh-docker lab defaults (also in .env.example): none of them may still work.
DEFAULT_INDEXER_LOGINS = {
    "admin": "SecretPassword",
    "kibanaserver": "kibanaserver",
    # upstream demo users, dropped from the generated internal_users.yml
    "kibanaro": "kibanaro",
    "logstash": "logstash",
    "readall": "readall",
    "snapshotrestore": "snapshotrestore",
}
DEFAULT_API_LOGIN = ("wazuh-wui", "MyS3cr37P450r.*-")


def sh(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", env=ENV, check=False)
    return result.stdout


def real_profile_running() -> bool:
    return bool(sh("docker", "compose", "--profile", "real", "ps", "-q", "--status", "running",
                   *sorted(REAL_AGENTS)).strip())


def check_agents() -> bool:
    print("== agents ==")
    listing = sh("docker", "exec", MANAGER, "/var/ossec/bin/agent_control", "-l")
    ok = True
    expected = EXPECTED_AGENTS | (REAL_AGENTS if real_profile_running() else set())
    for name in sorted(expected):
        line = next((line for line in listing.splitlines() if f"Name: {name}," in line), "")
        active = "Active" in line
        ok &= active
        print(f"  {name:14} {'active' if active else 'MISSING / not active'}")
    return ok


def check_credentials() -> bool:
    print("\n== default passwords (must all be rejected) ==")
    ok = True
    for user, password in DEFAULT_INDEXER_LOGINS.items():
        try:
            status, _ = request("GET", "/", user, password, timeout=5)
        except OSError as exc:
            print(f"  indexer {user:15} cannot check ({exc})")
            ok = False
            continue
        rejected = status == 401
        ok &= rejected
        print(f"  indexer {user:15} {'rejected' if rejected else f'STILL ACCEPTED (HTTP {status})'}")
    user, password = DEFAULT_API_LOGIN
    code = sh("docker", "exec", MANAGER, "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
              "-u", f"{user}:{password}", "https://localhost:55000/security/user/authenticate").strip()
    rejected = code == "401"
    ok &= rejected
    verdict = "rejected" if rejected else f"STILL ACCEPTED or unreachable (HTTP {code or '-'})"
    print(f"  api     {user:15} {verdict}")
    if not ok:
        print("  -> run scripts/rotate-passwords.sh (see SECURITY.md)")
    return ok


def check_retention() -> bool:
    print("\n== alert retention (ISM) ==")
    try:
        status, _ = request("GET", f"/_plugins/_ism/policies/{ISM_POLICY}", "admin", indexer_password(), timeout=5)
    except (OSError, SystemExit) as exc:
        print(f"  cannot check ({exc})")
        return False
    if status == 200:
        print(f"  {ISM_POLICY} present")
        return True
    print(f"  {ISM_POLICY} MISSING (HTTP {status}) -> python scripts/apply_ism.py")
    return False


def check_rules() -> bool:
    print("\n== custom rules fired (alerts.json) ==")
    raw = sh("docker", "exec", MANAGER, "sh", "-c", "grep '\"id\":\"1001' /var/ossec/logs/alerts/alerts.json || true")
    counts: Counter[str] = Counter()
    example: dict[str, str] = {}
    for line in raw.splitlines():
        try:
            rule = json.loads(line)["rule"]
        except (json.JSONDecodeError, KeyError):
            continue
        counts[rule["id"]] += 1
        example.setdefault(rule["id"], rule["description"][:80])
    if not counts:
        print("  none yet - attacks start 2-5 minutes after boot (see SIM_ATTACK_MIN in .env)")
        return False
    for rule_id, n in sorted(counts.items()):
        print(f"  {rule_id}  {n:5}x  e.g. {example[rule_id]}")
    return True


def main() -> int:
    print("== containers ==")
    print(sh("docker", "compose", "--profile", "real", "ps", "--format", "table {{.Service}}\t{{.Status}}"))
    results = [check_agents(), check_credentials(), check_retention(), check_rules()]
    ok = all(results)
    print("\nOK" if ok else "\nNOT READY (see above)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
