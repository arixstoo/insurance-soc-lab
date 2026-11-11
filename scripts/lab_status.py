#!/usr/bin/env python3
"""Health check of the running lab: containers, agents, and which custom rules fired.

    python scripts/lab_status.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter

MANAGER = os.environ.get("ISLAB_MANAGER", "islab-wazuh.manager-1")
EXPECTED_AGENTS = {"srv-linux-01", "srv-web-01", "srv-db-01", "ws-claims-01"}
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}


def sh(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", env=ENV, check=False)
    return result.stdout


def main() -> int:
    ok = True

    print("== containers ==")
    print(sh("docker", "compose", "ps", "--format", "table {{.Service}}\t{{.Status}}"))

    print("== agents ==")
    listing = sh("docker", "exec", MANAGER, "/var/ossec/bin/agent_control", "-l")
    active = {name for name in EXPECTED_AGENTS if f"Name: {name}," in listing and "Active" in
              next((line for line in listing.splitlines() if f"Name: {name}," in line), "")}
    for name in sorted(EXPECTED_AGENTS):
        state = "active" if name in active else "MISSING / not active"
        ok &= name in active
        print(f"  {name:14} {state}")

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
        ok = False
        print("  none yet - attacks start 2-5 minutes after boot (see SIM_ATTACK_MIN in .env)")
    for rule_id, n in sorted(counts.items()):
        print(f"  {rule_id}  {n:5}x  e.g. {example[rule_id]}")

    print("\nOK" if ok else "\nNOT READY (see above)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
