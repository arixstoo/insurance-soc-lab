#!/usr/bin/env python3
"""Apply the alert-retention ISM policy to the running indexer (idempotent).

    python scripts/apply_ism.py            # run after `docker compose up` (make up does it)
    python scripts/apply_ism.py --wait 300 # wait up to 5 min for the indexer

The policy lives in git (stack/config/wazuh_indexer/ism/alerts-retention.json):
wazuh-alerts-* indices are deleted 30 days after they are created. New indices
pick it up through its `ism_template`; indices that already exist are attached
here. Changing the JSON and re-running updates the policy; indices already
managed keep the version they started with (OpenSearch ISM behaviour).
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from indexer_client import ROOT, indexer_password, request

POLICY_ID = "insurco-alerts-retention"
POLICY_FILE = ROOT / "stack" / "config" / "wazuh_indexer" / "ism" / "alerts-retention.json"
INDEX_PATTERN = "wazuh-alerts-*"
ALREADY_MANAGED = "This index already has a policy"


def wait_for_indexer(password: str, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            status, _ = request("GET", "/_cluster/health", "admin", password, timeout=5)
            if status == 200:
                return
            reason = f"HTTP {status}"
        except OSError as exc:
            reason = str(exc)
        if time.monotonic() > deadline:
            raise SystemExit(f"indexer not ready after {seconds}s ({reason})")
        time.sleep(5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wait", type=int, default=180, help="seconds to wait for the indexer (default 180)")
    args = parser.parse_args()

    password = indexer_password()
    wait_for_indexer(password, args.wait)
    policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
    path = f"/_plugins/_ism/policies/{POLICY_ID}"

    status, current = request("GET", path, "admin", password)
    if status == 404:
        status, body = request("PUT", path, "admin", password, policy)
        action = "created"
    elif status == 200:
        query = f"?if_seq_no={current['_seq_no']}&if_primary_term={current['_primary_term']}"
        status, body = request("PUT", path + query, "admin", password, policy)
        action = "updated"
    else:
        print(f"cannot read policy {POLICY_ID}: HTTP {status} {current}", file=sys.stderr)
        return 1
    if status not in (200, 201):
        print(f"policy {POLICY_ID} not {action}: HTTP {status} {body}", file=sys.stderr)
        return 1
    print(f"ISM policy {POLICY_ID} {action}")

    status, body = request("POST", f"/_plugins/_ism/add/{INDEX_PATTERN}", "admin", password, {"policy_id": POLICY_ID})
    if status != 200:
        print(f"cannot attach policy to {INDEX_PATTERN}: HTTP {status} {body}", file=sys.stderr)
        return 1
    real_failures = [f for f in body.get("failed_indices", []) if ALREADY_MANAGED not in f.get("reason", "")]
    for failure in real_failures:
        print(f"  {failure.get('index_name')}: {failure.get('reason')}", file=sys.stderr)
    print(f"attached to {body.get('updated_indices', 0)} existing {INDEX_PATTERN} index(es); "
          "new indices are attached automatically")
    return 1 if real_failures else 0


if __name__ == "__main__":
    sys.exit(main())
