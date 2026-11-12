#!/usr/bin/env python3
"""End-to-end delay of the running lab: log line written -> alert searchable in the indexer.

    python scripts/measure_latency.py              # 5 samples
    python scripts/measure_latency.py --count 20 --interval 1

Each sample writes one SSH login line for a unique user name (`latency-<hex>`)
into srv-linux-01's auth.log, through `insurco-sim marker` inside the simulator
container. The line raises the built-in alert 5715 (internal source: no after-hours
custom rule, even at night). The script then polls `wazuh-alerts-*` until the alert is found.

Reported per sample:
  manager   line written -> alert produced by analysisd (alert `timestamp`;
            both clocks are containers on the same Docker host)
  indexed   marker command started -> alert visible in a search (host clock only;
            includes ~0.2-0.5 s of `docker compose exec` overhead, so it is an
            upper bound)
"""

from __future__ import annotations

import argparse
import os
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime

from indexer_client import ROOT, indexer_password, request

ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}
INDEX = "wazuh-alerts-*"


def write_marker(tag: str) -> float:
    """Write the marker line; return the container's epoch time of the write."""
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "simulator", "insurco-sim", "marker", tag],
        capture_output=True, text=True, encoding="utf-8", env=ENV, cwd=ROOT, check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"insurco-sim marker failed: {result.stderr.strip() or result.stdout.strip()}")
    return float(result.stdout.strip().splitlines()[-1])


def find_alert(tag: str, password: str) -> dict | None:
    query = {
        "size": 1,
        "query": {"bool": {"should": [
            {"term": {"data.dstuser": tag}},
            {"match_phrase": {"full_log": tag}},
        ], "minimum_should_match": 1}},
    }
    status, body = request("POST", f"/{INDEX}/_search", "admin", password, query, timeout=5)
    if status != 200:
        raise SystemExit(f"search failed: HTTP {status} {body}")
    hits = body["hits"]["hits"]
    return hits[0]["_source"] if hits else None


def alert_epoch(source: dict) -> float:
    """Alert `timestamp` (e.g. 2026-11-12T17:11:16.123+0100) as epoch seconds."""
    return datetime.strptime(source["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def sample(password: str, timeout: float, poll: float) -> tuple[float, float, str]:
    tag = f"latency-{uuid.uuid4().hex[:12]}"
    started = time.time()
    written = write_marker(tag)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        source = find_alert(tag, password)
        if source:
            return alert_epoch(source) - written, time.time() - started, source["rule"]["id"]
        time.sleep(poll)
    raise SystemExit(f"marker {tag} not indexed after {timeout:.0f}s (is the lab running? make status)")


def summary(name: str, values: list[float]) -> str:
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))]
    return (f"{name:8} min {ordered[0]:6.2f}  median {statistics.median(ordered):6.2f}  "
            f"p95 {p95:6.2f}  max {ordered[-1]:6.2f}  (seconds)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=5, help="number of samples (default 5)")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between samples (default 2)")
    parser.add_argument("--timeout", type=float, default=120.0, help="give up on a sample after N s (default 120)")
    parser.add_argument("--poll", type=float, default=0.25, help="search interval in seconds (default 0.25)")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be >= 1")

    password = indexer_password()
    manager, indexed = [], []
    print(f"{'#':>3}  {'rule':6}  {'manager':>8}  {'indexed':>8}")
    for i in range(1, args.count + 1):
        to_alert, to_index, rule = sample(password, args.timeout, args.poll)
        manager.append(to_alert)
        indexed.append(to_index)
        print(f"{i:>3}  {rule:6}  {to_alert:8.2f}  {to_index:8.2f}")
        if i < args.count:
            time.sleep(args.interval)
    print()
    print(summary("manager", manager))
    print(summary("indexed", indexed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
