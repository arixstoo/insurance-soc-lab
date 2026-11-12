#!/usr/bin/env python3
"""How many custom alerts does normal activity alone produce? (false-positive budget)

1. Generate N simulated hours of BACKGROUND traffic (no attack scenarios) with the
   simulator's own generator (insurco_sim.timeline), same mix and office-hours profile
   as the lab, on a working day.
2. Replay it through the real Wazuh engine: the replay image (detection/replay/) moves
   the analysisd clock to each event's simulated time, so frequency/timeframe/ignore
   windows and <time> rules behave as they would over a real day, in a few minutes.
   Same manager configuration, decoders, CDB lists and rules as the lab.
3. Count alerts of our rules (100100-100199, level >= 3, i.e. alerts actually written)
   and rewrite the generated block of docs/tuning-report.md.

    python scripts/noise_report.py                    # 24 h, seed 7, writes the report
    python scripts/noise_report.py --no-write --json  # just print the counts
    python scripts/noise_report.py --budget 20        # exit 1 if 20 alerts or more

Needs Docker. The replayed day is the next Monday (a working day in Algeria) at 00:00:
the replay clock may only move forward, so the date is always in the future.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from collections import Counter, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "simulator" / "src"))
sys.path.insert(0, str(ROOT / "detection" / "tests"))

from gen_catalog import parse_rules, replace_generated  # noqa: E402
from run_tests import ENV, LISTS, PYTHON, build_replay_image, docker, start_manager  # noqa: E402

from insurco_sim.profile import Profile  # noqa: E402
from insurco_sim.timeline import background_timeline  # noqa: E402

REPORT = ROOT / "docs" / "tuning-report.md"
CONTAINER = "islab-noise"
CUSTOM = range(100100, 100200)


def next_monday(today: dt.date | None = None) -> dt.datetime:
    today = today or dt.date.today()
    days = (7 - today.weekday()) % 7 or 7  # strictly after today
    return dt.datetime.combine(today + dt.timedelta(days=days), dt.time())


def replay(events: list[tuple[dt.datetime, str, str]], keep: bool, lists: Path = LISTS) -> list[dict]:
    """Send every event to one logtest session on the replay engine; one result per event."""
    image = build_replay_image()
    start_manager(CONTAINER, image, ["-e", "TZ=UTC", "-e", "LD_PRELOAD=/usr/local/lib/clockshim.so"], lists=lists)
    try:
        # Simulated times are local wall-clock times; the container runs in UTC, so the
        # same wall-clock value is used as UTC: <time> rules see the simulated hour.
        payload = "".join(f"{t.replace(tzinfo=dt.timezone.utc).timestamp():.3f}\t{line}\n"
                          for t, _, line in events)
        proc = subprocess.run(["docker", "exec", "-i", "-e", "LD_PRELOAD=", CONTAINER, PYTHON, "/replay/driver.py"],
                              input=payload, capture_output=True, text=True, encoding="utf-8", env=ENV, check=False)
        results = [json.loads(row) for row in proc.stdout.splitlines() if row.startswith("{")]
        if proc.returncode != 0 or len(results) != len(events):
            raise RuntimeError(f"replay failed after {len(results)}/{len(events)} events:\n"
                               f"{proc.stdout[-500:]}\n{proc.stderr[-1000:]}")
        return results
    finally:
        if not keep:
            docker("rm", "-f", CONTAINER, check=False)


# Frequency rules: (rule, threshold, window s, events that feed it, how to read the entity).
# Fed by the engine's own per-event results, so allow-lists and decoders are accounted for.
HEADROOM = [
    ("100100", 6, 120, {"5760"}, lambda line: _match(r" from (\S+) port ", line)),
    ("100129", 5, 300, {"100120", "100121", "100122", "100123"}, lambda line: line.split(" ", 1)[0]),
    ("100132", 5, 300, {"100131", "100133"}, lambda line: json.loads(line)["db_user"]),
    ("100142", 8, 120, {"100141"}, lambda line: json.loads(line)["IpAddress"]),
]


def _match(pattern: str, line: str) -> str | None:
    found = re.search(pattern, line)
    return found.group(1) if found else None


def headroom(events: list[tuple[dt.datetime, str, str]], results: list[dict]) -> list[dict]:
    """Largest number of feeding events one entity reached in any window, per frequency rule."""
    rows = []
    for rule, threshold, window, feeders, entity_of in HEADROOM:
        windows: dict[str, deque] = {}
        best, who = 0, None
        for (t, _, line), res in zip(events, results, strict=True):
            if res["rule"] not in feeders:
                continue
            key = entity_of(line)
            times = windows.setdefault(key, deque())
            times.append(t)
            while (t - times[0]).total_seconds() > window:
                times.popleft()
            if len(times) > best:
                best, who = len(times), key
        rows.append({"rule": rule, "threshold": threshold, "window": window, "max": best, "entity": who})
    return rows


def summarize(events: list[tuple[dt.datetime, str, str]], results: list[dict]) -> dict:
    alerts = [(ev, res) for ev, res in zip(events, results, strict=True)
              if res["alert"] and res["rule"] and int(res["rule"]) in CUSTOM]
    per_rule = Counter(res["rule"] for _, res in alerts)
    per_hour = Counter(ev[0].hour for ev, _ in alerts)
    samples: dict[str, list[str]] = {}
    for (t, role, line), res in alerts:
        samples.setdefault(res["rule"], [])
        if len(samples[res["rule"]]) < 2:
            samples[res["rule"]].append(f"{t:%H:%M:%S} {role}: {line[:150]}")
    return {
        "events": len(events),
        "events_per_role": dict(Counter(role for _, role, _ in events)),
        "builtin_alerts": sum(1 for r in results if r["alert"] and r["rule"] and int(r["rule"]) not in CUSTOM),
        "custom_alerts": len(alerts),
        "per_rule": dict(sorted(per_rule.items())),
        "per_hour": {h: per_hour.get(h, 0) for h in range(24)},
        "samples": samples,
        "headroom": headroom(events, results),
    }


def render(stats: dict, *, start: dt.datetime, hours: float, seed: int, rate: float, budget: int) -> str:
    descriptions = {r.id: (r.level, r.description) for r in parse_rules()}
    verdict = "within" if stats["custom_alerts"] < budget else "OVER"
    lines = [
        f"Replay of **{hours:g} h** of background traffic (no attacks), "
        f"{start:%A} from 00:00, seed `{seed}`, peak rate {rate} ev/s, office-hours profile; "
        f"rules from `detection/rules/insurco_rules.xml` as committed.",
        "",
        f"- Events replayed: **{stats['events']}** "
        f"({', '.join(f'{k} {v}' for k, v in sorted(stats['events_per_role'].items()))})",
        f"- Alerts of built-in Wazuh rules (not counted): {stats['builtin_alerts']}",
        f"- **Custom alerts: {stats['custom_alerts']}** - budget < {budget}: **{verdict}**",
        "",
        "| Rule | Level | Detection | Alerts in 24 h |",
        "|---|---|---|---|",
    ]
    for rid, count in stats["per_rule"].items():
        level, text = descriptions.get(rid, ("?", "?"))
        lines.append(f"| {rid} | {level} | {text.replace('|', chr(92) + '|')} | {count} |")
    if not stats["per_rule"]:
        lines.append("| - | - | no custom alert | 0 |")
    busy = [f"{h:02d}h: {n}" for h, n in stats["per_hour"].items() if n]
    lines += ["", f"Custom alerts per hour: {', '.join(busy) or 'none'}."]
    lines += ["", "Headroom of the frequency rules: the most events one entity (IP or user) reached in any",
              "window of the rule, in this background, against the rule's threshold.", "",
              "| Rule | Threshold | Window | Max reached by one entity | Entity |", "|---|---|---|---|---|"]
    lines += [f"| {h['rule']} | {h['threshold']} | {h['window']} s | {h['max']} | {h['entity'] or '-'} |"
              for h in stats["headroom"]]
    if stats["samples"]:
        lines += ["", "Examples (first two per rule):", "", "```text"]
        lines += [f"{rid}  {s}" for rid, items in stats["samples"].items() for s in items]
        lines.append("```")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hours", type=float, default=24)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--rate", type=float, default=0.7, help="peak background rate (compose SIM_RATE default)")
    parser.add_argument("--budget", type=int, default=20, help="exit 1 if custom alerts >= budget")
    parser.add_argument("--no-write", action="store_true", help=f"do not rewrite {REPORT.name}")
    parser.add_argument("--json", action="store_true", help="print the raw counts as JSON")
    parser.add_argument("--keep", action="store_true", help="leave the replay container running")
    parser.add_argument("--lists", type=Path, default=LISTS,
                        help="CDB list folder to mount (to measure the effect of the allow-lists)")
    args = parser.parse_args(argv)

    start = next_monday()
    events = list(background_timeline(start, args.hours, seed=args.seed, rate=args.rate, profile=Profile()))
    print(f"[*] {len(events)} background events, {start:%a %Y-%m-%d} + {args.hours:g} h; replaying...", flush=True)
    stats = summarize(events, replay(events, args.keep, args.lists))
    print(f"[*] custom alerts: {stats['custom_alerts']}  per rule: {stats['per_rule']}")
    if args.json:
        print(json.dumps(stats, indent=1))
    if not args.no_write:
        text = REPORT.read_text(encoding="utf-8")
        body = render(stats, start=start, hours=args.hours, seed=args.seed, rate=args.rate, budget=args.budget)
        REPORT.write_text(replace_generated(text, {"noise": body}), encoding="utf-8", newline="\n")
        print(f"[*] wrote {REPORT.relative_to(ROOT)}")
    return 0 if stats["custom_alerts"] < args.budget else 1


if __name__ == "__main__":
    sys.exit(main())
