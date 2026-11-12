"""Event counts per host per minute, read back from the log files on disk.

The timestamp of each line is parsed in the format of its host (syslog, Apache
combined, JSON `timestamp`), so the counts reflect when events were written,
not when the command runs. All times are naive local time, like the simulator.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path

from . import catalog as c

_APACHE = re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})")


def line_time(fmt: str, line: str, year: int) -> datetime | None:
    """Timestamp of one log line, or None if it cannot be parsed."""
    try:
        if fmt == "syslog":  # "Nov 12 14:30:00 host ..." has no year
            return datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S")
        if fmt == "apache":
            match = _APACHE.search(line)
            return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S") if match else None
        return datetime.fromisoformat(json.loads(line)["timestamp"]).replace(tzinfo=None)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


FORMATS = {"linux": "syslog", "web": "apache", "db": "json", "workstation": "json"}


def _tail_lines(path: Path, max_bytes: int) -> Iterable[str]:
    """Last `max_bytes` of a file as lines (the first, partial line is dropped)."""
    with path.open("rb") as handle:
        size = handle.seek(0, 2)
        handle.seek(max(0, size - max_bytes))
        data = handle.read().decode("utf-8", errors="replace")
    lines = data.splitlines()
    return lines[1:] if size > max_bytes else lines


def count_per_minute(out_dir: Path, now: datetime, minutes: int,
                     max_bytes: int = 32 * 1024 * 1024) -> dict[str, Counter[datetime]]:
    """{host name: Counter(minute -> events)} for the `minutes` full minutes before `now`."""
    end = now.replace(second=0, microsecond=0)
    start = end - timedelta(minutes=minutes)
    result: dict[str, Counter[datetime]] = {}
    for role, host in c.HOSTS.items():
        counts: Counter[datetime] = Counter()
        path = out_dir / host.name / host.log_file
        if path.exists():
            for line in _tail_lines(path, max_bytes):
                ts = line_time(FORMATS[role], line, now.year)
                if ts and start <= ts < end:
                    counts[ts.replace(second=0)] += 1
        result[host.name] = counts
    return result


def render(counts: dict[str, Counter[datetime]], now: datetime, minutes: int) -> str:
    """Table: one row per minute, one column per host, then totals and events/second."""
    end = now.replace(second=0, microsecond=0)
    slots = [end - timedelta(minutes=minutes - i) for i in range(minutes)]
    hosts = list(counts)
    width = max(len(h) for h in hosts)
    rows = ["minute  " + "  ".join(f"{h:>{width}}" for h in hosts) + "  " + f"{'total':>{width}}"]
    for slot in slots:
        values = [counts[h][slot] for h in hosts]
        rows.append(f"{slot:%H:%M}   " + "  ".join(f"{v:>{width}}" for v in values)
                    + "  " + f"{sum(values):>{width}}")
    totals = [sum(counts[h].values()) for h in hosts]
    seconds = minutes * 60
    rows.append("total   " + "  ".join(f"{v:>{width}}" for v in totals) + "  " + f"{sum(totals):>{width}}")
    rows.append("ev/s    " + "  ".join(f"{v / seconds:>{width}.3f}" for v in totals)
                + "  " + f"{sum(totals) / seconds:>{width}.3f}")
    return "\n".join(rows)
