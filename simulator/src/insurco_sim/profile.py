"""Activity profiles: how busy the insurer is at a given local time.

A profile maps a local datetime to a factor in [0, 1] that scales the peak
background rate. The runner uses it by *thinning*: it draws candidate events at
the peak rate and keeps each one with probability `factor(now)`. That gives a
non-homogeneous Poisson flow without long sleeps, so a change of hour (or a
SIGTERM) is picked up within one inter-event gap.

The default office profile follows a working day in Algeria:

- 08:00-18:00 is full activity, with a one-hour ramp on each side
  (07:00-08:00 up, 18:00-19:00 down);
- nights keep a small residue (backups, on-call staff, monitoring);
- Friday and Saturday are the weekend: the whole curve is scaled down (~20%).

Attack scenarios do NOT follow the profile: attackers do not keep office hours.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


@dataclass(frozen=True)
class Profile:
    """Office-hours curve. Hours are local, 0-24; days use datetime.weekday() (Mon=0)."""

    start: float = 8.0
    end: float = 18.0
    ramp: float = 1.0
    night: float = 0.1
    weekend: float = 0.2
    weekend_days: frozenset[int] = frozenset({4, 5})  # Friday, Saturday

    def __post_init__(self) -> None:
        if not 0 <= self.start < self.end <= 24:
            raise ValueError(f"office hours must satisfy 0 <= start < end <= 24 (got {self.start}-{self.end})")
        if self.ramp < 0:
            raise ValueError("ramp must be >= 0")
        for name in ("night", "weekend"):
            if not 0 <= getattr(self, name) <= 1:
                raise ValueError(f"{name} factor must be between 0 and 1")
        if not self.weekend_days <= set(range(7)):
            raise ValueError("weekend days must be weekday numbers 0-6")

    def daily(self, hour: float) -> float:
        """Factor for a fractional local hour on a working day."""
        if self.start <= hour < self.end:
            return 1.0
        if self.ramp and self.start - self.ramp <= hour < self.start:
            return self.night + (1 - self.night) * (hour - (self.start - self.ramp)) / self.ramp
        if self.ramp and self.end <= hour < self.end + self.ramp:
            return 1 - (1 - self.night) * (hour - self.end) / self.ramp
        return self.night

    def factor(self, now: datetime) -> float:
        hour = now.hour + now.minute / 60 + now.second / 3600
        value = self.daily(hour)
        return value * self.weekend if now.weekday() in self.weekend_days else value


class Flat:
    """Constant activity, the pre-3.1 behaviour (useful for load tests)."""

    def factor(self, now: datetime) -> float:  # same interface as Profile
        return 1.0

    def __repr__(self) -> str:
        return "Flat()"


def parse_hours(text: str) -> tuple[float, float]:
    """'08-18' or '8:30-17:45' -> (8.0, 18.0) / (8.5, 17.75)."""
    try:
        start, end = (part.strip() for part in text.split("-"))
        return _hour(start), _hour(end)
    except ValueError as exc:
        raise ValueError(f"office hours must look like 08-18 or 08:30-17:00 (got {text!r})") from exc


def _hour(text: str) -> float:
    hours, _, minutes = text.partition(":")
    return int(hours) + (int(minutes) if minutes else 0) / 60


def parse_days(text: str) -> frozenset[int]:
    """'fri,sat' -> {4, 5}; an empty string means no weekend."""
    days = set()
    for raw in filter(None, (part.strip().lower()[:3] for part in text.split(","))):
        if raw not in DAY_NAMES:
            raise ValueError(f"unknown day {raw!r} (use {','.join(DAY_NAMES)})")
        days.add(DAY_NAMES.index(raw))
    return frozenset(days)
