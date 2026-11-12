"""Background traffic as a timestamped stream, without sleeping.

Same process as `insurco-sim run` (Poisson candidates at the peak rate, thinned by the
activity profile, `background_event` mix) but the clock is simulated: a day of traffic
is produced in about a second. Used by scripts/noise_report.py to replay 24 h of
background activity through the real rule engine. No attack scenarios.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from datetime import datetime, timedelta

from .profile import Flat, Profile
from .scenarios import background_event


def background_timeline(start: datetime, hours: float, *, seed: int | None = None, rate: float = 0.7,
                        profile: Profile | Flat | None = None) -> Iterator[tuple[datetime, str, str]]:
    """Yield (local time, host role, log line) in time order, for `hours` from `start`."""
    if rate <= 0:
        raise ValueError("rate must be > 0")
    rng = random.Random(seed)
    profile = profile or Profile()
    end = start + timedelta(hours=hours)
    now = start
    while now < end:
        if rng.random() < profile.factor(now):
            role, line = background_event(rng, now)
            yield now, role, line
        now += timedelta(seconds=rng.expovariate(rate))
