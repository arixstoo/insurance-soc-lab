"""Background activity and attack scenarios.

A scenario is a list of `(host_role, line)` pairs. The runner decides when and
where to write them, which keeps scenarios pure and testable.

Each scenario names the detection rules it is meant to trigger, so the docs,
the tests and the dashboards all speak about the same thing.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from . import catalog as c
from . import events as e

Event = tuple[str, str]  # (host role, log line)


@dataclass(frozen=True)
class Scenario:
    name: str
    summary: str
    expected_rules: tuple[str, ...]
    build: Callable[[random.Random, datetime], list[Event]]


def background_event(rng: random.Random, now: datetime) -> Event:
    """One event of normal daily activity (weighted mix)."""
    builders: list[tuple[int, Callable[[], Event]]] = [
        (30, lambda: ("web", e.web_request(rng, now))),
        (20, lambda: ("db", e.db_query(rng, now))),
        (15, lambda: ("linux", e.ssh_success(rng, now))),
        (15, lambda: ("workstation", e.win_event(rng, now, 4624))),
        (6, lambda: ("linux", e.ssh_failure(rng, now))),  # people mistype passwords
        (6, lambda: ("workstation", e.win_event(rng, now, 4625))),
        (8, lambda: ("linux", e.sudo(rng, now))),
    ]
    weights = [w for w, _ in builders]
    return rng.choices([b for _, b in builders], weights=weights)[0]()


def _brute_force(rng: random.Random, now: datetime) -> list[Event]:
    ip = rng.choice(c.EXTERNAL_IPS)
    events = [("linux", e.ssh_failure(rng, now, user=rng.choice(c.INVALID_USERS + ["svc_backup"]), ip=ip))
              for _ in range(rng.randint(8, 14))]
    events.append(("linux", e.ssh_success(rng, now, user="svc_backup", ip=ip)))
    return events


def _insider(rng: random.Random, now: datetime) -> list[Event]:
    user = rng.choice(c.EMPLOYEES)
    return [("db", e.db_query(rng, now, bulk=True, user=user)) for _ in range(rng.randint(6, 10))]


def _web_campaign(rng: random.Random, now: datetime) -> list[Event]:
    ip = rng.choice(c.EXTERNAL_IPS)
    # Every kind twice: the event that completes the correlation (100129) raises 100129
    # *instead of* its own rule, so a kind sent once could vanish from the alerts.
    kinds = [kind for kind in c.WEB_ATTACKS for _ in range(2)]
    rng.shuffle(kinds)
    return [("web", e.web_attack(rng, now, kind=k, ip=ip)) for k in kinds]


def _privesc(rng: random.Random, now: datetime) -> list[Event]:
    user = rng.choice(c.EMPLOYEES)
    return [("linux", e.sudo(rng, now, suspicious=True, user=user)) for _ in range(3)]


def _rogue_admin(rng: random.Random, now: datetime) -> list[Event]:
    account = f"tmp_{rng.randint(100, 999)}"
    return [
        ("workstation", e.win_event(rng, now, 4720, TargetUserName=account)),
        ("workstation", e.win_event(rng, now, 4732, MemberName=account, GroupName="Administrators")),
    ]


def _password_spray(rng: random.Random, now: datetime) -> list[Event]:
    ip = rng.choice(c.INTERNAL_IPS)
    return [("workstation", e.win_event(rng, now, 4625, TargetUserName=user, IpAddress=ip))
            for user in rng.sample(c.EMPLOYEES, 10)]


SCENARIOS: dict[str, Scenario] = {s.name: s for s in [
    Scenario("brute_force", "SSH password guessing from one external IP, then a successful login",
             ("100100", "100101"), _brute_force),
    Scenario("insider", "One employee bulk-reads sensitive customer tables",
             ("100131", "100132"), _insider),
    Scenario("web_campaign", "One IP probes the web app with SQLi, XSS, traversal and secret-file requests",
             ("100120", "100121", "100122", "100123", "100129"), _web_campaign),
    Scenario("privesc", "An employee uses sudo to get a root shell and touch credential files",
             ("100110",), _privesc),
    Scenario("rogue_admin", "A new account is created and added to Administrators",
             ("100143", "100144"), _rogue_admin),
    Scenario("password_spray", "Many accounts fail to log on from one workstation IP",
             ("100141", "100142"), _password_spray),
]}
