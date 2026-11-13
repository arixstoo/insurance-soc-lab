"""Builders for single log lines, one function per event type.

Every builder is a pure function of a random generator and a timestamp, so the
output is reproducible with a seed and easy to unit test.
"""

from __future__ import annotations

import json
import random
from datetime import datetime

from . import catalog as c


def _syslog_ts(now: datetime) -> str:
    return now.strftime("%b %d %H:%M:%S")


def _apache_ts(now: datetime) -> str:
    return now.strftime("%d/%b/%Y:%H:%M:%S +0100")


# --- Linux / SSH ---------------------------------------------------------------

def ssh_success(rng: random.Random, now: datetime, *, user: str | None = None, ip: str | None = None) -> str:
    user = user or rng.choice(c.EMPLOYEES + c.SERVICE_ACCOUNTS)
    ip = ip or rng.choice(c.INTERNAL_IPS)
    return (f"{_syslog_ts(now)} {c.HOSTS['linux'].name} sshd[{rng.randint(1000, 65000)}]: "
            f"Accepted password for {user} from {ip} port {rng.randint(40000, 60999)} ssh2")


def ssh_failure(rng: random.Random, now: datetime, *, user: str | None = None, ip: str | None = None) -> str:
    user = user or rng.choice(c.EMPLOYEES + c.INVALID_USERS)
    ip = ip or rng.choice(c.INTERNAL_IPS)
    return (f"{_syslog_ts(now)} {c.HOSTS['linux'].name} sshd[{rng.randint(1000, 65000)}]: "
            f"Failed password for {user} from {ip} port {rng.randint(40000, 60999)} ssh2")


def sudo(rng: random.Random, now: datetime, *, suspicious: bool = False, user: str | None = None) -> str:
    user = user or rng.choice(c.EMPLOYEES)
    command = rng.choice(c.SUSPICIOUS_SUDO if suspicious else c.ROUTINE_SUDO)
    return (f"{_syslog_ts(now)} {c.HOSTS['linux'].name} sudo:  {user} : TTY=pts/{rng.randint(0, 4)} ; "
            f"PWD=/home/{user} ; USER=root ; COMMAND={command}")


# --- Web (Apache combined log format) -------------------------------------------

def web_request(rng: random.Random, now: datetime) -> str:
    page = rng.choice(c.WEB_PAGES).format(id=rng.randint(10000, 99999), agency=rng.randint(1, 480))
    status = rng.choices([200, 304, 302, 404], weights=[80, 10, 7, 3])[0]
    return (f'{rng.choice(c.INTERNAL_IPS)} - - [{_apache_ts(now)}] "GET {page} HTTP/1.1" '
            f'{status} {rng.randint(300, 60000)} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')


def web_attack(rng: random.Random, now: datetime, *, kind: str | None = None, ip: str | None = None) -> str:
    kind = kind or rng.choice(list(c.WEB_ATTACKS))
    path = rng.choice(c.WEB_ATTACKS[kind])
    status = 404 if kind == "probe" else 403
    return (f'{ip or rng.choice(c.EXTERNAL_IPS)} - - [{_apache_ts(now)}] "GET {path} HTTP/1.1" '
            f'{status} 512 "-" "Mozilla/5.0"')


# --- Database audit (JSON lines) ------------------------------------------------

def db_query(rng: random.Random, now: datetime, *, bulk: bool = False, user: str | None = None,
             ip: str | None = None) -> str:
    user = user or rng.choice(c.EMPLOYEES)
    if bulk:
        table = rng.choice(c.SENSITIVE_TABLES)
        rows = rng.randint(200, 900)
        query = f"SELECT * FROM {table} LIMIT {rows}"
    else:
        table = rng.choice(c.SENSITIVE_TABLES + c.OTHER_TABLES)
        rows = 1
        query = f"SELECT id, name FROM {table} WHERE id = {rng.randint(1, 99999)}"
    return json.dumps({
        "log_type": "db_audit", "timestamp": now.isoformat(timespec="seconds"),
        "db_user": user, "table": table, "query": query, "rows_returned": rows,
        "duration_ms": rng.randint(2, 40) if not bulk else rng.randint(300, 2500),
        "source_ip": ip or rng.choice(c.INTERNAL_IPS),
    })


# --- Windows-style security events (JSON lines) ---------------------------------

def win_event(rng: random.Random, now: datetime, event_id: int, **fields: str) -> str:
    base = {
        "log_type": "winsec", "timestamp": now.isoformat(timespec="seconds"),
        "EventID": event_id, "WorkstationName": rng.choice(c.WORKSTATIONS),
    }
    defaults = {
        4624: {"TargetUserName": rng.choice(c.EMPLOYEES), "LogonType": 3, "IpAddress": rng.choice(c.INTERNAL_IPS)},
        4625: {"TargetUserName": rng.choice(c.EMPLOYEES), "IpAddress": rng.choice(c.INTERNAL_IPS)},
        4720: {"SubjectUserName": "it.admin", "TargetUserName": f"tmp_{rng.randint(100, 999)}"},
        4732: {"SubjectUserName": "it.admin", "MemberName": rng.choice(c.EMPLOYEES), "GroupName": rng.choice(c.GROUPS)},
    }
    return json.dumps({**base, **defaults.get(event_id, {}), **fields})
