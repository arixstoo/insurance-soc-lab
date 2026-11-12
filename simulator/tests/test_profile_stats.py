"""Office-hours profile (with a fake clock), `stats` and the small CLI helpers."""

import json
import random
import re
from datetime import datetime, timedelta

import pytest

from insurco_sim import events as e
from insurco_sim import stats
from insurco_sim.cli import Clock, main, run
from insurco_sim.profile import Flat, Profile, parse_days, parse_hours

# 2026-11-12 is a Thursday (working day); 2026-11-13 a Friday (weekend in Algeria).
THU = datetime(2026, 11, 12)
FRI = datetime(2026, 11, 13)
SAT = datetime(2026, 11, 14)
SUN = datetime(2026, 11, 15)


class FakeClock(Clock):
    """Time only moves when the code under test sleeps."""

    def __init__(self, start: datetime) -> None:
        self.start = start
        self.elapsed = 0.0
        super().__init__(now=lambda: self.start + timedelta(seconds=self.elapsed),
                         monotonic=lambda: self.elapsed, sleep=self._sleep)

    def _sleep(self, seconds: float) -> None:
        self.elapsed += seconds


@pytest.mark.parametrize(("when", "expected"), [
    (THU.replace(hour=10), 1.0),
    (THU.replace(hour=8), 1.0),            # start is inclusive
    (THU.replace(hour=17, minute=59), 1.0),
    (THU.replace(hour=18), 1.0),           # the ramp down starts at full activity
    (THU.replace(hour=3), 0.1),
    (THU.replace(hour=23), 0.1),
    (THU.replace(hour=7, minute=30), 0.55),   # halfway up the 07:00-08:00 ramp
    (THU.replace(hour=18, minute=30), 0.55),  # halfway down the 18:00-19:00 ramp
    (FRI.replace(hour=10), 0.2),
    (SAT.replace(hour=10), 0.2),
    (SAT.replace(hour=3), 0.1 * 0.2),
    (SUN.replace(hour=10), 1.0),            # Sunday is a working day in Algeria
])
def test_office_profile_curve(when, expected):
    assert Profile().factor(when) == pytest.approx(expected)


def test_profile_is_configurable():
    profile = Profile(start=9, end=17, ramp=0, night=0, weekend=0.5, weekend_days=frozenset({5, 6}))
    assert profile.factor(THU.replace(hour=8, minute=59)) == 0
    assert profile.factor(THU.replace(hour=9)) == 1
    assert profile.factor(SAT.replace(hour=12)) == 0.5
    assert profile.factor(FRI.replace(hour=12)) == 1


@pytest.mark.parametrize("kwargs", [
    {"start": 18, "end": 8}, {"night": 1.5}, {"weekend": -0.1}, {"ramp": -1}, {"weekend_days": frozenset({7})},
])
def test_profile_rejects_bad_values(kwargs):
    with pytest.raises(ValueError):
        Profile(**kwargs)


def test_parsers():
    assert parse_hours("08-18") == (8, 18)
    assert parse_hours("8:30-17:45") == (8.5, 17.75)
    assert parse_days("fri,sat") == {4, 5}
    assert parse_days("Friday, Saturday") == {4, 5}
    assert parse_days("") == frozenset()
    with pytest.raises(ValueError):
        parse_hours("8h-18h")
    with pytest.raises(ValueError):
        parse_days("fri,xyz")


def _simulate(tmp_path, start, *, profile=None, hours=1.0, rate=2.0):
    clock = FakeClock(start)
    result = run(tmp_path / start.strftime("%a%H"), seed=1, duration=hours * 3600, rate=rate,
                 attack_every=(10**9, 10**9), only=None, profile=profile, clock=clock)
    return result, clock


def test_run_follows_the_daily_curve_with_a_fake_clock(tmp_path):
    day, _ = _simulate(tmp_path, THU.replace(hour=10))
    night, _ = _simulate(tmp_path, THU.replace(hour=2))
    weekend, _ = _simulate(tmp_path, FRI.replace(hour=10))
    # ~7200 candidates per simulated hour at 2 ev/s; tolerances are many standard deviations wide
    assert day.background == day.candidates
    assert night.background / night.candidates == pytest.approx(0.1, abs=0.03)
    assert weekend.background / weekend.candidates == pytest.approx(0.2, abs=0.03)


def test_flat_profile_keeps_every_event(tmp_path):
    result, _ = _simulate(tmp_path, THU.replace(hour=2), profile=Flat(), hours=0.2)
    assert result.background == result.candidates > 0


def test_run_writes_background_lines_with_the_fake_time(tmp_path):
    _, clock = _simulate(tmp_path, THU.replace(hour=10), hours=0.05)
    db_lines = (tmp_path / "Thu10" / "srv-db-01" / "db_audit.json").read_text().splitlines()
    stamps = [datetime.fromisoformat(json.loads(line)["timestamp"]) for line in db_lines]
    assert stamps and THU.replace(hour=10) <= min(stamps) <= max(stamps) <= clock.now()


def test_attacks_ignore_office_hours(tmp_path):
    clock = FakeClock(THU.replace(hour=3))
    result = run(tmp_path, seed=4, duration=600, rate=1, attack_every=(100, 100), only=["insider"],
                 profile=Profile(), clock=clock)
    assert result.attacks == ["insider"] * 5


def test_cli_rejects_bad_profile_options(tmp_path):
    with pytest.raises(SystemExit):
        main(["run", "--out", str(tmp_path), "--office-hours", "18-08"])
    with pytest.raises(SystemExit):
        main(["run", "--out", str(tmp_path), "--rate", "0"])


# --- stats ---------------------------------------------------------------------

def test_line_time_parses_every_host_format():
    when = datetime(2026, 11, 12, 14, 30, 5)
    rng = random.Random(1)
    assert stats.line_time("syslog", e.ssh_success(rng, when), 2026) == when
    assert stats.line_time("apache", e.web_request(rng, when), 2026) == when
    assert stats.line_time("json", e.db_query(rng, when), 2026) == when
    assert stats.line_time("json", "not json", 2026) is None
    assert stats.line_time("syslog", "", 2026) is None


def test_stats_counts_per_host_per_minute(tmp_path):
    clock = FakeClock(THU.replace(hour=10))
    result = run(tmp_path, seed=2, duration=300, rate=2, attack_every=(10**9, 10**9), only=None,
                 profile=Flat(), clock=clock)
    now = clock.now()
    counts = stats.count_per_minute(tmp_path, now, minutes=5)
    assert set(counts) == {"srv-linux-01", "srv-web-01", "srv-db-01", "ws-claims-01"}
    total = sum(sum(c.values()) for c in counts.values())
    # 5 full minutes out of a 5-minute run whose last partial minute is excluded
    assert 0 < total <= result.background
    table = stats.render(counts, now, 5)
    lines = table.splitlines()
    assert lines[0].split()[:2] == ["minute", "srv-linux-01"]
    assert len(lines) == 1 + 5 + 2  # header, 5 minutes, total, ev/s
    assert lines[-2].split()[-1] == str(total)
    assert float(lines[-1].split()[-1]) == pytest.approx(total / 300, abs=0.001)


def test_stats_command_on_empty_folder(tmp_path, capsys):
    assert main(["stats", "--out", str(tmp_path), "--minutes", "2"]) == 0
    assert "ev/s" in capsys.readouterr().out


# --- list --json, marker ---------------------------------------------------------

def test_list_json_matches_scenarios(capsys):
    assert main(["list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {s["name"] for s in data} >= {"brute_force", "insider"}
    assert all(s["expected_rules"] for s in data)


def test_marker_writes_one_tagged_ssh_login(tmp_path, capsys):
    assert main(["marker", "latency-abc123", "--out", str(tmp_path)]) == 0
    written = float(capsys.readouterr().out)
    assert written > 0
    line = (tmp_path / "srv-linux-01" / "auth.log").read_text().strip()
    assert re.search(r"sshd\[\d+\]: Accepted password for latency-abc123 from ", line)


def test_marker_rejects_unsafe_tags(tmp_path):
    with pytest.raises(SystemExit):
        main(["marker", "a b\nFake line", "--out", str(tmp_path)])
