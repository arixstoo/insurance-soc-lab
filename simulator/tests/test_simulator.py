import json
import random
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from insurco_sim import catalog as c
from insurco_sim import events as e
from insurco_sim.cli import LogWriter, main
from insurco_sim.scenarios import SCENARIOS, background_event

REPO = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 11, 14, 30, 0)

SYSLOG = re.compile(r"^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \S+ (sshd\[\d+\]|sudo): ")
APACHE = re.compile(r'^\S+ - - \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} \+0100\] "GET \S+ HTTP/1\.1" \d{3} \d+ ')


def rng(seed: int = 1) -> random.Random:
    return random.Random(seed)


def test_ssh_lines_use_sshd_syslog_format():
    assert SYSLOG.match(e.ssh_failure(rng(), NOW))
    assert "Failed password for" in e.ssh_failure(rng(), NOW)
    assert "Accepted password for" in e.ssh_success(rng(), NOW)


def test_sudo_lines_use_sudo_syslog_format():
    line = e.sudo(rng(), NOW, suspicious=True)
    assert SYSLOG.match(line)
    assert "USER=root ; COMMAND=" in line


def test_web_lines_use_apache_combined_format():
    assert APACHE.match(e.web_request(rng(), NOW))
    for kind in ("sqli", "xss", "traversal", "probe"):
        assert APACHE.match(e.web_attack(rng(), NOW, kind=kind))


def test_db_events_are_json_with_log_type():
    normal = json.loads(e.db_query(rng(), NOW))
    bulk = json.loads(e.db_query(rng(), NOW, bulk=True))
    assert normal["log_type"] == bulk["log_type"] == "db_audit"
    assert normal["rows_returned"] == 1
    assert bulk["rows_returned"] >= 100


def test_win_events_override_fields():
    event = json.loads(e.win_event(rng(), NOW, 4732, GroupName="Administrators"))
    assert event == event | {"log_type": "winsec", "EventID": 4732, "GroupName": "Administrators"}


def test_same_seed_gives_same_output():
    assert SCENARIOS["insider"].build(rng(7), NOW) == SCENARIOS["insider"].build(rng(7), NOW)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenarios_are_big_enough_to_trigger_correlation(name):
    events = SCENARIOS[name].build(rng(), NOW)
    assert events, name
    if name == "brute_force":
        assert sum("Failed password" in line for _, line in events) >= 6
    if name == "insider":
        assert len(events) >= 5
    if name == "password_spray":
        assert len(events) >= 8


@pytest.mark.parametrize("seed", range(20))
def test_web_campaign_survives_the_correlation_masking_one_event(seed):
    """The 5th web attack fires 100129 instead of its own rule: each kind must appear twice."""
    lines = [line for _, line in SCENARIOS["web_campaign"].build(rng(seed), NOW)]
    for kind, paths in c.WEB_ATTACKS.items():
        assert sum(any(p in line for p in paths) for line in lines) >= 2, kind


def test_background_mix_touches_every_host():
    generator = rng(3)
    roles = {background_event(generator, NOW)[0] for _ in range(500)}
    assert roles == {"linux", "web", "db", "workstation"}


def test_writer_keeps_one_folder_per_host(tmp_path):
    writer = LogWriter(tmp_path)
    writer.write("db", "x")
    assert (tmp_path / "srv-db-01" / "db_audit.json").read_text() == "x\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["srv-db-01", "srv-linux-01", "srv-web-01", "ws-claims-01"]


def test_writer_creates_every_log_file_up_front(tmp_path):
    # An agent must find its file when logcollector starts, before the first event
    LogWriter(tmp_path)
    for host in c.HOSTS.values():
        path = tmp_path / host.name / host.log_file
        assert path.is_file() and path.stat().st_size == 0


def test_run_for_a_short_duration(tmp_path):
    assert main(["run", "--out", str(tmp_path), "--duration", "1", "--rate", "20", "--seed", "1"]) == 0
    assert any(p.stat().st_size for p in tmp_path.rglob("*.*"))


def test_inject_writes_scenario_to_the_right_host(tmp_path):
    assert main(["inject", "insider", "--out", str(tmp_path), "--seed", "2"]) == 0
    lines = (tmp_path / "srv-db-01" / "db_audit.json").read_text().splitlines()
    assert len(lines) >= 5
    assert all(json.loads(line)["rows_returned"] >= 100 for line in lines)


def test_scenario_rules_exist_and_are_tested():
    """Docs, simulator and detection must agree on rule ids."""
    root = ET.fromstring(f"<root>{(REPO / 'detection/rules/insurco_rules.xml').read_text(encoding='utf-8')}</root>")
    defined = {rule.get("id") for rule in root.iter("rule")}
    cases = yaml.safe_load((REPO / "detection/tests/cases.yaml").read_text(encoding="utf-8"))["cases"]
    tested = {c.get("expect") for c in cases} | {c.get("expect_not") for c in cases}
    for scenario in SCENARIOS.values():
        for rule_id in scenario.expected_rules:
            assert rule_id in defined, f"{scenario.name}: rule {rule_id} is not defined"
            assert rule_id in tested, f"{scenario.name}: rule {rule_id} has no test case"


# --- phase 3: legitimate-but-suspicious background, timeline ----------------------------

def test_background_includes_allow_listed_activity():
    """The noise report is only meaningful if the background exercises the allow-lists."""
    generator = rng(3)
    lines = [background_event(generator, NOW)[1] for _ in range(5000)]
    reporting = [json.loads(x) for x in lines if '"db_user": "svc_reporting"' in x]
    assert reporting and all(r["rows_returned"] >= 100 and r["source_ip"] == c.REPORTING_HOST_IP
                             for r in reporting)
    assert any(x.startswith(c.SCANNER_IP + " ") for x in lines)


def test_allow_listed_values_match_the_cdb_lists():
    lists = REPO / "detection" / "lists"
    keys = {path.name: {line.split(":", 1)[0] for line in path.read_text().splitlines() if line}
            for path in lists.iterdir()}
    assert c.REPORTING_ACCOUNT in keys["db-service-accounts"]
    assert c.SCANNER_IP in keys["scanner-ips"]
    assert c.SCANNER_IP not in c.INTERNAL_IPS and c.REPORTING_HOST_IP not in c.INTERNAL_IPS


def test_background_never_promotes_to_an_admin_group():
    generator = rng(4)
    for _ in range(5000):
        role, line = background_event(generator, NOW)
        if '"EventID": 4732' in line:
            assert json.loads(line)["GroupName"] in c.GROUPS


def test_timeline_is_ordered_seeded_and_follows_the_profile():
    from insurco_sim.timeline import background_timeline

    start = datetime(2026, 11, 16)  # a Monday (working day in Algeria)
    events = list(background_timeline(start, 24, seed=5, rate=0.7))
    assert events == list(background_timeline(start, 24, seed=5, rate=0.7))
    stamps = [t for t, _, _ in events]
    assert stamps == sorted(stamps) and start <= stamps[0] and stamps[-1] < start.replace(day=17)
    per_hour = [sum(1 for t in stamps if t.hour == h) for h in range(24)]
    # peak ~2520/h (0.7 ev/s) from 08:00 to 18:00, ~10% at night
    assert 2200 < per_hour[12] < 2850
    assert per_hour[3] < per_hour[12] * 0.15
    assert {role for _, role, _ in events} == set(c.HOSTS)


def test_timeline_rejects_a_bad_rate():
    from insurco_sim.timeline import background_timeline

    with pytest.raises(ValueError):
        next(background_timeline(NOW, 1, rate=0))
