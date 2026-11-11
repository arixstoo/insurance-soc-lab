import json
import random
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import pytest
import yaml

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


def test_background_mix_touches_every_host():
    generator = rng(3)
    roles = {background_event(generator, NOW)[0] for _ in range(500)}
    assert roles == {"linux", "web", "db", "workstation"}


def test_writer_keeps_one_folder_per_host(tmp_path):
    writer = LogWriter(tmp_path)
    writer.write("db", "x")
    assert (tmp_path / "srv-db-01" / "db_audit.json").read_text() == "x\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["srv-db-01", "srv-linux-01", "srv-web-01", "ws-claims-01"]


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
