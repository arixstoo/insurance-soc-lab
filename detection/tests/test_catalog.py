"""docs/detection-catalog.md is generated from the rules XML: keep it in sync (no Docker)."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import gen_catalog as gc  # noqa: E402

RULES = gc.parse_rules()


def test_catalog_is_up_to_date():
    text = gc.CATALOG.read_text(encoding="utf-8")
    assert gc.render(text, RULES) == text, "run: python scripts/gen_catalog.py"


def test_every_rule_has_a_false_positive_row():
    rows = gc.false_positive_ids(gc.CATALOG.read_text(encoding="utf-8"))
    assert sorted(rows) == sorted(r.id for r in RULES)


def test_parser_reads_correlation_and_lists():
    by_id = {r.id: r for r in RULES}
    assert "6 in 120 s" in by_id["100100"].correlation
    assert ("db_user", "not_match_key", "db-service-accounts") in by_id["100131"].lists
    assert "same `account`" in by_id["100145"].correlation
    assert by_id["100145"].mitre == ["T1136.001", "T1098"]


def test_every_mitre_id_has_a_name():
    assert {t for r in RULES for t in r.mitre} <= set(gc.MITRE)


def test_replace_generated_keeps_hand_written_text():
    text = "intro\n<!-- BEGIN GENERATED: a (x) -->\nold\n<!-- END GENERATED: a -->\noutro\n"
    assert gc.replace_generated(text, {"a": "new"}) == (
        "intro\n<!-- BEGIN GENERATED: a (x) -->\nnew\n<!-- END GENERATED: a -->\noutro\n")
    with pytest.raises(ValueError):
        gc.replace_generated(text, {"missing": "x"})


def test_check_mode_fails_on_a_stale_catalog(tmp_path, capsys):
    stale = tmp_path / "catalog.md"
    stale.write_text(gc.CATALOG.read_text(encoding="utf-8").replace("| 100100 | 10 |", "| 100100 | 3 |"),
                     encoding="utf-8")
    assert gc.main(["--check", "--catalog", str(stale)]) == 1
    assert gc.main(["--check"]) == 0


def test_noise_report_helpers():
    import noise_report as nr

    assert nr.next_monday(dt.date(2026, 11, 12)) == dt.datetime(2026, 11, 16)
    assert nr.next_monday(dt.date(2026, 11, 16)) == dt.datetime(2026, 11, 23)  # strictly after
    t0 = dt.datetime(2026, 11, 16, 9)
    line = '{"log_type":"winsec","EventID":4625,"IpAddress":"10.20.10.9"}'
    events = [(t0 + dt.timedelta(seconds=s), "workstation", line) for s in (0, 50, 100, 400)]
    results = [{"rule": "100141"}] * 4
    row = next(h for h in nr.headroom(events, results) if h["rule"] == "100142")
    assert (row["max"], row["entity"]) == (3, "10.20.10.9")
