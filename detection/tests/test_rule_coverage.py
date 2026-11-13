"""Static checks on the detection test cases (no Docker): every rule is tested both ways.

Run with the other unit tests: python -m pytest -q simulator detection/tests
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_tests import RULES, coverage, load_raw_cases, rule_ids  # noqa: E402

IDS = rule_ids()
RAW = load_raw_cases()
COVERAGE = coverage(IDS, RAW)


def test_rules_file_defines_rules():
    assert len(IDS) >= 17
    assert len(IDS) == len(set(IDS)), "duplicate rule id"


@pytest.mark.parametrize("rule_id", IDS)
def test_every_rule_has_a_positive_case(rule_id):
    assert COVERAGE[rule_id]["positive"], f"rule {rule_id}: no case with expect: \"{rule_id}\""


@pytest.mark.parametrize("rule_id", IDS)
def test_every_rule_has_a_negative_case(rule_id):
    assert COVERAGE[rule_id]["negative"], f"rule {rule_id}: no case with expect_not: \"{rule_id}\""


def test_case_names_are_unique():
    names = [c["name"] for c in RAW]
    assert len(names) == len(set(names))


def test_cases_only_use_known_keys():
    known = {"name", "lines", "expect", "expect_not", "clock", "at", "note", "real"}
    for case in RAW:
        assert set(case) <= known, f"{case['name']}: unknown keys {set(case) - known}"
        assert "expect" in case or "expect_not" in case, f"{case['name']}: checks nothing"
        if "at" in case:
            assert len(case["at"]) == len(case["lines"]), f"{case['name']}: one offset per line"
            assert case["at"] == sorted(case["at"]), f"{case['name']}: offsets must not go back"


def _conditions(rule_id: str) -> list[tuple]:
    """What a rule tests (fields, lists, time), without its parents, level or wording."""
    rule = next(r for r in ET.parse(RULES).getroot().iter("rule") if r.get("id") == rule_id)
    return [(el.tag, sorted(el.attrib.items()), (el.text or "").strip())
            for el in rule if el.tag in {"field", "list", "time", "srcip", "user", "url", "regex", "match"}]


# Real audit trail (pgaudit) rules that repeat a simulated-trail rule: they must not drift
# apart, or "the same rule fires on simulated and real logs" stops being true.
REAL_TWINS = [("100131", "100137"), ("100133", "100138")]


@pytest.mark.parametrize(("simulated", "real"), REAL_TWINS)
def test_real_audit_trail_rules_match_their_simulated_twin(simulated, real):
    assert _conditions(real) == _conditions(simulated), f"{real} must test exactly what {simulated} tests"


def test_coverage_detects_a_missing_case():
    """The check itself: a rule without cases is reported on both sides."""
    report = coverage(["100100", "999999"], [{"name": "x", "expect": "100100"}])
    assert report["999999"] == {"positive": [], "negative": []}
    assert report["100100"] == {"positive": ["x"], "negative": []}
