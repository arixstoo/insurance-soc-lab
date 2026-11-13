"""Static checks on dashboards/*.ndjson (no Docker).

The dashboards may only filter on rule ids and groups that a detection test proves:
every `rule.id` used in a panel query must be a rule that writes an alert (level >= 3)
and has a positive case in cases.yaml; every `rule.groups` value must belong to at
least one such rule. The files must also be self-contained and in sync with
scripts/build_dashboards.py.
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))

import build_dashboards as bd  # noqa: E402
from run_tests import RULES, coverage, load_raw_cases, rule_ids  # noqa: E402

LOG_ALERT_LEVEL = 3  # stack/config/wazuh_cluster/wazuh_manager.conf
FILES = sorted((ROOT / "dashboards").glob("*.ndjson"))
TERM = re.compile(r"rule\.(id|groups)\s*:\s*(\([^)]*\)|[\w.-]+)")


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def queries(obj: dict) -> list[str]:
    """Every KQL string of a saved object: its search source and its `filters` aggregations."""
    attrs = obj["attributes"]
    found = []
    source = attrs.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON")
    if source:
        found.append(json.loads(source).get("query", {}).get("query", ""))
    if "visState" in attrs:
        for agg in json.loads(attrs["visState"])["aggs"]:
            for f in agg.get("params", {}).get("filters", []):
                found.append(f["input"]["query"])
    return [q for q in found if q]


def terms(query: str) -> list[tuple[str, str]]:
    """('id'|'groups', value) pairs of `rule.id:x`, `rule.groups:(a or b)`, ..."""
    pairs = []
    for kind, value in TERM.findall(query):
        values = re.split(r"\s+or\s+", value.strip("()"), flags=re.IGNORECASE)
        pairs += [(kind, v.strip().strip('"')) for v in values if v.strip()]
    return pairs


def rules_with_groups(path: Path = RULES) -> dict[str, tuple[int, set[str]]]:
    """rule id -> (level, groups), groups including the enclosing <group name="...">."""
    result = {}
    for block in ET.parse(path).getroot().iter("group"):
        outer = {g.strip() for g in (block.get("name") or "").split(",") if g.strip()}
        for rule in block.iter("rule"):
            inner = {g.strip() for el in rule.findall("group") for g in (el.text or "").split(",") if g.strip()}
            result[rule.get("id")] = (int(rule.get("level")), outer | inner)
    return result


RULES_INFO = rules_with_groups()
COVERAGE = coverage(rule_ids(), load_raw_cases())
PROVEN = {rid for rid, (level, _) in RULES_INFO.items()
          if level >= LOG_ALERT_LEVEL and COVERAGE[rid]["positive"]}
OBJECTS = {path.name: load(path) for path in FILES}
USED = sorted({pair for objs in OBJECTS.values() for obj in objs for q in queries(obj) for pair in terms(q)})


def test_both_dashboards_are_stored():
    titles = {o["attributes"]["title"] for objs in OBJECTS.values() for o in objs if o["type"] == "dashboard"}
    assert titles == {"InsurCo - SOC Overview", "InsurCo - Insurer Security"}


@pytest.mark.parametrize("name", sorted(OBJECTS))
def test_file_is_self_contained(name):
    objects = OBJECTS[name]
    have = {(o["type"], o["id"]) for o in objects}
    for obj in objects:
        for ref in obj.get("references", []):
            assert (ref["type"], ref["id"]) in have, f"{obj['id']}: reference {ref} not in {name}"
        if obj["type"] == "dashboard":
            names = {r["name"] for r in obj["references"]}
            for panel in json.loads(obj["attributes"]["panelsJSON"]):
                assert panel["panelRefName"] in names


def test_queries_use_rules():
    assert ("id", "100101") in USED and ("groups", "insurco") in USED


@pytest.mark.parametrize("kind,value", USED, ids=[f"{k}:{v}" for k, v in USED])
def test_filter_value_is_proven_by_a_test(kind, value):
    if kind == "id":
        assert value in RULES_INFO, f"rule.id:{value} is not a rule in insurco_rules.xml"
        assert value in PROVEN, f"rule.id:{value} writes no alert or has no positive case in cases.yaml"
    else:
        owners = {rid for rid, (_, groups) in RULES_INFO.items() if value in groups}
        assert owners, f"rule.groups:{value} is not a group of any custom rule"
        assert owners & PROVEN, f"rule.groups:{value}: none of {sorted(owners)} is an alert proven by a test"


def test_term_parser():
    assert terms("rule.id:(100100 or 100101) and rule.groups:sqli") == [
        ("id", "100100"), ("id", "100101"), ("groups", "sqli")]
    assert terms("rule.level >= 12") == []


def test_files_match_the_builder():
    """dashboards/ was exported from the current build_dashboards.py (same objects, same queries)."""
    for slug, build in bd.DASHBOARDS.items():
        built = [bd.index_pattern(), *build()]
        stored = OBJECTS[f"{slug}.ndjson"]
        assert sorted((o["type"], o["id"]) for o in built) == sorted((o["type"], o["id"]) for o in stored), \
            "run: python scripts/build_dashboards.py"
        by_id = {o["id"]: o for o in stored}
        for obj in built:
            assert queries(obj) == queries(by_id[obj["id"]]), f"{obj['id']}: run scripts/build_dashboards.py"
