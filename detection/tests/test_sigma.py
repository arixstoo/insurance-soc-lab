"""The Sigma rules of detection/sigma/ (no Docker): valid for pySigma, mapped to existing
Wazuh rules, and in agreement with them on the engine-verified cases of cases.yaml.

    python -m pytest -q detection/tests/test_sigma.py

Agreement: a case whose `expect` is a Wazuh rule a Sigma rule stands for must make that
Sigma rule fire on its last line; a case whose `expect_not` is one of them must not
(unless what fired instead is built on it: in Wazuh one event raises one alert, the
correlation instead of its input, while Sigma raises both). Same policy as the Wazuh
rules: every Sigma rule needs at least one positive and one negative case.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.plugins import InstalledSigmaPlugins
from sigma.rule import SigmaRule
from sigma.types import Placeholder, SigmaString
from sigma.validation import SigmaValidator

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sigma_eval  # noqa: E402
from run_tests import RULES, load_raw_cases, render  # noqa: E402

COLLECTION = sigma_eval.load()
SIGMA = list(COLLECTION.rules)
BY_NAME = {r.name: r for r in SIGMA}
CASES = load_raw_cases()
XML = {r.get("id"): r for r in ET.parse(RULES).getroot().iter("rule")}
# Validators that download MITRE ATT&CK / D3FEND data: run on their own (test below).
ONLINE_VALIDATORS = {"attacktag", "d3_fendtag"}


def _ids(rule) -> str:
    return rule.name


def _wazuh_children(ids: set[str]) -> set[str]:
    """Wazuh rules built on `ids` (if_sid / if_matched_sid), transitively."""
    found = set(ids)
    while True:
        more = {rid for rid, node in XML.items() if rid not in found and any(
            p.strip() in found for tag in ("if_sid", "if_matched_sid") for p in (node.findtext(tag) or "").split(","))}
        if not more:
            return found
        found |= more


def family(rule) -> set[str]:
    """Wazuh ids of the rule, of the Wazuh rules built on them (e.g. the threat-intel child
    100153 of 100129) and of every Sigma correlation built on the rule, transitively."""
    ids = _wazuh_children(set(sigma_eval.wazuh_rules(rule)))
    for other in SIGMA:
        if isinstance(other, SigmaCorrelationRule) and rule.name in [ref.rule.name for ref in other.rules]:
            ids |= family(other)
    return ids


def verdicts(rule) -> tuple[list[dict], list[dict]]:
    own, fam = set(sigma_eval.wazuh_rules(rule)), family(rule)
    positives = [c for c in CASES if c.get("expect") in own]
    negatives = [c for c in CASES if c.get("expect_not") in own and c.get("expect") not in fam]
    return positives, negatives


def events_of(case: dict) -> list[sigma_eval.Timed]:
    start = dt.datetime(2026, 1, 5, 12 if case.get("clock", "day") == "day" else 2)
    offsets = case.get("at") or [0] * len(case["lines"])
    return [sigma_eval.Timed(t, sigma_eval.to_event(render(line, start + dt.timedelta(seconds=t))))
            for t, line in zip(offsets, case["lines"], strict=True)]


# ----------------------------------------------------------------------------- pySigma

def test_rules_load_without_errors():
    assert len(SIGMA) >= 13
    for rule in SIGMA:
        assert not rule.errors, f"{rule.source}: {rule.errors}"


def test_rules_pass_the_pysigma_validators():
    validators = InstalledSigmaPlugins.autodiscover().validators
    offline = [cls for name, cls in validators.items() if name not in ONLINE_VALIDATORS]
    issues = SigmaValidator(offline).validate_rules(SIGMA)
    assert not issues, "\n".join(f"{type(i).__name__}: {[r.title for r in i.rules]}" for i in issues)


def test_attack_tags_exist_in_mitre_attack():
    """pySigma downloads the ATT&CK dataset for this one: required in CI, skipped offline."""
    from sigma.validators.core.tags import ATTACKTagValidator
    try:
        issues = SigmaValidator([ATTACKTagValidator]).validate_rules(SIGMA)
    except RuntimeError as exc:  # no network
        if os.environ.get("CI"):
            raise
        pytest.skip(f"MITRE ATT&CK data unavailable offline: {exc}")
    assert not issues, [(i.tag, [r.title for r in i.rules]) for i in issues]


def test_ids_names_and_files_are_unique():
    assert len({r.id for r in SIGMA}) == len(SIGMA)
    assert len(BY_NAME) == len(SIGMA)
    for rule in SIGMA:
        assert rule.name and rule.name.startswith("insurco_"), rule.title
        assert Path(str(rule.source.path)).stem == rule.name, "one rule per file, named after the rule"


# ----------------------------------------------------------------------------- mapping

@pytest.mark.parametrize("rule", SIGMA, ids=_ids)
def test_maps_to_wazuh_rules_proven_by_the_engine(rule):
    ids = sigma_eval.wazuh_rules(rule)
    assert ids, f"{rule.name}: no wazuh_rules"
    proven = {c.get("expect") for c in CASES}
    for rid in ids:
        assert rid in XML or rid in proven, f"{rule.name}: Wazuh rule {rid} neither ours nor in a tested case"


@pytest.mark.parametrize("rule", SIGMA, ids=_ids)
def test_attack_techniques_are_those_of_the_main_wazuh_rule(rule):
    main = sigma_eval.wazuh_rules(rule)[0]
    if main not in XML:
        pytest.skip(f"{main} is a built-in Wazuh rule")
    wazuh = {el.text.strip().lower() for el in XML[main].findall("mitre/id")}
    sigma = {t.name for t in rule.tags if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", t.name)}
    assert sigma == wazuh


@pytest.mark.parametrize("rule", [r for r in SIGMA if isinstance(r, SigmaCorrelationRule)], ids=_ids)
def test_correlation_window_and_threshold_match_wazuh(rule):
    wazuh = XML[sigma_eval.wazuh_rules(rule)[0]]
    assert rule.timespan.seconds == int(wazuh.get("timeframe"))
    if rule.type == SigmaCorrelationType.EVENT_COUNT:
        assert rule.condition.count == int(wazuh.get("frequency"))
    else:  # temporal: Wazuh writes it as a child of the last step with if_matched_sid on the first
        steps = [sigma_eval.wazuh_rules(ref.rule)[0] for ref in rule.rules]
        assert wazuh.findtext("if_matched_sid").strip() == steps[0]
        assert wazuh.findtext("if_sid").strip() == steps[-1]


def test_placeholders_resolve_to_the_lab_lists():
    used = set()
    for rule in SIGMA:
        for detection in getattr(rule, "detection", None).detections.values() if isinstance(rule, SigmaRule) else []:
            for item in detection.detection_items:
                for value in getattr(item, "value", []):
                    if isinstance(value, SigmaString):
                        used |= {p.name for p in value.s if isinstance(p, Placeholder)}
    assert used == {"insurco_scanner_ips", "insurco_db_service_accounts"}
    for name in used:
        assert sigma_eval.placeholder_values(name)


# ----------------------------------------------------------------------------- behaviour

@pytest.mark.parametrize("rule", SIGMA, ids=_ids)
def test_every_sigma_rule_has_a_positive_and_a_negative_case(rule):
    positives, negatives = verdicts(rule)
    assert positives, f"{rule.name}: no case expects {sigma_eval.wazuh_rules(rule)}"
    assert negatives, f"{rule.name}: no case has expect_not in {sigma_eval.wazuh_rules(rule)}"


AGREEMENT = [(rule, case, kind) for rule in SIGMA
             for kind, cases in zip(("fires", "quiet"), verdicts(rule), strict=True) for case in cases]


@pytest.mark.parametrize(("rule", "case", "kind"), AGREEMENT,
                         ids=[f"{r.name}-{k}-{c['name']}" for r, c, k in AGREEMENT])
def test_sigma_agrees_with_wazuh(rule, case, kind):
    fired = sigma_eval.fires(rule, events_of(case))
    assert fired == (kind == "fires"), f"{rule.name} {'did not fire' if kind == 'fires' else 'fired'}"


# ----------------------------------------------------------------------------- the evaluator itself

def test_evaluator_reports_unsupported_and_wrong_input():
    with pytest.raises(KeyError):
        sigma_eval.placeholder_values("other_list")
    event = sigma_eval.to_event('203.0.113.9 - - [05/Jan/2026:12:00:00 +0100] "GET /a?b=c HTTP/1.1" 200 1 "-" "x"')
    assert (event["c-ip"], event["cs-uri-stem"], event["cs-uri-query"]) == ("203.0.113.9", "/a", "b=c")
    win = sigma_eval.to_event('{"log_type":"winsec","EventID":4732,"MemberName":"x","GroupName":"Administrators"}')
    assert win["TargetSid"] == "S-1-5-32-544" and win["MemberSid"] == sigma_eval.lab_sid("x")
