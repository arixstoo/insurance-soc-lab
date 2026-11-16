"""A small Sigma evaluator, to test the Sigma rules of detection/sigma/ on the events of
detection/tests/cases.yaml (the same events the Wazuh tests run through the real engine).

It is NOT a Sigma backend. It evaluates the parsed rule that pySigma builds (condition
tree, modifiers already applied) on Python dicts, with the semantics most backends share:
case-insensitive strings with wildcards, keywords as case-insensitive substrings of the
raw line, `re` as an unanchored search, `cidr`, numeric `gte`/`lt`..., placeholders
(`|expand`) resolved from the CDB lists in detection/lists/. Correlations: event_count and
temporal / temporal_ordered, with group-by, aliases and timespan.

The log lines are turned into events with the field names the Sigma rules use: the
`webserver` taxonomy, the Windows Security schema (SIDs included), pgaudit's documented
field names. That mapping is the "log pipeline" a real deployment would need; it is
written down in docs/detection-catalog.md (Sigma rules).
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import zlib
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule, SigmaCorrelationType
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    Placeholder,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = ROOT / "detection" / "sigma" / "rules"
LISTS = ROOT / "detection" / "lists"
PLACEHOLDER_PREFIX = "insurco_"


def load(directory: Path = SIGMA_DIR) -> SigmaCollection:
    collection = SigmaCollection.load_ruleset(sorted(directory.rglob("*.yml")), collect_errors=True)
    collection.resolve_rule_references()
    return collection


def wazuh_rules(rule: SigmaRule | SigmaCorrelationRule) -> list[str]:
    return [str(r) for r in (rule.custom_attributes or {}).get("wazuh_rules", [])]


def placeholder_values(name: str, lists: Path = LISTS) -> list[str]:
    """%insurco_scanner_ips% -> the keys of detection/lists/scanner-ips."""
    if not name.startswith(PLACEHOLDER_PREFIX):
        raise KeyError(f"unknown placeholder %{name}%: expected {PLACEHOLDER_PREFIX}<list name>")
    path = lists / name.removeprefix(PLACEHOLDER_PREFIX).replace("_", "-")
    return [line.partition(":")[0] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ----------------------------------------------------------------------------- matching

def _string_regex(value: SigmaString) -> re.Pattern:
    parts = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, Placeholder):
            raise ValueError("placeholder inside a string")
        else:
            parts.append(re.escape(part))
    return re.compile("".join(parts), re.IGNORECASE | re.DOTALL)


def match_value(expected, actual) -> bool:
    if isinstance(expected, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(expected, SigmaString):
        placeholders = [p for p in expected.s if isinstance(p, Placeholder)]
        if placeholders:
            if len(expected.s) != 1:
                raise ValueError("only a whole-value placeholder is supported")
            return any(str(actual).lower() == v.lower() for v in placeholder_values(placeholders[0].name))
        return _string_regex(expected).fullmatch(str(actual)) is not None
    if isinstance(expected, SigmaNumber):
        try:
            return float(actual) == float(expected.number)
        except (TypeError, ValueError):
            return False
    if isinstance(expected, SigmaCompareExpression):
        try:
            number, limit = float(actual), float(expected.number.number)
        except (TypeError, ValueError):
            return False
        return {CompareOperators.LT: number < limit, CompareOperators.LTE: number <= limit,
                CompareOperators.GT: number > limit, CompareOperators.GTE: number >= limit}[expected.op]
    if isinstance(expected, SigmaRegularExpression):
        flags = 0
        for flag in expected.flags:
            flags |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}[flag.value]
        return re.search(expected.regexp.to_plain(), str(actual), flags) is not None
    if isinstance(expected, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in expected.network
        except ValueError:
            return False
    raise TypeError(f"value type not supported by the test evaluator: {type(expected).__name__}")


def _eval(node, event: dict) -> bool:
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return match_value(node.value, event.get(node.field))
    if isinstance(node, ConditionValueExpression):  # keyword: substring of the raw line
        pattern = _string_regex(node.value).pattern
        return re.search(pattern, event.get("_raw", ""), re.IGNORECASE) is not None
    raise TypeError(f"condition node not supported by the test evaluator: {type(node).__name__}")


def logsource_matches(rule: SigmaRule, event: dict) -> bool:
    src = rule.logsource
    return all(getattr(src, key) is None or getattr(src, key) == event.get(f"_{key}")
               for key in ("category", "product", "service"))


def matches(rule: SigmaRule, event: dict) -> bool:
    return logsource_matches(rule, event) and any(
        _eval(cond.parsed, event) for cond in rule.detection.parsed_condition)


# ----------------------------------------------------------------------------- correlations

@dataclass
class Timed:
    t: float
    event: dict


def _group_key(corr: SigmaCorrelationRule, rule: SigmaRule, event: dict) -> tuple:
    key = []
    for field in corr.group_by or []:
        alias = corr.aliases.aliases.get(field) if corr.aliases else None
        name = field
        if alias is not None:
            name = next(f for ref, f in alias.mapping.items() if ref.reference == rule.name)
        key.append(str(event.get(name)).lower())
    return tuple(key)


def _matched_by(corr: SigmaCorrelationRule, event: dict) -> list[SigmaRule]:
    return [ref.rule for ref in corr.rules if fires(ref.rule, [Timed(0, event)])]


def fires(rule: SigmaRule | SigmaCorrelationRule, events: list[Timed]) -> bool:
    """Does `rule` fire on the LAST event of the sequence (as the Wazuh tests check)?"""
    last = events[-1]
    if isinstance(rule, SigmaRule):
        return matches(rule, last.event)
    hits_last = _matched_by(rule, last.event)
    if not hits_last:
        return False
    key = _group_key(rule, hits_last[0], last.event)
    window = [e for e in events if last.t - e.t <= rule.timespan.seconds]
    in_group = [(e, [r for r in _matched_by(rule, e.event) if _group_key(rule, r, e.event) == key])
                for e in window]
    in_group = [(e, rs) for e, rs in in_group if rs]
    if rule.type == SigmaCorrelationType.EVENT_COUNT:
        count, cond = len(in_group), rule.condition
        return {SigmaCorrelationConditionOperator.GTE: count >= cond.count,
                SigmaCorrelationConditionOperator.GT: count > cond.count,
                SigmaCorrelationConditionOperator.LTE: count <= cond.count,
                SigmaCorrelationConditionOperator.LT: count < cond.count,
                SigmaCorrelationConditionOperator.EQ: count == cond.count}[cond.op]
    names = [ref.rule.name for ref in rule.rules]
    if rule.type == SigmaCorrelationType.TEMPORAL:
        return set(names) <= {r.name for _, rs in in_group for r in rs}
    if rule.type == SigmaCorrelationType.TEMPORAL_ORDERED:
        if names[-1] not in {r.name for r in hits_last}:
            return False
        step = 0
        for _, rs in in_group:
            if step < len(names) and names[step] in {r.name for r in rs}:
                step += 1
        return step == len(names)
    raise TypeError(f"correlation type not supported by the test evaluator: {rule.type}")


# ----------------------------------------------------------------------------- log lines -> events

ACCESS = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>\S+) (?P<uri>\S+)[^"]*" (?P<status>\d{3}) '
                    r'\S+ "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"')
SYSLOG = re.compile(r"^\S+(?: \d+ [\d:]+)? (?P<host>\S+) (?P<program>[\w.-]+)(?:\[\d+\])?: (?P<message>.*)$")
SSH_FROM = re.compile(r"\bfrom (?P<ip>[0-9a-fA-F.:]+) port \d+")
WELL_KNOWN_GROUPS = {"administrators": "S-1-5-32-544", "domain admins": "S-1-5-21-1000-2000-3000-512"}


def lab_sid(name: str) -> str:
    """A stable fake domain SID for a lab account name (the lab's events carry names only)."""
    return f"S-1-5-21-1000-2000-3000-{1100 + zlib.crc32(name.lower().encode()) % 90000}"


def _windows(record: dict) -> dict:
    """The lab's simplified winsec JSON -> the Windows Security schema of the Sigma rules."""
    event = {"_product": "windows", "_service": "security", **record}
    if record.get("EventID") == 4720 and "TargetUserName" in record:
        event["TargetSid"] = lab_sid(record["TargetUserName"])
    if record.get("EventID") in (4728, 4732):
        group = record.get("GroupName", "")
        event["TargetUserName"] = group  # real 4728 / 4732: TargetUserName is the GROUP
        event["TargetSid"] = WELL_KNOWN_GROUPS.get(group.lower(), lab_sid("group:" + group))
        if "MemberName" in record:
            event["MemberSid"] = lab_sid(record["MemberName"])
    return event


def _pgaudit(record: dict) -> dict:
    """PostgreSQL jsonlog + pgaudit CSV message -> pgaudit's documented field names."""
    event = {"_product": "postgresql", "_service": "pgaudit", **record}
    message = record.get("message", "")
    if message.startswith("AUDIT: "):
        row = next(csv.reader([message.removeprefix("AUDIT: ")]))
        names = ["audit_type", "statement_id", "substatement_id", "class", "command",
                 "object_type", "object_name", "statement", "parameter", "rows"]
        event.update(dict(zip(names, row, strict=False)))
    return event


def to_event(line: str) -> dict:
    event: dict = {"_raw": line}
    if line.startswith("{"):
        record = json.loads(line)
        if record.get("log_type") == "db_audit":
            return {**event, "_product": "insurco", "_service": "db_audit", **record}
        if record.get("log_type") == "winsec":
            return {**event, **_windows(record)}
        if "error_severity" in record:
            return {**event, **_pgaudit(record)}
        return event
    if access := ACCESS.match(line):
        stem, _, query = access["uri"].partition("?")
        return {**event, "_category": "webserver", "c-ip": access["ip"], "cs-method": access["method"],
                "cs-uri-stem": stem, "cs-uri-query": query or None, "sc-status": int(access["status"]),
                "cs-referer": access["referer"], "cs-user-agent": access["agent"]}
    if (syslog := SYSLOG.match(line)) and "sshd" in syslog["program"]:
        event.update({"_product": "linux", "_service": "sshd"})
        if src := SSH_FROM.search(syslog["message"]):
            event["src_ip"] = src["ip"]
    return event
