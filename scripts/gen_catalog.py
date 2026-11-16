#!/usr/bin/env python3
"""Generate the tables of docs/detection-catalog.md from the rules XML.

Only the blocks between `<!-- BEGIN GENERATED: <name> ... -->` and
`<!-- END GENERATED: <name> -->` are rewritten; every hand-written section (why,
false positives, tuning log, gaps) is kept as is.

    python scripts/gen_catalog.py           # rewrite docs/detection-catalog.md
    python scripts/gen_catalog.py --check   # exit 1 if the file is stale (CI)

--check also fails when a rule has no row in the hand-written "Known false
positives" table, or when that table names a rule that does not exist.

Sigma: the `sigma` block lists detection/sigma/rules/ (one file per rule) with the Wazuh
rules each one stands for (its `wazuh_rules` attribute); detection/tests/test_sigma.py
proves that they agree on the test cases.

Runbooks: a rule's `<info type="link">` (Wazuh's own element, so the link also travels
with the alert) points to docs/runbooks/<file>.md on GitHub; the catalog links the
rule's description to that runbook.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "detection" / "rules" / "insurco_rules.xml"
LISTS = ROOT / "detection" / "lists"
CATALOG = ROOT / "docs" / "detection-catalog.md"
RUNBOOKS = ROOT / "docs" / "runbooks"
SIGMA = ROOT / "detection" / "sigma" / "rules"
LIST_SHOWN = 4  # longer lists (threat intel) show their first entries and a count
# Absolute, so the link still works in an alert, a webhook message or a ticket
RUNBOOK_BASE = "https://github.com/arixstoo/insurance-soc-lab/blob/main/docs/runbooks/"

# ATT&CK names for the ids used by the rules (display only; an unknown id shows bare).
MITRE = {
    "T1078": "Valid Accounts",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1083": "File and Directory Discovery",
    "T1098": "Account Manipulation",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1136.001": "Create Account: Local Account",
    "T1190": "Exploit Public-Facing Application",
    "T1213": "Data from Information Repositories",
    "T1530": "Data from Cloud Storage",
    "T1548.003": "Sudo and Sudo Caching",
    "T1595": "Active Scanning",
    "T1595.003": "Wordlist Scanning",
}

BLOCK = re.compile(
    r"(<!-- BEGIN GENERATED: (?P<name>[\w-]+)[^>]*-->\n)(?P<body>.*?)(<!-- END GENERATED: (?P=name) -->)",
    re.DOTALL,
)


@dataclass
class Rule:
    id: str
    level: int
    description: str
    groups: list[str]
    mitre: list[str]
    built_on: list[str] = field(default_factory=list)
    correlation: list[str] = field(default_factory=list)
    lists: list[tuple[str, str, str]] = field(default_factory=list)  # (field, lookup, list name)
    links: list[str] = field(default_factory=list)  # <info type="link"> values

    @property
    def runbook(self) -> str | None:
        """File name of the runbook in docs/runbooks/, or None if the rule links none."""
        return next((link.removeprefix(RUNBOOK_BASE) for link in self.links if link.startswith(RUNBOOK_BASE)), None)


def _text(node: ET.Element, tag: str) -> str | None:
    child = node.find(tag)
    return child.text.strip() if child is not None and child.text else None


def parse_rules(path: Path = RULES) -> list[Rule]:
    rules = []
    for node in ET.parse(path).getroot().iter("rule"):
        groups = [g for el in node.findall("group") for g in (el.text or "").split(",") if g.strip()]
        rule = Rule(
            id=node.get("id"),
            level=int(node.get("level")),
            description=re.sub(r"^InsurCo - ", "", _text(node, "description") or ""),
            groups=[g.strip() for g in groups],
            mitre=[el.text.strip() for el in node.findall("mitre/id")],
            links=[el.text.strip() for el in node.findall("info") if el.get("type") == "link" and el.text],
        )
        for tag, label in (("if_sid", "{}"), ("if_matched_sid", "after {}"), ("if_group", "group `{}`"),
                           ("if_matched_group", "after group `{}`"), ("decoded_as", "decoder `{}`")):
            value = _text(node, tag)
            if value:
                rule.built_on.append(label.format(value.replace(",", ", ")))
        if node.get("frequency"):
            rule.correlation.append(f"{node.get('frequency')} in {node.get('timeframe')} s")
        elif node.get("timeframe"):
            rule.correlation.append(f"within {node.get('timeframe')} s")
        for el in node.findall("same_field"):
            rule.correlation.append(f"same `{el.text.strip()}`")
        for tag in ("same_source_ip", "same_srcip", "same_user"):
            if node.find(tag) is not None:
                rule.correlation.append(f"same `{tag.removeprefix('same_').replace('source_ip', 'srcip')}`")
        if node.get("ignore"):
            rule.correlation.append(f"then quiet {node.get('ignore')} s")
        if _text(node, "time"):
            rule.correlation.append(f"only {_text(node, 'time')}")
        for el in node.findall("list"):
            rule.lists.append((el.get("field"), el.get("lookup"), Path(el.text.strip()).name))
        rules.append(rule)
    return rules


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def detection_cell(rule: Rule) -> str:
    text = _cell(rule.description)
    return f"[{text}](runbooks/{rule.runbook})" if rule.runbook else text


def mitre_cell(ids: list[str]) -> str:
    return "<br>".join(f"{i} {MITRE[i]}" if i in MITRE else i for i in ids) or "-"


def rules_table(rules: list[Rule]) -> str:
    rows = ["| ID | Level | Detection | Built on | Correlation / conditions | MITRE ATT&CK | Groups |",
            "|---|---|---|---|---|---|---|"]
    for r in rules:
        conditions = list(r.correlation)
        conditions += [f"{'not in' if lk.startswith('not_') else 'in'} list `{name}` ({fld})"
                       for fld, lk, name in r.lists]
        rows.append("| " + " | ".join([
            r.id, str(r.level), detection_cell(r), _cell(", ".join(r.built_on) or "-"),
            _cell("; ".join(conditions) or "-"), mitre_cell(r.mitre),
            ", ".join(f"`{g}`" for g in r.groups),
        ]) + " |")
    return "\n".join(rows)


def lists_table(rules: list[Rule], lists_dir: Path = LISTS) -> str:
    rows = ["| List (`etc/lists/insurco/`) | Entries | Used by | Effect |", "|---|---|---|---|"]
    for path in sorted(p for p in lists_dir.iterdir() if p.is_file()):
        entries = [line.partition(":")[::2] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        users = [r for r in rules if any(name == path.name for _, _, name in r.lists)]
        effect = "; ".join(sorted({f"{'skip' if lk.startswith('not_') else 'require'} on `{fld}`"
                                   for r in users for fld, lk, name in r.lists if name == path.name}))
        shown = entries if len(entries) <= LIST_SHOWN else entries[:LIST_SHOWN - 1]
        listed = "<br>".join(f"`{key}` - {_cell(value.strip())}" if value.strip() else f"`{key}`"
                             for key, value in shown)
        if len(shown) < len(entries):
            listed += f"<br>... **{len(entries)} entries** (see the file)"
        rows.append(f"| `{path.name}` | {listed or '-'} | {', '.join(r.id for r in users) or 'unused'} | "
                    f"{effect or '-'} |")
    return "\n".join(rows)


def mitre_table(rules: list[Rule]) -> str:
    techniques: dict[str, list[str]] = {}
    for r in rules:
        for t in r.mitre:
            techniques.setdefault(t, []).append(r.id)
    rows = ["| Technique | Rules |", "|---|---|"]
    rows += [f"| {mitre_cell([t])} | {', '.join(ids)} |" for t, ids in sorted(techniques.items())]
    return "\n".join(rows)


def sigma_table(directory: Path = SIGMA) -> str:
    rows = ["| Sigma rule | Kind | Logsource | Level | Wazuh rule(s) |", "|---|---|---|---|---|"]
    for path in sorted(directory.rglob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        corr = doc.get("correlation")
        if corr:
            kind = f"{corr['type']} ({', '.join(corr['group-by'])}, {corr['timespan']}"
            kind += f", >= {corr['condition']['gte']})" if "condition" in corr else ")"
            source = "correlation of " + ", ".join(f"`{r}`" for r in corr["rules"])
        else:
            kind = "rule"
            source = ", ".join(f"{k}: `{v}`" for k, v in doc["logsource"].items() if k != "definition")
        link = f"[`{path.stem}`](../{path.relative_to(ROOT).as_posix()})"
        rows.append(f"| {link}<br>{_cell(doc['title'])} | {_cell(kind)} | {source} | {doc['level']} | "
                    f"{', '.join(str(i) for i in doc['wazuh_rules'])} |")
    return "\n".join(rows)


def summary(rules: list[Rule]) -> str:
    alerting = [r for r in rules if r.level >= 3]
    return (f"{len(rules)} rules ({len(alerting)} raise alerts, {len(rules) - len(alerting)} are building blocks below "
            f"the alert level), {len({t for r in rules for t in r.mitre})} ATT&CK techniques.")


def replace_generated(text: str, blocks: dict[str, str]) -> str:
    """Replace the body of each named generated block; unknown or missing names are errors."""
    found = {m.group("name") for m in BLOCK.finditer(text)}
    if missing := set(blocks) - found:
        raise ValueError(f"markers not found: {', '.join(sorted(missing))}")

    def sub(match: re.Match) -> str:
        name = match.group("name")
        if name not in blocks:
            return match.group(0)
        return f"{match.group(1)}{blocks[name].rstrip()}\n{match.group(4)}"

    return BLOCK.sub(sub, text)


def false_positive_ids(text: str) -> list[str]:
    """Rule ids of the rows of the hand-written "Known false positives" table."""
    match = re.search(r"^## Known false positives\n(.*?)(?=^## |\Z)", text, re.DOTALL | re.MULTILINE)
    return re.findall(r"^\| (\d{6}) \|", match.group(1), re.MULTILINE) if match else []


def runbook_problems(rules: list[Rule], runbooks: Path = RUNBOOKS) -> list[str]:
    """Every alerting rule (level >= 3) links a runbook, and every linked runbook exists."""
    problems = []
    for r in rules:
        if r.runbook is None and r.level >= 3:
            problems.append(f"rule {r.id} (level {r.level}) has no <info type=\"link\"> to {RUNBOOK_BASE}...")
        elif r.runbook is not None and not (runbooks / r.runbook).is_file():
            problems.append(f"rule {r.id} links a missing runbook: docs/runbooks/{r.runbook}")
    return problems


def render(text: str, rules: list[Rule]) -> str:
    return replace_generated(text, {
        "summary": summary(rules),
        "rules": rules_table(rules),
        "lists": lists_table(rules),
        "mitre": mitre_table(rules),
        "sigma": sigma_table(),
    })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the catalog is not up to date")
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    args = parser.parse_args(argv)

    rules = parse_rules()
    current = args.catalog.read_text(encoding="utf-8")
    updated = render(current, rules)

    ids = [r.id for r in rules]
    fp_ids = false_positive_ids(updated)
    problems = [f"rule {i} has no row in 'Known false positives'" for i in ids if i not in fp_ids]
    problems += [f"'Known false positives' lists unknown rule {i}" for i in fp_ids if i not in ids]
    problems += runbook_problems(rules)

    if args.check:
        if updated != current:
            sys.stdout.writelines(difflib.unified_diff(
                current.splitlines(True), updated.splitlines(True), "catalog (committed)", "catalog (generated)"))
            problems.insert(0, f"{args.catalog.name} is stale: run python scripts/gen_catalog.py")
    else:
        if updated != current:
            args.catalog.write_text(updated, encoding="utf-8", newline="\n")
            print(f"updated {args.catalog.relative_to(ROOT) if args.catalog.is_relative_to(ROOT) else args.catalog}")
        else:
            print("catalog already up to date")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
