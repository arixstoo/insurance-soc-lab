#!/usr/bin/env python3
"""Generate the MITRE ATT&CK Navigator layer docs/mitre-layer.json from the rules XML.

    python scripts/gen_mitre_layer.py           # rewrite docs/mitre-layer.json
    python scripts/gen_mitre_layer.py --check   # exit 1 if the file is stale (CI)

Score of a technique = number of custom rules mapped to it (`<mitre><id>`); the colour
goes from light (1 rule) to dark (most rules). The comment and metadata list the rules,
so hovering a cell in the Navigator says which detection covers it. A parent technique
with no rule of its own is added unscored, only so its sub-technique shows expanded.

Open it at https://mitre-attack.github.io/attack-navigator/ -> "Open Existing Layer"
-> "Upload from local" (or "Load from URL" with the raw GitHub URL of the file).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from gen_catalog import MITRE, ROOT, Rule, parse_rules

LAYER = ROOT / "docs" / "mitre-layer.json"
COLOURS = ["#fde4c3", "#f4a259", "#bc4b51"]  # light -> dark, readable on the Navigator's white


def build_layer(rules: list[Rule]) -> dict:
    by_technique: dict[str, list[Rule]] = defaultdict(list)
    for rule in rules:
        for tid in rule.mitre:
            by_technique[tid].append(rule)
    techniques = []
    for tid in sorted(by_technique):
        mapped = by_technique[tid]
        techniques.append({
            "techniqueID": tid,
            "score": len(mapped),
            "enabled": True,
            "comment": "Rules: " + ", ".join(f"{r.id} (level {r.level})" for r in mapped),
            "metadata": [{"name": r.id, "value": f"level {r.level} - {r.description}"} for r in mapped],
            "showSubtechniques": any(other.startswith(tid + ".") for other in by_technique),
        })
    for parent in sorted({tid.split(".")[0] for tid in by_technique if "." in tid} - set(by_technique)):
        techniques.append({"techniqueID": parent, "enabled": True, "showSubtechniques": True})
    techniques.sort(key=lambda t: t["techniqueID"])
    top = max((t.get("score", 0) for t in techniques), default=1)
    return {
        "name": "InsurCo SOC lab - detection coverage",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": (
            f"{len(by_technique)} techniques covered by {sum(1 for r in rules if r.mitre)} custom Wazuh rules "
            "(insurance-soc-lab). Score = number of rules mapped to the technique; every rule has a "
            "positive and a negative test against the real engine. Generated from "
            "detection/rules/insurco_rules.xml by scripts/gen_mitre_layer.py - do not edit by hand."
        ),
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": COLOURS, "minValue": 1, "maxValue": max(top, 2)},
        "legendItems": [{"label": f"{n} rule{'s' if n > 1 else ''}", "color": c}
                        for n, c in ((1, COLOURS[0]), (max(top, 2), COLOURS[-1]))],
        "metadata": [{"name": "techniques", "value": ", ".join(
            f"{tid} {MITRE.get(tid, '')}".strip() for tid in sorted(by_technique))}],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def render(rules: list[Rule]) -> str:
    return json.dumps(build_layer(rules), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if docs/mitre-layer.json is stale")
    args = parser.parse_args(argv)
    expected = render(parse_rules())
    current = LAYER.read_text(encoding="utf-8") if LAYER.exists() else ""
    if args.check:
        if current != expected:
            print(f"{LAYER.relative_to(ROOT).as_posix()} is stale: run python scripts/gen_mitre_layer.py",
                  file=sys.stderr)
            return 1
        print("MITRE layer up to date")
        return 0
    Path(LAYER).write_text(expected, encoding="utf-8", newline="\n")
    print(f"wrote {LAYER.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
