"""docs/mitre-layer.json is generated from the rules XML: keep it in sync (no Docker)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import gen_catalog as gc  # noqa: E402
import gen_mitre_layer as gm  # noqa: E402

RULES = gc.parse_rules()


def test_layer_is_up_to_date():
    assert gm.LAYER.read_text(encoding="utf-8") == gm.render(RULES), "run: python scripts/gen_mitre_layer.py"


def test_score_is_the_number_of_rules_per_technique():
    layer = gm.build_layer(RULES)
    scores = {t["techniqueID"]: t.get("score") for t in layer["techniques"]}
    for tid, score in scores.items():
        if score is not None:
            assert score == sum(tid in r.mitre for r in RULES), tid
    assert set(scores) >= {tid for r in RULES for tid in r.mitre}


def test_parent_of_an_unscored_subtechnique_is_expanded():
    rules = [gc.Rule(id="1", level=5, description="x", groups=[], mitre=["T1548.003"])]
    by_id = {t["techniqueID"]: t for t in gm.build_layer(rules)["techniques"]}
    assert by_id["T1548"] == {"techniqueID": "T1548", "enabled": True, "showSubtechniques": True}
    assert by_id["T1548.003"]["score"] == 1


def test_layer_is_valid_navigator_json():
    layer = json.loads(gm.LAYER.read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    assert layer["gradient"]["minValue"] < layer["gradient"]["maxValue"]
