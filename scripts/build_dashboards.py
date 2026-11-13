#!/usr/bin/env python3
"""Build the two InsurCo dashboards through the Dashboards saved-objects API.

    python scripts/build_dashboards.py            # create/overwrite them in the running lab,
                                                  # then export them to dashboards/*.ndjson
    python scripts/build_dashboards.py --no-export   # only create/overwrite them in the lab

The panels are defined here, in code. The objects are sent to the running dashboard
(`_bulk_create?overwrite=true`) and then exported back with `_export`, so the files in
dashboards/ are exactly what OpenSearch Dashboards produces (migrations applied), not
hand-written JSON. scripts/import_dashboards.py loads those files into a fresh lab.

Every rule.id / rule.groups value used in a query must be a rule that a detection test
proves (detection/tests/test_dashboards.py). Queries use only the KQL forms
`rule.id:100100`, `rule.id:(100100 or 100101)`, `rule.groups:name`,
`rule.groups:(a or b)` so that the test can read them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from indexer_client import ROOT, dashboard_request, indexer_password

OUT = ROOT / "dashboards"
OSD_VERSION = "2.19.6"  # wazuh-dashboard 4.14.9

# One index pattern of our own (fixed id), so the dashboards do not depend on the Wazuh
# app having created its pattern (it does so only when a user opens the app).
INDEX_PATTERN_ID = "insurco-alerts"
LAB_TZ_DEFAULT = "Africa/Algiers"  # replaced by LAB_TZ at import (import_dashboards.py)
HOUR_FIELD = "hour_of_day"
HOUR_SCRIPT = (
    "if (doc['timestamp'].size() == 0) { return null; } "
    f"return doc['timestamp'].value.withZoneSameInstant(ZoneId.of('{LAB_TZ_DEFAULT}')).getHour();"
)
# Only the scripted field is stored. Without `readFromDocValues` the field list counts
# as incomplete, so the dashboard reads the real fields from the live mapping on load.
SCRIPTED_FIELDS = [{
    "name": HOUR_FIELD, "type": "number", "count": 0, "scripted": True,
    "script": HOUR_SCRIPT, "lang": "painless", "searchable": True, "aggregatable": True,
}]

CRITICAL = "rule.level >= 12"  # same threshold as the phase 6 alert routing
CUSTOM = "rule.groups:insurco"
# Bulk reads: simulated DB audit (100131 / 100133) and real pgaudit trail (100137 / 100138)
DAY_READ = "rule.id:(100131 or 100137)"
NIGHT_READ = "rule.id:(100133 or 100138)"

# Colours (OUI palette): one meaning per colour across both dashboards.
RED, ORANGE, YELLOW, BLUE, GREY, PURPLE, TEAL = (
    "#BD271E", "#E7664C", "#D6BF57", "#6092C0", "#98A2B3", "#9170B8", "#54B399")


# ---------------------------------------------------------------- aggregation helpers
def _agg(n: int, type_: str, schema: str, **params: Any) -> dict:
    return {"id": str(n), "enabled": True, "type": type_, "schema": schema, "params": params}


def count(label: str = "") -> dict:
    return _agg(1, "count", "metric", **({"customLabel": label} if label else {}))


def terms(n: int, field: str, schema: str, size: int = 10, label: str = "") -> dict:
    return _agg(n, "terms", schema, field=field, size=size, order="desc", orderBy="1",
                otherBucket=False, missingBucket=False, customLabel=label)


def date_hist(n: int = 2, schema: str = "segment") -> dict:
    return _agg(n, "date_histogram", schema, field="timestamp", interval="auto", min_doc_count=1,
                extended_bounds={}, useNormalizedOpenSearchInterval=True, drop_partials=False)


def filters(n: int, schema: str, items: list[tuple[str, str]]) -> dict:
    return _agg(n, "filters", schema, filters=[
        {"input": {"query": q, "language": "kuery"}, "label": label} for label, q in items])


LEVELS = [  # rule.level bands (Wazuh scale 0-15)
    ("Low (0-6)", "rule.level < 7", GREY),
    ("Medium (7-11)", "rule.level >= 7 and rule.level < 12", YELLOW),
    ("High (12-14)", "rule.level >= 12 and rule.level < 15", ORANGE),
    ("Critical (15)", "rule.level >= 15", RED),
]


# ---------------------------------------------------------------- saved objects
def _search_source(query: str, with_index: bool = True) -> str:
    source: dict[str, Any] = {"query": {"query": query, "language": "kuery"}, "filter": []}
    if with_index:
        source["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    return json.dumps(source)


INDEX_REF = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern",
              "id": INDEX_PATTERN_ID}]


def vis(id_: str, title: str, type_: str, aggs: list[dict], query: str = "",
        params: dict | None = None, colors: dict[str, str] | None = None, description: str = "") -> dict:
    state = {"title": title, "type": type_, "params": {"type": type_, **(params or {})}, "aggs": aggs}
    ui = {"vis": {"colors": colors}} if colors else {}
    return {
        "type": "visualization", "id": id_,
        "attributes": {
            "title": title, "description": description, "version": 1,
            "visState": json.dumps(state), "uiStateJSON": json.dumps(ui),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
        },
        "references": INDEX_REF,
    }


def saved_search(id_: str, title: str, query: str, columns: list[str], description: str = "") -> dict:
    return {
        "type": "search", "id": id_,
        "attributes": {
            "title": title, "description": description, "hits": 0, "version": 1,
            "columns": columns, "sort": [["timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
        },
        "references": INDEX_REF,
    }


def dashboard(id_: str, title: str, description: str, panels: list[tuple[dict, int, int, int, int]]) -> dict:
    """panels: (saved object, x, y, w, h) on the 48-column grid."""
    panels_json, refs = [], []
    for i, (obj, x, y, w, h) in enumerate(panels):
        panels_json.append({"version": OSD_VERSION, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                            "panelIndex": str(i), "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": obj["type"], "id": obj["id"]})
    return {
        "type": "dashboard", "id": id_,
        "attributes": {
            "title": title, "description": description, "hits": 0, "version": 1,
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 60000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source("", with_index=False)},
        },
        "references": refs,
    }


def index_pattern() -> dict:
    return {
        "type": "index-pattern", "id": INDEX_PATTERN_ID,
        "attributes": {"title": "wazuh-alerts-*", "timeFieldName": "timestamp",
                       "fields": json.dumps(SCRIPTED_FIELDS)},
        "references": [],
    }


METRIC_LABELS = {"type": "metric", "addTooltip": True, "addLegend": False, "metric": {
    "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
    "metricColorMode": "Labels", "colorsRange": [{"from": 0, "to": 1}, {"from": 1, "to": 1_000_000}],
    "labels": {"show": True}, "invertColors": False,
    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 36}}}
# The heatmap editor needs the full parameter set (valueAxes included): no defaults are merged.
HEATMAP = {"type": "heatmap", "addTooltip": True, "addLegend": True, "enableHover": False,
           "legendPosition": "right", "times": [], "colorsNumber": 5, "colorSchema": "Reds",
           # explicit bands: only an empty hour is near-white, a single alert is already visible
           "setColorRange": True, "colorsRange": [{"from": 0, "to": 1}, {"from": 1, "to": 3}, {"from": 3, "to": 10},
                                                  {"from": 10, "to": 30}, {"from": 30, "to": 100000}],
           "invertColors": False, "percentageMode": False,
           "valueAxes": [{"show": False, "id": "ValueAxis-1", "type": "value",
                          "scale": {"type": "linear", "defaultYExtents": False},
                          "labels": {"show": False, "rotate": 0, "overwriteColor": False, "color": "black"}}]}
METRIC_PLAIN = {**METRIC_LABELS, "metric": {**METRIC_LABELS["metric"], "metricColorMode": "None"}}


# ---------------------------------------------------------------- SOC Overview
def soc_overview() -> list[dict]:
    p = "insurco-soc-"
    volume = vis(p + "volume", "Alert volume", "metric", [
        count("alerts"), filters(2, "group", [("All", "*"), ("InsurCo custom detections", CUSTOM)])],
        params=METRIC_PLAIN, description="Every alert indexed, and the share raised by the custom rules.")
    critical = vis(p + "critical", "Critical alerts (level 12+)", "metric", [count("Level 12+")],
                   query=CRITICAL, params=METRIC_LABELS,
                   description="rule.level >= 12: the threshold that pages an analyst (phase 6 routing).")
    timeline = vis(p + "timeline-level", "Alerts over time by level", "histogram", [
        count(), date_hist(), filters(3, "group", [(label, q) for label, q, _ in LEVELS])],
        colors={label: colour for label, _, colour in LEVELS})
    top_rules = vis(p + "top-rules", "Top rules", "table", [
        count("Alerts"), terms(2, "rule.id", "bucket", 20, "Rule"),
        _agg(3, "max", "metric", field="rule.level", customLabel="Level"),
        _agg(4, "top_hits", "metric", field="rule.description", aggregate="concat", size=1,
             sortField="timestamp", sortOrder="desc", customLabel="Description (latest)")],
        params={"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False})
    top_ips = vis(p + "top-srcip", "Top source IPs (alerts level 7+)", "horizontal_bar", [
        count(), terms(2, "data.srcip", "segment", 10, "Source IP")], query="rule.level >= 7",
        description="data.srcip (SSH, web, DB client). Windows events carry the address in data.IpAddress.")
    per_agent = vis(p + "per-agent", "Alerts per agent", "pie", [
        count(), terms(2, "agent.name", "segment", 10, "Agent")], params={"isDonut": True})
    return [volume, critical, timeline, top_rules, top_ips, per_agent, dashboard(
        "insurco-soc-overview", "InsurCo - SOC Overview",
        "What an analyst checks first: how much, how bad, since when, which rules, from where, on which host.",
        [(volume, 0, 0, 16, 9), (critical, 16, 0, 10, 9), (per_agent, 26, 0, 22, 18),
         (timeline, 0, 9, 26, 18), (top_ips, 26, 18, 22, 20), (top_rules, 0, 27, 26, 20)])]


# ---------------------------------------------------------------- Insurer Security
def insurer_security() -> list[dict]:
    p = "insurco-sec-"
    insider_q = "rule.groups:(insurco_bulk_read or insider_threat)"
    insider_kpi = vis(p + "insider-kpi", "Customer data access", "metric", [count("alerts"), filters(2, "group", [
        ("Bulk reads (day)", DAY_READ), ("Bulk reads at night", NIGHT_READ),
        ("Mass access = insider", "rule.id:(100132 or 100134)")])], params=METRIC_LABELS)
    insider_who = vis(p + "insider-who", "Insider data access: who read which table", "table", [
        count("Alerts"), terms(2, "data.db_user", "bucket", 10, "DB user"),
        terms(3, "data.table", "bucket", 5, "Table")], query=insider_q,
        params={"perPage": 10, "showPartialRows": False})
    insider_time = vis(p + "insider-time", "Customer data access over time", "histogram", [
        count(), date_hist(), filters(3, "group", [
            ("Bulk read (day)", DAY_READ), ("Bulk read at night", NIGHT_READ),
            ("Mass access (day)", "rule.id:100132"), ("Mass access at night", "rule.id:100134")])],
        colors={"Bulk read (day)": BLUE, "Bulk read at night": PURPLE,
                "Mass access (day)": ORANGE, "Mass access at night": RED})
    brute_kpi = vis(p + "brute-kpi", "Brute force -> compromise", "metric", [count("alerts"), filters(2, "group", [
        ("SSH brute force", "rule.id:100100"), ("Login right after brute force", "rule.id:100101"),
        ("Windows password guessing", "rule.id:100142")])], params=METRIC_LABELS)
    brute_ip = vis(p + "brute-ip", "Brute force -> compromise by source IP", "table", [
        count("Alerts"), terms(2, "data.srcip", "bucket", 10, "Source IP"),
        filters(3, "bucket", [("Brute force", "rule.id:100100"), ("COMPROMISE", "rule.id:100101")])],
        query="rule.id:(100100 or 100101)", params={"perPage": 10, "showPartialRows": False},
        description="An IP with a COMPROMISE row logged in successfully right after guessing.")
    web_time = vis(p + "web-time", "Web attack campaigns by technique", "histogram", [
        count(), date_hist(), filters(3, "group", [
            ("SQL injection", "rule.groups:sqli"), ("XSS", "rule.groups:xss"),
            ("Path traversal", "rule.groups:path_traversal"), ("Secret / backup probing", "rule.groups:web_scan"),
            ("Coordinated campaign", "rule.groups:coordinated_attack")])],
        query="rule.groups:insurco_web",
        colors={"SQL injection": ORANGE, "XSS": YELLOW, "Path traversal": PURPLE,
                "Secret / backup probing": TEAL, "Coordinated campaign": RED})
    web_ip = vis(p + "web-ip", "Web attackers", "table", [
        count("Alerts"), terms(2, "data.srcip", "bucket", 10, "Source IP"),
        terms(3, "rule.description", "bucket", 5, "Detection")], query="rule.groups:insurco_web",
        params={"perPage": 10, "showPartialRows": False})
    priv = saved_search(p + "privilege-changes", "Privilege changes",
                        "rule.id:(100110 or 100143 or 100144 or 100145)",
                        ["rule.id", "rule.level", "rule.description", "agent.name",
                         "data.srcuser", "data.SubjectUserName", "data.account"],
                        description="Root shells via sudo, new accounts, admin group additions, and the "
                                    "created-then-promoted correlation.")
    heatmap = vis(p + "heatmap-hour", "Activity by hour of day (lab time zone)", "heatmap", [
        count(), _agg(2, "histogram", "segment", field=HOUR_FIELD, interval=1, min_doc_count=True,
                      has_extended_bounds=True, extended_bounds={"min": 0, "max": 23}, customLabel="Hour"),
        filters(3, "group", [
            ("Authentication", "rule.groups:insurco_auth"), ("Privilege", "rule.groups:insurco_privesc"),
            ("Web", "rule.groups:insurco_web"), ("Customer data", "rule.groups:insurco_db"),
            ("Windows", "rule.groups:insurco_windows")])],
        query=CUSTOM, params=HEATMAP,
        description="Custom detections per hour (00-23, LAB_TZ). Office hours are 08:00-18:00.")
    return [insider_kpi, insider_who, insider_time, brute_kpi, brute_ip, web_time, web_ip, priv, heatmap,
            dashboard(
                "insurco-insurer-security", "InsurCo - Insurer Security",
                "Threats specific to an insurer: customer-data misuse, account takeover, attacks on "
                "the business web apps, privilege changes, and when they happen.",
                [(insider_kpi, 0, 0, 24, 9), (brute_kpi, 24, 0, 24, 9),
                 (insider_who, 0, 9, 20, 18), (insider_time, 20, 9, 28, 18),
                 (brute_ip, 0, 27, 20, 18), (web_time, 20, 27, 28, 18),
                 (web_ip, 0, 45, 20, 18), (heatmap, 20, 45, 28, 18),
                 (priv, 0, 63, 48, 16)])]


DASHBOARDS = {"soc-overview": soc_overview, "insurer-security": insurer_security}


# ---------------------------------------------------------------- API
def normalise(ndjson: str) -> str:
    """Stable, environment-free export: no summary line, timestamps or versions; sorted."""
    objects = []
    for line in ndjson.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if "exportedCount" in obj:
            continue
        obj.pop("updated_at", None)
        obj.pop("version", None)
        if obj["type"] == "index-pattern":
            obj["attributes"]["fields"] = json.dumps(SCRIPTED_FIELDS)
            obj["attributes"].pop("fieldFormatMap", None)
        objects.append(obj)
    order = {"index-pattern": 0, "search": 1, "visualization": 2, "dashboard": 3}
    objects.sort(key=lambda o: (order.get(o["type"], 9), o["id"]))
    return "".join(json.dumps(o, sort_keys=True, ensure_ascii=False) + "\n" for o in objects)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-export", action="store_true", help="do not rewrite dashboards/*.ndjson")
    args = parser.parse_args(argv)
    password = indexer_password()

    for slug, build in DASHBOARDS.items():
        objects = [index_pattern(), *build()]
        status, body = dashboard_request("POST", "/api/saved_objects/_bulk_create?overwrite=true",
                                         "admin", password, objects)
        errors = [o for o in (body or {}).get("saved_objects", []) if "error" in o] if status == 200 else []
        if status != 200 or errors:
            print(f"{slug}: bulk create failed: HTTP {status} {errors or body}", file=sys.stderr)
            return 1
        print(f"{slug}: {len(objects)} saved objects created/overwritten")
        if args.no_export:
            continue
        dash_id = objects[-1]["id"]
        status, body = dashboard_request("POST", "/api/saved_objects/_export", "admin", password,
                                         {"objects": [{"type": "dashboard", "id": dash_id}],
                                          "includeReferencesDeep": True})
        if isinstance(body, dict) and status == 200:  # a one-object export parses as plain JSON
            body = json.dumps(body)
        if status != 200 or not isinstance(body, str):
            print(f"{slug}: export failed: HTTP {status} {body}", file=sys.stderr)
            return 1
        path: Path = OUT / f"{slug}.ndjson"
        OUT.mkdir(exist_ok=True)
        path.write_text(normalise(body), encoding="utf-8", newline="\n")
        print(f"  exported -> {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
