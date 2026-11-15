"""The response configuration in git says what docs/response.md says (no Docker needed).

The live behaviour (alert -> webhook -> block -> expiry) is checked on a running lab by
scripts/check_response.py.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MANAGER_CONF = ROOT / "stack" / "config" / "wazuh_cluster" / "wazuh_manager.conf"
RULES = ROOT / "detection" / "rules" / "insurco_rules.xml"
COMPOSE = ROOT / "docker-compose.yml"
WRAPPER = ROOT / "response" / "integrations" / "custom-insurco-webhook"
RUNBOOK_INDEX = ROOT / "docs" / "runbooks" / "README.md"

BLOCK_RULE, BLOCK_SECONDS = "100101", 600
BLOCKING_HOSTS = {"srv-linux-01", "real-linux-01"}  # the hosts whose logs can raise 100101


@pytest.fixture(scope="module")
def conf() -> ET.Element:
    # The file holds several <ossec_config> blocks: wrap them in one root
    return ET.fromstring(f"<root>{MANAGER_CONF.read_text(encoding='utf-8')}</root>")


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rules() -> dict[str, ET.Element]:
    root = ET.fromstring(RULES.read_text(encoding="utf-8"))
    return {r.get("id"): r for r in root.iter("rule")}


def _text(node: ET.Element, tag: str) -> str:
    return (node.findtext(tag) or "").strip()


def test_one_active_response_block_firewall_drop_on_100101(conf):
    blocks = conf.findall(".//active-response")
    assert len(blocks) == 1, "one active response in the lab: the 100101 block (docs/response.md)"
    ar = blocks[0]
    assert _text(ar, "disabled") in ("", "no")
    assert _text(ar, "command") == "firewall-drop"
    assert _text(ar, "location") == "local", "block on the targeted host only, never on every agent"
    assert _text(ar, "rules_id") == BLOCK_RULE
    assert int(_text(ar, "timeout")) == BLOCK_SECONDS
    command = next(c for c in conf.findall(".//command") if _text(c, "name") == "firewall-drop")
    assert _text(command, "timeout_allowed") == "yes", "without it, execd never removes the block"


def test_blocking_rule_is_a_high_confidence_compromise(rules):
    """Blocking on a single failed login would let anyone lock a partner out: only 100101."""
    rule = rules[BLOCK_RULE]
    assert int(rule.get("level")) >= 12
    assert _text(rule, "if_matched_sid") == "100100" and rule.find("same_source_ip") is not None


def test_manager_never_blocks_itself(conf):
    assert "127.0.0.1" in [w.text.strip() for w in conf.findall(".//global/white_list")]


def test_integration_routes_level_12_to_the_receiver(conf, hook, receiver_mod):
    blocks = conf.findall(".//integration")
    assert len(blocks) == 1
    integ = blocks[0]
    assert _text(integ, "name") == WRAPPER.name and _text(integ, "name").startswith("custom-")
    assert int(_text(integ, "level")) == hook.MIN_LEVEL == 12
    assert _text(integ, "alert_format") == "json"
    url = urlparse(_text(integ, "hook_url"))
    assert (url.scheme, url.hostname, url.port, url.path) == ("http", "webhook-receiver", 8080,
                                                             receiver_mod.HOOK_PATH)


def test_integration_files_are_mounted_and_executable(compose):
    mounts = compose["services"]["wazuh.manager"]["volumes"]
    for name in (WRAPPER.name, WRAPPER.name + ".py"):
        assert f"./response/integrations/{name}:/wazuh-config-mount/integrations/{name}:ro" in mounts
    text = WRAPPER.read_bytes()
    assert text.startswith(b"#!/bin/sh\n") and b"\r\n" not in text
    try:
        listing = subprocess.run(["git", "ls-files", "-s", str(WRAPPER.relative_to(ROOT))], cwd=ROOT,
                                 capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    if listing:  # tracked: integratord runs it directly, so git must keep the exec bit
        assert listing.startswith("100755"), "git update-index --chmod=+x " + WRAPPER.name


def test_receiver_publishes_the_viewer_only_on_localhost(compose):
    svc = compose["services"]["webhook-receiver"]
    assert svc["ports"] == ["127.0.0.1:8088:8081"], "ingest :8080 must stay on the lab network"
    assert "soc" in svc["networks"]


def test_only_the_ssh_hosts_get_net_admin(compose):
    with_net_admin = {name for name, svc in compose["services"].items() if "NET_ADMIN" in svc.get("cap_add", [])}
    assert with_net_admin == BLOCKING_HOSTS
    for svc in compose["services"].values():
        assert not svc.get("privileged"), "never privileged: NET_ADMIN on the container's own namespace is enough"
        assert svc.get("network_mode") != "host"


def test_runbook_index_names_every_webhook_rule(rules):
    """docs/runbooks/README.md says which rules reach the webhook: keep it true."""
    index = RUNBOOK_INDEX.read_text(encoding="utf-8")
    column = " ".join(re.findall(r"\| ([^|]*webhook[^|]*) \|$", index, re.MULTILINE))
    listed = set(re.findall(r"\b1001\d\d\b", column))
    expected = {rid for rid, r in rules.items() if int(r.get("level")) >= 12}
    assert listed == expected


def test_detection_runner_mounts_the_integration_like_compose():
    """run_tests.py starts throwaway managers with the lab config: it needs the script too."""
    import sys
    sys.path.insert(0, str(ROOT / "detection" / "tests"))
    import run_tests

    mounts = " ".join(run_tests.lab_mounts())
    for name in (WRAPPER.name, WRAPPER.name + ".py"):
        assert f"/wazuh-config-mount/integrations/{name}:ro" in mounts
