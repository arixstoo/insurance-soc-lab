"""Shared fixtures: load the integration script and the receiver as modules, run a receiver."""

from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INTEGRATION = ROOT / "response" / "integrations" / "custom-insurco-webhook.py"
RECEIVER = ROOT / "response" / "webhook-receiver" / "receiver.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def hook():
    """The integration script (its file name has dashes: load it by path)."""
    return load("insurco_webhook", INTEGRATION)


@pytest.fixture(scope="session")
def receiver_mod():
    return load("insurco_receiver", RECEIVER)


@pytest.fixture
def receiver(receiver_mod, tmp_path):
    """A running receiver on two ephemeral ports: (store, ingest_url, view_url)."""
    store = receiver_mod.Store(tmp_path / "messages.jsonl")
    servers = [receiver_mod.make_server(store, 0, ingest=True, host="127.0.0.1"),
               receiver_mod.make_server(store, 0, ingest=False, host="127.0.0.1")]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    ingest, view = (f"http://127.0.0.1:{s.server_port}" for s in servers)
    yield store, ingest, view
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def alert_100101():
    """An alert as wazuh-integratord writes it (shape of a 4.14.9 alert, lab values)."""
    return {
        "timestamp": "2026-11-15T10:42:07.123+0100",
        "id": "1763199727.123456",
        "rule": {
            "level": 14,
            "description": "InsurCo - CRITICAL: successful SSH login from 203.0.113.45 right after a brute force",
            "id": "100101",
            "info": "https://github.com/arixstoo/insurance-soc-lab/blob/main/docs/runbooks/ssh-brute-force.md",
            "mitre": {"id": ["T1110.001", "T1078"]},
            "groups": ["insurco", "insurco_auth", "account_compromise"],
        },
        "agent": {"id": "001", "name": "srv-linux-01"},
        "manager": {"name": "wazuh.manager"},
        "full_log": "Nov 15 10:42:07 srv-linux-01 sshd[4242]: Accepted password for svc_backup from 203.0.113.45 "
                    "port 50522 ssh2",
        "decoder": {"name": "sshd"},
        "data": {"srcip": "203.0.113.45", "srcport": "50522", "dstuser": "svc_backup"},
        "location": "/var/log/insurco/auth.log",
    }
