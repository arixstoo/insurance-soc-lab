"""custom-insurco-webhook: message format, level filter, delivery, retries, failures."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture(autouse=True)
def _log_to_tmp(hook, tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "LOG_FILE", tmp_path / "integrations.log")
    monkeypatch.setattr(hook, "RETRY_DELAY", 0.01)


def write_alert(tmp_path, alert) -> str:
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(alert), encoding="utf-8")
    return str(path)


def test_message_carries_what_the_analyst_needs_first(hook, alert_100101):
    msg = hook.build_message(alert_100101)
    a = msg["alert"]
    assert (a["rule_id"], a["level"], a["agent"], a["srcip"], a["user"]) == (
        "100101", 14, "srv-linux-01", "203.0.113.45", "svc_backup")
    assert a["runbook"].endswith("/docs/runbooks/ssh-brute-force.md")
    assert a["mitre"] == ["T1110.001", "T1078"]
    # Slack / Mattermost compatible one-liner
    assert msg["text"].startswith("[level 14] InsurCo - CRITICAL") and "rule 100101" in msg["text"]
    assert "runbook: https://" in msg["text"]


def test_message_fields_for_other_families(hook):
    win = {"rule": {"id": "100145", "level": 15, "description": "x"}, "agent": {"name": "ws-claims-01"},
           "data": {"account": "tmp_123", "IpAddress": "10.20.10.9"}}
    a = hook.build_message(win)["alert"]
    assert (a["user"], a["srcip"], a["runbook"]) == ("tmp_123", "10.20.10.9", None)


def test_runbook_must_be_http(hook):
    assert hook.runbook_of({"info": "javascript:alert(1)"}) is None
    assert hook.runbook_of({}) is None


def test_full_log_is_truncated(hook, alert_100101):
    alert_100101["full_log"] = "A" * 50_000
    assert len(hook.build_message(alert_100101)["alert"]["full_log"]) == hook.MAX_LOG_CHARS


def test_alert_reaches_the_receiver(hook, receiver, alert_100101, tmp_path):
    """The whole lab path minus Wazuh: integration script -> receiver ingest -> viewer API."""
    store, ingest, view = receiver
    argv = ["custom-insurco-webhook", write_alert(tmp_path, alert_100101), "None", ingest + "/hooks/wazuh"]
    assert hook.main(argv) == hook.OK
    with urllib.request.urlopen(view + "/api/messages", timeout=5) as resp:
        messages = json.load(resp)
    assert len(messages) == 1
    assert messages[0]["message"]["alert"]["rule_id"] == "100101"
    assert messages[0]["remote"] == "127.0.0.1"


def test_below_threshold_is_not_sent(hook, receiver, tmp_path):
    store, ingest, _ = receiver
    low = {"id": "1", "rule": {"id": "100100", "level": 10, "description": "x"}}
    assert hook.main(["x", write_alert(tmp_path, low), "None", ingest + "/hooks/wazuh"]) == hook.OK
    assert store.newest() == []
    assert "level 10 < 12" in hook.LOG_FILE.read_text(encoding="utf-8")


class _Flaky(BaseHTTPRequestHandler):
    """Answers 500 to the first `fail` requests, then 201; remembers the headers."""

    calls = 0
    fail = 2
    headers_seen: list = []

    def do_POST(self):
        type(self).calls += 1
        type(self).headers_seen.append(dict(self.headers))
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(500 if type(self).calls <= type(self).fail else 201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def flaky():
    handler = type("Flaky", (_Flaky,), {"calls": 0, "headers_seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield handler, f"http://127.0.0.1:{server.server_port}/hook"
    server.shutdown()
    server.server_close()


def test_retries_on_server_errors(hook, flaky, alert_100101):
    handler, url = flaky
    assert hook.send(hook.build_message(alert_100101), url, attempts=3) == 201
    assert handler.calls == 3


def test_gives_up_after_the_last_attempt(hook, flaky, alert_100101, tmp_path):
    handler, url = flaky
    handler.fail = 99
    assert hook.main(["x", write_alert(tmp_path, alert_100101), "None", url]) == hook.ERR_SEND
    assert handler.calls == hook.ATTEMPTS
    assert "FAILED alert 1763199727.123456 rule 100101 -> HTTP 500" in hook.LOG_FILE.read_text(encoding="utf-8")


def test_api_key_becomes_a_bearer_token(hook, flaky, alert_100101, tmp_path):
    handler, url = flaky
    handler.fail = 0
    assert hook.main(["x", write_alert(tmp_path, alert_100101), "s3cret", url]) == hook.OK
    assert handler.headers_seen[-1]["Authorization"] == "Bearer s3cret"
    assert hook.main(["x", write_alert(tmp_path, alert_100101), "None", url]) == hook.OK
    assert "Authorization" not in handler.headers_seen[-1]


def test_unreachable_hook_is_logged_not_raised(hook, alert_100101, tmp_path):
    url = "http://127.0.0.1:9/hooks/wazuh"  # discard port: nothing listens
    assert hook.main(["x", write_alert(tmp_path, alert_100101), "None", url]) == hook.ERR_SEND
    assert "unreachable" in hook.LOG_FILE.read_text(encoding="utf-8")


@pytest.mark.parametrize("argv, code", [
    (["x", "a.json"], "ERR_ARGS"),
    (["x", "a.json", "None", "file:///etc/passwd"], "ERR_ARGS"),
    (["x", "/does/not/exist.json", "None", "http://127.0.0.1:9/"], "ERR_ALERT"),
])
def test_bad_input(hook, argv, code):
    assert hook.main(argv) == getattr(hook, code)
