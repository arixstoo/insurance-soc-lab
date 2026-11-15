"""webhook-receiver: ingest vs read-only viewer, storage, escaping of attacker-controlled text."""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from urllib.parse import urlparse


def call(url: str, method: str = "GET", body: bytes | None = None, ctype: str = "application/json"):
    req = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def post(ingest: str, message: dict):
    return call(ingest + "/hooks/wazuh", "POST", json.dumps(message).encode())


def test_post_is_stored_and_listed_newest_first(receiver):
    store, ingest, view = receiver
    for i in (1, 2, 3):
        status, _, body = post(ingest, {"text": f"m{i}"})
        assert status == 201 and json.loads(body) == {"seq": i}
    status, _, body = call(view + "/api/messages")
    assert status == 200
    assert [m["message"]["text"] for m in json.loads(body)] == ["m3", "m2", "m1"]
    _, _, body = call(view + "/api/messages?after=2")
    assert [m["seq"] for m in json.loads(body)] == [3]


def test_viewer_is_read_only_and_ingest_has_no_ui(receiver):
    _, ingest, view = receiver
    assert call(view + "/hooks/wazuh", "POST", b"{}")[0] == 405
    assert call(ingest + "/", "GET")[0] == 404
    assert call(ingest + "/api/messages")[0] == 404  # stored alerts are not readable from the lab network
    assert call(ingest + "/hooks/wazuh", "PUT", b"{}")[0] == 405
    assert call(ingest + "/healthz")[0] == 200 and call(view + "/healthz")[0] == 200


def test_rejects_bad_bodies(receiver, receiver_mod):
    store, ingest, _ = receiver
    assert call(ingest + "/hooks/wazuh", "POST", b"not json")[0] == 400
    assert call(ingest + "/hooks/wazuh", "POST", b"[1, 2]")[0] == 400
    # announce a too-large body: refused before reading it
    conn = http.client.HTTPConnection(urlparse(ingest).hostname, urlparse(ingest).port, timeout=5)
    conn.putrequest("POST", "/hooks/wazuh")
    conn.putheader("Content-Length", str(receiver_mod.MAX_BODY + 1))
    conn.endheaders()
    assert conn.getresponse().status == 413
    conn.close()
    assert call(ingest + "/elsewhere", "POST", b"{}")[0] == 404
    assert store.newest() == []


def test_page_escapes_attacker_controlled_text(receiver):
    """A web-campaign alert carries the attacker's XSS payload in full_log: it must stay text."""
    _, ingest, view = receiver
    payload = '<script>alert("x")</script><img src=x onerror=alert(1)>'
    post(ingest, {"text": "t", "alert": {"level": 13, "rule_id": "100129", "description": payload,
                                         "agent": payload, "full_log": payload,
                                         "runbook": "javascript:alert(1)"}})
    status, headers, body = call(view + "/")
    page = body.decode()
    assert status == 200
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page
    assert 'href="javascript:' not in page
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_runbook_link_is_shown(receiver):
    _, ingest, view = receiver
    url = "https://github.com/arixstoo/insurance-soc-lab/blob/main/docs/runbooks/ssh-brute-force.md"
    post(ingest, {"text": "t", "alert": {"level": 14, "rule_id": "100101", "runbook": url}})
    assert f'href="{url}"' in call(view + "/")[2].decode()


def test_messages_survive_a_restart(receiver_mod, tmp_path):
    path = tmp_path / "messages.jsonl"
    store = receiver_mod.Store(path)
    store.add({"text": "a"}, "10.0.0.1")
    store.add({"text": "b"}, "10.0.0.1")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"seq": 3, "torn')  # crash in the middle of a write
    again = receiver_mod.Store(path)
    assert [r["message"]["text"] for r in again.newest()] == ["b", "a"]
    assert again.add({"text": "c"}, "10.0.0.1")["seq"] == 3


def test_memory_is_bounded(receiver_mod, tmp_path):
    store = receiver_mod.Store(tmp_path / "m.jsonl", keep=5)
    for i in range(12):
        store.add({"text": str(i)}, "x")
    assert [r["seq"] for r in store.newest()] == [12, 11, 10, 9, 8]
