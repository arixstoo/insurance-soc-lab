#!/usr/bin/env python3
"""webhook-receiver: the lab's offline stand-in for a chat channel (insurance-soc-lab).

Two listeners, standard library only:

- ingest (INGEST_PORT, default 8080, lab network only, NOT published):
    POST /hooks/wazuh   JSON message from the Wazuh integration custom-insurco-webhook
    GET  /healthz
- viewer (VIEW_PORT, default 8081, published on 127.0.0.1:8088 by compose), read-only:
    GET  /                  HTML list, newest first, refreshes every 10 s
    GET  /api/messages      JSON list, newest first (?after=<seq> for newer ones only)
    GET  /healthz

Messages are appended to DATA_DIR/messages.jsonl (a volume), the last MAX_MESSAGES are
kept in memory and reloaded at start. Alert text is attacker-controlled (web payloads,
user names): the page escapes everything and runs no script (Content-Security-Policy).
"""

from __future__ import annotations

import html
import json
import os
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MAX_BODY = 256 * 1024
MAX_MESSAGES = 1000
HOOK_PATH = "/hooks/wazuh"
CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class Store:
    """Append-only JSONL file + the newest messages in memory. Thread-safe."""

    def __init__(self, path: Path, keep: int = MAX_MESSAGES):
        self.path = path
        self.lock = threading.Lock()
        self.messages: deque[dict] = deque(maxlen=keep)
        self.seq = 0
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue  # a torn last line after a crash
                self.messages.append(record)
                self.seq = max(self.seq, int(record.get("seq", 0)))

    def add(self, message: dict, remote: str) -> dict:
        with self.lock:
            self.seq += 1
            record = {"seq": self.seq, "received": round(time.time(), 3), "remote": remote, "message": message}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            self.messages.append(record)
            return record

    def newest(self, after: int = 0, limit: int = MAX_MESSAGES) -> list[dict]:
        with self.lock:
            return [r for r in reversed(self.messages) if r["seq"] > after][:limit]


def _alert(record: dict) -> dict:
    alert = record.get("message", {}).get("alert")
    return alert if isinstance(alert, dict) else {}


def _safe_link(url: object) -> str:
    """An escaped <a> for http(s) URLs only (no javascript: or data: links)."""
    if isinstance(url, str) and url.startswith(("https://", "http://")):
        return f'<a href="{html.escape(url, quote=True)}" rel="noreferrer">runbook</a>'
    return ""


def render_page(records: list[dict]) -> str:
    e = html.escape
    rows = []
    for r in records:
        a = _alert(r)
        level = a.get("level", "")
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["received"]))
        text = r.get("message", {}).get("text", "") if not a else a.get("description", "")
        rows.append(
            f'<tr class="{"crit" if isinstance(level, int) and level >= 13 else ""}">'
            f"<td>{r['seq']}</td><td>{e(when)}</td><td>{e(str(level))}</td><td>{e(str(a.get('rule_id', '')))}</td>"
            f"<td>{e(str(text))}</td><td>{e(str(a.get('agent') or ''))}</td><td>{e(str(a.get('srcip') or ''))}</td>"
            f"<td>{e(str(a.get('user') or ''))}</td><td>{_safe_link(a.get('runbook'))}</td>"
            f"<td><details><summary>log</summary><pre>{e(str(a.get('full_log', '')))}</pre></details></td></tr>")
    body = "\n".join(rows) or '<tr><td colspan="10">No message yet. Alerts of level 12+ appear here.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="10">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>InsurCo SOC - alert channel</title>
<style>
body{{font:14px system-ui,sans-serif;margin:1rem;background:#fafafa;color:#222}}
table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid #ddd;padding:.35rem;text-align:left;
vertical-align:top}} th{{background:#eee}} tr.crit td{{background:#fdecea}}
pre{{white-space:pre-wrap;word-break:break-all;max-width:40rem}}
</style></head><body>
<h1>InsurCo SOC - alert channel (lab)</h1>
<p>Wazuh alerts of level 12 or more, posted by the integration <code>custom-insurco-webhook</code>.
Newest first, {len(records)} shown. JSON: <a href="/api/messages">/api/messages</a>.</p>
<table><thead><tr><th>#</th><th>Received</th><th>Level</th><th>Rule</th><th>Alert</th><th>Agent</th>
<th>Source IP</th><th>User</th><th></th><th>Log</th></tr></thead>
<tbody>
{body}
</tbody></table></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "insurco-webhook-receiver/1.0"
    sys_version = ""
    store: Store
    ingest = False  # True on the ingest listener only

    def log_message(self, fmt: str, *args) -> None:  # one line per request on stdout
        print(f"{self.address_string()} {'ingest' if self.ingest else 'view'} {fmt % args}", flush=True)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path == "/healthz":
            return self._json(HTTPStatus.OK, {"status": "ok", "messages": self.store.seq})
        if self.ingest:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "ingest listener: POST " + HOOK_PATH})
        if url.path == "/api/messages":
            try:
                after = int(parse_qs(url.query).get("after", ["0"])[0])
            except ValueError:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": "after must be an integer"})
            return self._json(HTTPStatus.OK, self.store.newest(after))
        if url.path == "/":
            return self._send(HTTPStatus.OK, render_page(self.store.newest(limit=200)).encode("utf-8"),
                              "text/html; charset=utf-8")
        return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def _body_length(self) -> int:
        try:
            return int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return -1

    def _discard_body(self) -> None:
        """Read the body of a request rejected before parsing it. Closing a socket that still holds
        unread data sends a TCP reset, and the client may lose the response; a body too large to
        read is not read and the connection is closed instead."""
        length = self._body_length()
        if 0 < length <= MAX_BODY:
            self.rfile.read(length)
        elif length != 0:
            self.close_connection = True

    def do_POST(self) -> None:
        if not self.ingest:
            self._discard_body()
            return self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "read-only listener"})
        if urlparse(self.path).path != HOOK_PATH:
            self._discard_body()
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        length = self._body_length()
        if length <= 0 or length > MAX_BODY:
            self.close_connection = True  # the unread body must not be parsed as a next request
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE if length > MAX_BODY else HTTPStatus.LENGTH_REQUIRED,
                              {"error": f"body must be 1..{MAX_BODY} bytes"})
        try:
            message = json.loads(self.rfile.read(length))
        except ValueError:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
        if not isinstance(message, dict):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "expected a JSON object"})
        record = self.store.add(message, self.client_address[0])
        return self._json(HTTPStatus.CREATED, {"seq": record["seq"]})

    def _not_allowed(self) -> None:
        self._discard_body()
        self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})

    do_PUT = do_DELETE = do_PATCH = _not_allowed


def make_server(store: Store, port: int, ingest: bool, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    handler = type("IngestHandler" if ingest else "ViewHandler", (Handler,), {"store": store, "ingest": ingest})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main() -> None:
    store = Store(Path(os.environ.get("DATA_DIR", "/data")) / "messages.jsonl")
    ingest = make_server(store, int(os.environ.get("INGEST_PORT", "8080")), ingest=True)
    view = make_server(store, int(os.environ.get("VIEW_PORT", "8081")), ingest=False)
    print(f"webhook-receiver: ingest :{ingest.server_port}{HOOK_PATH}, viewer :{view.server_port}, "
          f"{store.seq} stored messages", flush=True)
    threading.Thread(target=ingest.serve_forever, daemon=True).start()
    view.serve_forever()


if __name__ == "__main__":
    main()
