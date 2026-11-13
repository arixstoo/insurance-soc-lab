"""Tiny HTTPS client for the lab indexer and dashboard, standard library only.

The indexer is published on 127.0.0.1:9200 and the dashboard on 127.0.0.1:443,
but their certificates are issued to `wazuh.indexer` / `wazuh.dashboard`
(stack/config/certs.yml). We connect to 127.0.0.1 and verify the certificate
against the lab CA *for that name*, so TLS stays fully checked without editing
the hosts file.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CA_FILE = ROOT / "stack" / "certs" / "root-ca.pem"
HOST = os.environ.get("ISLAB_INDEXER_HOST", "127.0.0.1")
PORT = int(os.environ.get("ISLAB_INDEXER_PORT", "9200"))
TLS_NAME = "wazuh.indexer"
DASHBOARD_HOST = os.environ.get("ISLAB_DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.environ.get("ISLAB_DASHBOARD_PORT", "443"))
DASHBOARD_TLS_NAME = "wazuh.dashboard"


def read_env(path: Path = ROOT / ".env") -> dict[str, str]:
    """Parse KEY=VALUE lines of the compose .env file (no quoting rules needed here)."""
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    return values


def indexer_password() -> str:
    """INDEXER_PASSWORD from the environment, else from .env."""
    password = os.environ.get("INDEXER_PASSWORD") or read_env().get("INDEXER_PASSWORD")
    if not password:
        raise SystemExit("INDEXER_PASSWORD not found in the environment or .env (run scripts/rotate-passwords.sh)")
    return password


class _Connection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, tls_name: str, context: ssl.SSLContext, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._lab_context = context
        self._tls_name = tls_name

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._lab_context.wrap_socket(sock, server_hostname=self._tls_name)


def _send(
    target: tuple[str, int, str],
    method: str,
    path: str,
    user: str,
    password: str,
    payload: bytes | str | None,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int, Any]:
    context = ssl.create_default_context(cafile=str(CA_FILE))
    conn = _Connection(*target, context=context, timeout=timeout)
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", **headers}
    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read().decode("utf-8", errors="replace")
    finally:
        conn.close()
    try:
        return response.status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return response.status, raw


def request(
    method: str,
    path: str,
    user: str,
    password: str,
    body: Any | None = None,
    timeout: float = 15,
) -> tuple[int, Any]:
    """Send one request to the indexer; return (status, decoded JSON body or raw text)."""
    payload = json.dumps(body) if body is not None else None
    return _send((HOST, PORT, TLS_NAME), method, path, user, password, payload,
                 {"Content-Type": "application/json"}, timeout)


def dashboard_request(
    method: str,
    path: str,
    user: str,
    password: str,
    body: Any | None = None,
    timeout: float = 30,
    content_type: str = "application/json",
) -> tuple[int, Any]:
    """Send one request to the Dashboards HTTP API (adds the `osd-xsrf` header it requires).

    `body` is JSON-encoded unless it is already bytes (e.g. a multipart upload).
    """
    payload = body if isinstance(body, bytes) or body is None else json.dumps(body)
    headers = {"Content-Type": content_type, "osd-xsrf": "true"}
    return _send((DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_TLS_NAME), method, path, user, password,
                 payload, headers, timeout)
