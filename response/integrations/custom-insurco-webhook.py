"""Wazuh custom integration: POST an alert to a chat-style webhook (insurance-soc-lab).

wazuh-integratord runs it once per alert that matches its <integration> block
(stack/config/wazuh_cluster/wazuh_manager.conf: level >= 12, JSON format) through the
shell wrapper `custom-insurco-webhook`, with the manager's bundled Python (3.10, standard
library only):

    custom-insurco-webhook <alert file> <api key> <hook url> [debug]

The message is Slack / Mattermost / Rocket.Chat compatible (`text`), so the same script
can point at a self-hosted chat channel; the `alert` object carries the fields an analyst
needs first, with the runbook link of the rule (`<info type="link">`). In the lab the
hook is the `webhook-receiver` container (response/webhook-receiver/), so it works offline.

Never raises on a delivery problem (integratord would only log a bare exit code): it
logs to logs/integrations.log and exits non-zero. Tests: response/tests/.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MIN_LEVEL = 12  # same threshold as <level> in the <integration> block (defence in depth)
TIMEOUT = 5  # seconds per attempt
ATTEMPTS = 3
RETRY_DELAY = 1.0
MAX_LOG_CHARS = 1000  # full_log is attacker-controlled and can be long
USER_AGENT = "insurco-wazuh-webhook/1.0"

# Exit codes (also written to integrations.log)
OK, ERR_ARGS, ERR_ALERT, ERR_SEND = 0, 2, 3, 4

LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "integrations.log"


def log(message: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} custom-insurco-webhook: {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def _first(*values):
    return next((v for v in values if v not in (None, "", [])), None)


def runbook_of(rule: dict) -> str | None:
    """The rule's <info type="link">, if any (Wazuh puts it in rule.info)."""
    info = rule.get("info")
    if isinstance(info, str) and info.startswith(("https://", "http://")):
        return info
    return None


def build_message(alert: dict) -> dict:
    """Chat message for one alert: a one-line `text` plus a structured `alert` object."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    level = int(rule.get("level", 0))
    srcip = _first(data.get("srcip"), data.get("IpAddress"), data.get("source_ip"))
    user = _first(data.get("dstuser"), data.get("srcuser"), data.get("db_user"), data.get("account"),
                  data.get("TargetUserName"))
    summary = {
        "id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "level": level,
        "rule_id": str(rule.get("id", "")),
        "description": rule.get("description", ""),
        "groups": rule.get("groups", []),
        "mitre": rule.get("mitre", {}).get("id", []),
        "agent": agent.get("name"),
        "srcip": srcip,
        "user": user,
        "runbook": runbook_of(rule),
        "location": alert.get("location"),
        "full_log": (alert.get("full_log") or "")[:MAX_LOG_CHARS],
    }
    text = f"[level {level}] {summary['description']} (rule {summary['rule_id']}, {summary['agent'] or '?'})"
    if summary["runbook"]:
        text += f" - runbook: {summary['runbook']}"
    return {"username": "wazuh", "text": text, "alert": summary}


def send(message: dict, url: str, api_key: str = "", attempts: int = ATTEMPTS,
         timeout: float = TIMEOUT, retry_delay: float = RETRY_DELAY) -> int:
    """POST the message; retry on network errors and 5xx. Returns the final HTTP status (0 = no answer)."""
    body = json.dumps(message).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    status = 0
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # URL from ossec.conf, http(s) checked
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except (urllib.error.URLError, OSError) as exc:
            status = 0
            log(f"attempt {attempt}/{attempts}: {url} unreachable: {exc}")
        if 200 <= status < 300 or 400 <= status < 500:  # done, or a 4xx a retry will not fix
            return status
        if attempt < attempts:
            time.sleep(retry_delay)
    return status


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        log(f"bad arguments ({len(argv) - 1}): expected <alert file> <api key> <hook url>")
        return ERR_ARGS
    alert_file, api_key, url = argv[1], argv[2], argv[3]
    if not url.startswith(("http://", "https://")):
        log(f"refusing hook url {url!r}: http(s) only")
        return ERR_ARGS
    try:
        with open(alert_file, encoding="utf-8") as fh:
            alert = json.load(fh)
    except (OSError, ValueError) as exc:
        log(f"cannot read alert {alert_file}: {exc}")
        return ERR_ALERT
    level = int(alert.get("rule", {}).get("level", 0))
    if level < MIN_LEVEL:
        log(f"skipped alert {alert.get('id')}: level {level} < {MIN_LEVEL}")
        return OK
    message = build_message(alert)
    # integratord passes the literal string "None" (or nothing) when <api_key> is not set
    status = send(message, url, "" if api_key in ("", "None") else api_key)
    rule_id = message["alert"]["rule_id"]
    if 200 <= status < 300:
        if len(argv) > 4 and argv[4] == "debug":
            log(f"sent alert {alert.get('id')} rule {rule_id} -> HTTP {status}")
        return OK
    log(f"FAILED alert {alert.get('id')} rule {rule_id} -> HTTP {status or 'no answer'}")
    return ERR_SEND


if __name__ == "__main__":
    os.umask(0o027)
    sys.exit(main(sys.argv))
