#!/usr/bin/env python3
"""Live check of the response chain on a running lab (docs/response.md).

For each target, trigger a brute force that succeeds, then prove, in order:

  1. alert    100101 is in wazuh-alerts-* (indexer, TLS verified)
  2. webhook  the integration posted it to webhook-receiver (http://localhost:8088)
  3. block    firewall-drop added `-s <srcip>/32 -j DROP` to the targeted host's iptables,
              and (real host) a TCP connection from the attacker to sshd now times out
  4. expiry   execd removed the rule after the configured timeout (600 s): the measured
              add -> delete delay is printed and checked, and (real host) sshd answers again

Targets:
  simulated  `insurco-sim inject brute_force` -> srv-linux-01 (the attacker IP only exists
             in the log: nothing is really dropped, the rule is checked)
  real       `lab-traffic ssh` from real-client (10.20.60.50) -> real-linux-01 (real sshd,
             real packets dropped). Needs the compose profile `real`.

    python scripts/check_response.py                       # simulated, waits for the expiry (~11 min)
    python scripts/check_response.py --target both
    python scripts/check_response.py --no-expiry           # stop after the block (~1 min)
    python scripts/check_response.py --no-inject --lookback 1800 --target both
                                                           # after e2e.sh, which already triggered both

Note: rule 100100 has ignore="60", and Wazuh's `ignore` mutes the WHOLE rule, whatever the
source: a brute force less than 60 s after another one raises no 100100, hence no 100101. With
--target both the second trigger therefore waits that window out (found by this script: the
real brute force sent right after the simulated one raised nothing). If no 100101 arrives
anyway, the script waits the window out and retries once. The simulator's RANDOM attacks
(every 2-5 min, brute_force among them) open the same window at any time: for a
deterministic run, start the simulator without them, as the e2e workflow does:
    SIM_ATTACK_MIN=86400 SIM_ATTACK_MAX=86400 docker compose up -d simulator
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from indexer_client import indexer_password, request

ROOT = Path(__file__).resolve().parents[1]
MANAGER_CONF = ROOT / "stack" / "config" / "wazuh_cluster" / "wazuh_manager.conf"
RULES_XML = ROOT / "detection" / "rules" / "insurco_rules.xml"
RECEIVER = os.environ.get("WEBHOOK_VIEW_URL", "http://127.0.0.1:8088")
RULE = "100101"
AR_LOG = "/var/ossec/logs/active-responses.log"
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}  # Git Bash: keep /var/ossec/... as is
COMPOSE = ["docker", "compose", "--profile", "real"]
REAL_ATTACKER, REAL_SSHD = "real-client", ("10.20.60.11", 22)
EXPIRY_SLACK = 90  # execd checks its timeouts periodically: a few seconds late is normal


@dataclass
class Target:
    name: str
    host: str  # agent / container that must block
    since: float = 0.0  # receiver clock (epoch seconds): messages newer than this count
    srcip: str = ""
    alert_id: str = ""
    added: datetime | None = None
    deleted: datetime | None = None
    notes: list[str] = field(default_factory=list)


TARGETS = {"simulated": "srv-linux-01", "real": "real-linux-01"}


def sh(*args: str, check: bool = False, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", env=ENV, check=check,
                          timeout=timeout)


def block_seconds(path: Path = MANAGER_CONF) -> int:
    """The <timeout> of the firewall-drop active response in the manager config (git)."""
    root = ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")
    ar = next(a for a in root.iter("active-response") if (a.findtext("command") or "").strip() == "firewall-drop")
    return int(ar.findtext("timeout"))


def brute_force_ignore(path: Path = RULES_XML) -> int:
    """ignore="" of 100100 (seconds during which a second brute force raises nothing)."""
    rule = next(r for r in ET.parse(path).getroot().iter("rule") if r.get("id") == "100100")
    return int(rule.get("ignore", "0"))


def messages(after: int = 0) -> list[dict]:
    with urllib.request.urlopen(f"{RECEIVER}/api/messages?after={after}", timeout=10) as resp:
        return json.load(resp)


def find_message(target: Target) -> dict | None:
    for record in messages():
        alert = record.get("message", {}).get("alert", {})
        if record["received"] >= target.since and alert.get("rule_id") == RULE and alert.get("agent") == target.host:
            return record
    return None


def trigger(target: Target) -> None:
    if target.name == "simulated":
        sh(*COMPOSE, "exec", "-T", "simulator", "insurco-sim", "inject", "brute_force", check=True)
    else:
        out = sh(*COMPOSE, "exec", "-T", REAL_ATTACKER, "lab-traffic", "ssh")
        print("   " + out.stdout.strip().replace("\n", "\n   "))
        if out.returncode != 0:
            raise SystemExit("lab-traffic ssh failed (is the client still blocked by a previous run? "
                             "wait 10 min or see docs/response.md)")


def ar_events(host: str, srcip: str) -> list[tuple[datetime, str]]:
    """(time, command) of the firewall-drop lines for srcip in the host's active-responses.log."""
    out = sh(*COMPOSE, "exec", "-T", host, "cat", AR_LOG).stdout
    events = []
    for line in out.splitlines():
        if "firewall-drop" not in line or srcip not in line:
            continue
        stamp = re.match(r"(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)", line)
        command = re.search(r'"command"\s*:\s*"(add|delete)"', line)
        if stamp and command:
            events.append((datetime.strptime(stamp.group(1), "%Y/%m/%d %H:%M:%S"), command.group(1)))
    return events


def blocked(host: str, srcip: str) -> bool:
    rules = sh(*COMPOSE, "exec", "-T", host, "iptables", "-S", "INPUT").stdout
    return f"-A INPUT -s {srcip}/32 -j DROP" in rules


def sshd_reachable() -> bool:
    """TCP connect from the attacker container to the real sshd (3 s): False while DROPped."""
    code = (f"import socket; socket.create_connection({REAL_SSHD!r}, timeout=3).close()")
    return sh(*COMPOSE, "exec", "-T", REAL_ATTACKER, "python3", "-c", code).returncode == 0


def indexed(target: Target) -> bool:
    query = {"size": 1, "query": {"bool": {"filter": [
        {"term": {"rule.id": RULE}}, {"term": {"agent.name": target.host}}, {"term": {"id": target.alert_id}}]}}}
    status, body = request("POST", "/wazuh-alerts-*/_search", "admin", indexer_password(), query)
    return status == 200 and body["hits"]["total"]["value"] > 0


def wait(what: str, check, timeout: float, every: float = 3) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if check():
            return True
        if time.monotonic() >= deadline:
            print(f"   {what}: not after {timeout:.0f} s")
            return False
        time.sleep(every)


def ok(flag: bool, text: str) -> bool:
    print(f"   [{'ok' if flag else 'FAIL'}] {text}")
    return flag


def check_until_block(target: Target, inject: bool) -> bool:
    print(f"\n== {target.name}: {target.host} ==")
    if inject:
        print(f" - trigger ({'insurco-sim inject brute_force' if target.name == 'simulated' else 'lab-traffic ssh'})")
        trigger(target)
    found: dict = {}

    def got_message() -> bool:
        found.update(find_message(target) or {})
        return bool(found)

    if not wait("webhook message", got_message, 90) and inject:
        pause = brute_force_ignore() + 5
        print(f"   no 100101 yet: maybe inside 100100's ignore window; trying once more in {pause} s")
        time.sleep(pause)
        trigger(target)
        wait("webhook message", got_message, 120)
    if not ok(bool(found), f"webhook message for rule {RULE} from {target.host}"):
        return False
    alert = found["message"]["alert"]
    target.srcip, target.alert_id = alert["srcip"], alert["id"]
    print(f"     level {alert['level']}, srcip {target.srcip}, runbook {alert.get('runbook') or '-'}")
    ok(bool(alert.get("runbook")), "message links the runbook")
    good = ok(wait("indexed alert", lambda: indexed(target), 60), f"alert {target.alert_id} in wazuh-alerts-*")

    def has_add() -> bool:
        events = ar_events(target.host, target.srcip)
        adds = [t for t, c in events if c == "add"]
        if not adds:
            return False
        target.added = adds[-1]
        if blocked(target.host, target.srcip):
            return True
        # --no-inject: the block may already be over; then the log must show its removal
        deletes = [t for t, c in events if c == "delete" and t >= target.added]
        if deletes and not inject:
            target.deleted = deletes[0]
            return True
        return False

    seen = wait("block", has_add, 60)
    state = "already lifted at " + str(target.deleted) if target.deleted else "in place"
    good &= ok(seen, f"{target.host}: iptables DROP for {target.srcip} (firewall-drop add at {target.added}, {state})")
    if seen and target.name == "real" and not target.deleted:
        good &= ok(not sshd_reachable(), f"{REAL_ATTACKER} -> {REAL_SSHD[0]}:{REAL_SSHD[1]} times out while blocked")
    return good


def check_expiry(targets: list[Target], seconds: int) -> bool:
    print(f"\n== expiry: waiting for the blocks to be lifted ({seconds} s timeout + up to {EXPIRY_SLACK} s) ==")
    pending = [t for t in targets if t.deleted is None]
    deadline = time.monotonic() + seconds + EXPIRY_SLACK + 30
    while pending and time.monotonic() < deadline:
        for t in list(pending):
            if not blocked(t.host, t.srcip):
                deletes = [ts for ts, c in ar_events(t.host, t.srcip) if c == "delete" and ts >= t.added]
                t.deleted = deletes[0] if deletes else None
                pending.remove(t)
        time.sleep(10)
    good = True
    for t in targets:
        if t.deleted is None:
            good &= ok(False, f"{t.host}: block of {t.srcip} not lifted (or no delete line in {AR_LOG})")
            continue
        held = (t.deleted - t.added).total_seconds()
        good &= ok(seconds - 5 <= held <= seconds + EXPIRY_SLACK,
                   f"{t.host}: block of {t.srcip} held {held:.0f} s (configured {seconds} s), then removed")
        if t.name == "real":
            good &= ok(wait("sshd reachable", sshd_reachable, 30), f"{REAL_ATTACKER} reaches sshd again")
    return good


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", choices=["simulated", "real", "both"], default="simulated")
    parser.add_argument("--no-inject", dest="inject", action="store_false",
                        help="do not trigger: check a 100101 already received within --lookback")
    parser.add_argument("--lookback", type=float, default=900, help="seconds, with --no-inject (default 900)")
    parser.add_argument("--no-expiry", dest="expiry", action="store_false", help="stop once the block is seen")
    args = parser.parse_args(argv)

    seconds = block_seconds()
    names = ["simulated", "real"] if args.target == "both" else [args.target]
    try:
        messages()
    except OSError as exc:
        print(f"webhook-receiver not reachable at {RECEIVER}: {exc} (is the lab up?)", file=sys.stderr)
        return 2
    now = time.time()
    targets = [Target(n, TARGETS[n], since=now - (5 if args.inject else args.lookback)) for n in names]
    print(f"active response: firewall-drop on {RULE}, timeout {seconds} s; webhook viewer {RECEIVER}")
    good = True
    for i, t in enumerate(targets):
        if i and args.inject:
            pause = brute_force_ignore() + 5
            print(f"\n(waiting {pause} s: 100100's ignore window would mute the next brute force)")
            time.sleep(pause)
        good &= check_until_block(t, args.inject)
    if good and args.expiry:
        good = check_expiry(targets, seconds)
    print("\nOK: alert -> webhook -> timed block" + (" -> expiry" if args.expiry else "") if good else "\nFAIL")
    return 0 if good else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    socket.setdefaulttimeout(15)
    sys.exit(main())
