# Runbook - SSH brute force and compromise (rules 100100, 100101, 100102, 100103)

**Severity:** 100100 medium (10) · 100101 critical (14) · 100102 medium (8) · 100103 medium (10)
**MITRE:** T1110.001 Password Guessing, T1078 Valid Accounts, T1078.003 Local Accounts
**Why it matters at an insurer:** the Linux servers host the policy and claims
back-ends. A guessed password on one of them is a foothold next to the customer
database; service accounts such as `svc_backup` often have broad read access
and nobody watches their logins.

| Rule | Means | Automatic action |
|---|---|---|
| 100100 | 6 failed SSH logins from one IP in 2 minutes | none |
| 100101 | a **successful** login from that IP within 5 minutes of 100100 | webhook (level >= 12) + **source IP blocked on the targeted host for 10 minutes** ([response.md](../response.md)) |
| 100102 | login at night (22:00-06:00) from outside `10.20.0.0/16` | none |
| 100103 | login at night to `root` / `admin` / `administrator` | none |

## 1. Triage (L1, 10 minutes)

1. Open the alert and note `agent.name` (the targeted server), `data.srcip`,
   `data.dstuser`, and the time.
2. **100101 first.** It is the only one that says "the guessing worked". Check the
   webhook channel (lab: `http://localhost:8088`) - the message is already there -
   and confirm the active response ran (see Containment). Then call L2: do not
   wait for the end of the 10-minute block.
3. 100100 alone: is `srcip` internal (`10.20.0.0/16`)? An internal source is a
   misconfigured script or a compromised workstation, not internet noise:
   escalate. External and no 100101 within 5 minutes: record, watch, close as
   "attempt, no success".
4. 100102 / 100103: is there an on-call change or incident at that hour? If yes
   and the account is expected, close as false positive and note the ticket.
   An unknown external IP or a shared `root` login with no ticket: escalate.
5. How many targets? Dashboard *Insurer Security* -> "brute force -> compromise",
   or `rule.id:(100100 or 100101) and data.srcip:"<ip>"`.

## 2. Investigation (L2)

- Which account was guessed (`dstuser`) and who owns it? Service accounts must
  never log in interactively: a successful `svc_*` SSH login is suspicious by itself.
- What did the session do? Following events on the same `agent.name` after the
  login: `sudo` (5402 / 100110), new users, file changes, outbound connections.
- Same `srcip` on other hosts or other log sources (web 100120-100129, Windows
  100142)? A single source across families is a campaign, not a typo.
- Reputation and ownership of `srcip` (threat-intel list, WHOIS) - lab IPs are
  RFC 5737 documentation addresses.

## 3. Containment

- **Automatic (100101, lab):** Wazuh active response `firewall-drop` blocks
  `srcip` on the targeted host (`location local`) for 600 s, then removes the
  rule by itself. Check it on the host:
  `docker compose exec srv-linux-01 iptables -S INPUT` (expect
  `-A INPUT -s <ip>/32 -j DROP`) and
  `docker compose exec srv-linux-01 tail /var/ossec/logs/active-responses.log`.
- 10 minutes buys time, it does not fix anything. With the system owner's
  approval: disable the account (`usermod -L`, `chage -E0`), kill its sessions
  (`pkill -KILL -u <user>`), rotate its password and SSH keys.
- Block the IP at the perimeter firewall if it is external and still active.
- Preserve evidence before rebuilding: `auth.log`, the alerts, the session's
  shell history.

## 4. Close

Record: true/false positive, account(s) touched, whether the active response
ran and expired as expected, root cause (weak password, exposed SSH), tuning
(none expected on 100100: never allow-list an IP on authentication rules),
time to detect and time to contain.
