# Runbook - Threat-intel hit: known-bad source IP (rules 100150-100154)

**Severity:** 100154 low (5) · 100151 medium (6) · 100150 high (12) · 100152 / 100153 critical (15)
**MITRE:** T1078 Valid Accounts, T1595 Active Scanning, T1190 Exploit Public-Facing Application
**Why it matters at an insurer:** a source that a public feed already lists as a botnet
command-and-control server (or worse) has no business on the broker portal or on an SSH
server. A login from such an address is almost never a false positive: someone else holds
valid credentials, or the account's machine is infected.

| Rule | Means |
|---|---|
| 100150 | **SSH login accepted** from a listed IP (no brute force seen before it) |
| 100151 | Web request from a listed IP that matched no attack pattern (reconnaissance, or a bot using the portal) |
| 100152 | Night SSH login (100102 / 100103) from a listed IP |
| 100153 | Web attack campaign (100129) from a listed IP |
| 100154 | Web request **with a query string** (2xx / 3xx) from a listed IP that matched no attack pattern |

The list is `etc/lists/insurco/ti-bad-ips`, built by `scripts/update_ti.py` from a public
feed (default: abuse.ch Feodo Tracker); its CDB value says which feed listed the address.
What these rules do **not** cover (on purpose, see the detection catalog): a brute force or
a single attack request from a listed IP keeps its normal rule (100100, 100120...), so the
correlations and the active response still work. Search for those by IP (step 1.4).

## 1. Triage (L1, 10 minutes)

1. Note `data.srcip`, `agent.name`, `data.dstuser` (SSH) or `data.url` (web), and the time.
2. **Is the listing current?** Feeds age: look the IP up on the feed's own site
   (Feodo Tracker shows first / last seen) and in a second source. Listed, but removed
   months ago, with no other sign: lower the priority, note it, continue.
3. **100150 / 100152: treat as a compromised account until proven otherwise.** Escalate to
   L2 now (phone), do not wait for the investigation. Call the account owner: did they
   log in, from where? A "yes, from my home ISP" is possible (an infected home router can
   be listed): still escalate.
4. Scope: everything from that IP, all rules -
   `data.srcip:"<ip>"` over 7 days (brute force 100100, web 100120-100129, DB 100131...).

## 2. Investigation (L2)

- SSH (100150 / 100152): what did the session do? `sudo` (100110), new accounts, outbound
  connections, files changed (FIM). Other logins by the same account from other IPs.
- Web (100151 / 100153 / 100154): replay the IP's requests in order. Which pages, which documents,
  any `200` on attack URLs (see [web-attack-campaign.md](web-attack-campaign.md))?
- Is the listing about **us**? A C2 server contacting our portal may be a bot checking in
  from an infected customer's machine: the problem is theirs, the data exposure ours.

## 3. Containment

- 100150 / 100152: disable the account or reset its password and keys, kill the session,
  block the IP on the perimeter firewall. The lab's timed block runs on 100101 only.
- 100151 / 100153 / 100154: block the IP on the WAF / reverse proxy.
- Keep the list fresh rather than allow-listing: `make ti` (or `scripts/lab.ps1 ti`)
  downloads the feed again and restarts the manager.

## 4. Close

Record: feed and listing date, true/false positive (was the IP still malicious?), what
the source did, accounts reset, blocks added (with an end date), time to detect and to
contain. A listed IP that turns out legitimate goes back to the feed provider (they all
take false-positive reports), never into a local "ignore" rule.
