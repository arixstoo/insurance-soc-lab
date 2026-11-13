# Detection catalog

All rules live in [`detection/rules/insurco_rules.xml`](../detection/rules/insurco_rules.xml)
(ID range `100100-100199`). Every rule has at least one **positive and one negative**
case in [`detection/tests/cases.yaml`](../detection/tests/cases.yaml), run against the
real Wazuh engine (`detection/tests/test_rule_coverage.py` fails if a rule has none).

The tables marked *generated* are produced from the XML by `python scripts/gen_catalog.py`
(CI runs `--check`); everything else is hand-written.

<!-- BEGIN GENERATED: summary (scripts/gen_catalog.py - do not edit by hand) -->
21 rules (18 raise alerts, 3 are building blocks below the alert level), 12 ATT&CK techniques.
<!-- END GENERATED: summary -->

## Rules (generated)

<!-- BEGIN GENERATED: rules (scripts/gen_catalog.py - do not edit by hand) -->
| ID | Level | Detection | Built on | Correlation / conditions | MITRE ATT&CK | Groups |
|---|---|---|---|---|---|---|
| 100100 | 10 | SSH brute force: 6 failed logins from $(srcip) in 2 minutes | after 5760 | 6 in 120 s; same `srcip`; then quiet 60 s | T1110.001 Password Guessing | `insurco_auth`, `brute_force` |
| 100101 | 14 | CRITICAL: successful SSH login from $(srcip) right after a brute force | 5715, after 100100 | within 300 s; same `srcip` | T1110.001 Password Guessing<br>T1078 Valid Accounts | `insurco_auth`, `account_compromise` |
| 100102 | 8 | SSH login outside office hours by $(dstuser) from outside the internal network ($(srcip)) | 5715 | only 10 pm - 6 am | T1078 Valid Accounts | `insurco_auth`, `after_hours` |
| 100103 | 10 | SSH login to privileged account $(dstuser) outside office hours from $(srcip) | 5715 | only 10 pm - 6 am | T1078.003 Valid Accounts: Local Accounts | `insurco_auth`, `after_hours`, `privileged_account` |
| 100110 | 12 | Suspicious sudo command (root shell or credential file change) by $(srcuser) | 5402, 5403 | - | T1548.003 Sudo and Sudo Caching | `insurco_privesc`, `privilege_escalation` |
| 100120 | 11 | SQL injection attempt on a business web app from $(srcip) | 31103, 31164, 31170, 31171 | not in list `scanner-ips` (srcip) | T1190 Exploit Public-Facing Application | `insurco_web`, `web_attack`, `sqli` |
| 100121 | 10 | Cross-site scripting attempt on a business web app from $(srcip) | 31105 | not in list `scanner-ips` (srcip) | T1190 Exploit Public-Facing Application | `insurco_web`, `web_attack`, `xss` |
| 100122 | 10 | Path traversal attempt from $(srcip) | 31104 | not in list `scanner-ips` (srcip) | T1190 Exploit Public-Facing Application<br>T1083 File and Directory Discovery | `insurco_web`, `web_attack`, `path_traversal` |
| 100123 | 8 | Probe for secrets or backup files from $(srcip) | 31100, 31101, 31108 | not in list `scanner-ips` (srcip) | T1595.003 Wordlist Scanning | `insurco_web`, `web_scan` |
| 100129 | 13 | Coordinated web attack campaign from $(srcip) | after group `insurco_web` | 5 in 300 s; same `srcip`; then quiet 120 s | T1190 Exploit Public-Facing Application | `insurco_web`, `coordinated_attack` |
| 100130 | 0 | Database audit event | decoder `insurco-db-audit` | - | - | `insurco_db` |
| 100131 | 7 | Bulk read of sensitive table $(table) by $(db_user) | 100130 | not in list `db-service-accounts` (db_user) | T1213 Data from Information Repositories | `insurco_db`, `insurco_bulk_read`, `data_access` |
| 100132 | 12 | Mass customer data access by $(db_user): possible insider fraud | after group `insurco_bulk_read` | 5 in 300 s; same `db_user`; then quiet 300 s | T1213 Data from Information Repositories<br>T1530 Data from Cloud Storage | `insurco_db`, `insider_threat` |
| 100133 | 13 | Bulk customer data read OUTSIDE office hours by $(db_user) | 100131 | only 10 pm - 6 am | T1213 Data from Information Repositories<br>T1078 Valid Accounts | `insurco_db`, `insurco_bulk_read`, `insider_threat`, `after_hours` |
| 100134 | 14 | Mass customer data access OUTSIDE office hours by $(db_user): possible insider fraud | 100133, after group `insurco_bulk_read` | 5 in 300 s; same `db_user`; then quiet 300 s | T1213 Data from Information Repositories<br>T1530 Data from Cloud Storage<br>T1078 Valid Accounts | `insurco_db`, `insider_threat`, `after_hours` |
| 100140 | 0 | Windows security event | decoder `insurco-winsec` | - | - | `insurco_windows` |
| 100141 | 2 | Windows logon failure for $(TargetUserName) | 100140 | - | - | `insurco_windows`, `authentication_failed` |
| 100142 | 10 | Windows password guessing from $(IpAddress) | after 100141 | 8 in 120 s; same `IpAddress`; then quiet 60 s | T1110 Brute Force | `insurco_windows`, `brute_force` |
| 100143 | 8 | New user account $(TargetUserName) created by $(SubjectUserName) | 100140 | - | T1136.001 Create Account: Local Account | `insurco_windows`, `account_management` |
| 100144 | 13 | CRITICAL: $(MemberName) added to $(GroupName) | 100140 | - | T1098 Account Manipulation | `insurco_windows`, `privilege_escalation` |
| 100145 | 15 | CRITICAL: account $(account) created and added to $(GroupName) within 10 minutes | 100144, after 100143 | within 600 s; same `account` | T1136.001 Create Account: Local Account<br>T1098 Account Manipulation | `insurco_windows`, `privilege_escalation`, `account_compromise` |
<!-- END GENERATED: rules -->

## Allow-lists (generated)

CDB lists in [`detection/lists/`](../detection/lists/), loaded by the manager as
`etc/lists/insurco/<name>` (declared in `stack/config/wazuh_cluster/wazuh_manager.conf`).
Adding an entry is a reviewed change, like a rule: the value says why and who owns it.

<!-- BEGIN GENERATED: lists (scripts/gen_catalog.py - do not edit by hand) -->
| List (`etc/lists/insurco/`) | Entries | Used by | Effect |
|---|---|---|---|
| `db-service-accounts` | `svc_reporting` - BI and regulatory reporting extracts - owner data team | 100131 | skip on `db_user` |
| `scanner-ips` | `10.20.5.10` - internal vulnerability scanner - owner security team | 100120, 100121, 100122, 100123 | skip on `srcip` |
<!-- END GENERATED: lists -->

## MITRE ATT&CK coverage (generated)

<!-- BEGIN GENERATED: mitre (scripts/gen_catalog.py - do not edit by hand) -->
| Technique | Rules |
|---|---|
| T1078 Valid Accounts | 100101, 100102, 100133, 100134 |
| T1078.003 Valid Accounts: Local Accounts | 100103 |
| T1083 File and Directory Discovery | 100122 |
| T1098 Account Manipulation | 100144, 100145 |
| T1110 Brute Force | 100142 |
| T1110.001 Password Guessing | 100100, 100101 |
| T1136.001 Create Account: Local Account | 100143, 100145 |
| T1190 Exploit Public-Facing Application | 100120, 100121, 100122, 100129 |
| T1213 Data from Information Repositories | 100131, 100132, 100133, 100134 |
| T1530 Data from Cloud Storage | 100132, 100134 |
| T1548.003 Sudo and Sudo Caching | 100110 |
| T1595.003 Wordlist Scanning | 100123 |
<!-- END GENERATED: mitre -->

## Known false positives

One row per rule (`gen_catalog.py --check` fails if a rule is missing here).

| Rule | Known false positives | Handling |
|---|---|---|
| 100100 | Monitoring tool or script with an expired password | Fix the credential; never allow-list an IP on auth rules |
| 100101 | Admin who mistyped 6 times, then succeeded | Confirm with the user; still worth a call |
| 100102 | Remote admin connecting from home or a hotel at night | Expected to be rare; confirm with on-call rota |
| 100103 | On-call admin logging in as `root` during an incident | Ask for named accounts + `sudo`; the alert is the nudge |
| 100110 | Admins who use `sudo bash` out of habit | Coach; keep the alert |
| 100120 | Authorised vulnerability scans | Scanner IPs allow-listed (`scanner-ips`); other scanners: add after review |
| 100121 | Same as 100120 | Same |
| 100122 | Rare (encoded `..` in legitimate parameters) | Review the app |
| 100123 | Internet background noise on exposed apps | Low level (8); feeds 100129 |
| 100129 | Authorised penetration test from an unlisted IP | Announce tests; temporary list entry |
| 100130 | Level 0 building block: no alert | - |
| 100131 | Monthly reporting extracts by a person | Service accounts allow-listed (`db-service-accounts`); people: check the ticket |
| 100132 | A BI developer testing an extract by hand | Ask them to use the service account |
| 100133 | Scheduled exports run under a personal account | Move the job to an allow-listed service account |
| 100134 | Same as 100133, in a batch | Same |
| 100140 | Level 0 building block: no alert | - |
| 100141 | Level 2 (no alert since phase 3): users mistyping passwords | Feeds 100142 only |
| 100142 | A device with a cached old password | Find and fix the device |
| 100143 | Normal onboarding by IT (~1-3 a day) | Match with the HR / IAM ticket; accepted noise |
| 100144 | Approved admin change | Check the change ticket |
| 100145 | A new admin account created and promoted under an approved change | Check the change ticket; should be very rare |

## Tuning log

Measured with `python scripts/noise_report.py` (24 h of background traffic replayed
through the real engine, details in [`tuning-report.md`](tuning-report.md)). Budget:
fewer than 20 custom alerts per day of normal activity.

| Phase | Rule | Change | Why (alerts / 24 h of background) |
|---|---|---|---|
| 3 | 100131 / 100132 / 100133 | `db_user` not in `db-service-accounts` | The reporting service account's scheduled extracts: 253 + 36 alerts without the list |
| 3 | 100120-100123 (and so 100129) | `srcip` not in `scanner-ips` | The internal vulnerability scanner: 243 + 70 alerts without the list |
| 3 | 100132 | Counts group `insurco_bulk_read` (100131 + 100133) instead of 100131 | Night gap: the correlation never fired at night; reads across 22:00 now add up |
| 3 | 100134 | New: night variant of 100132 (child of 100133) | 100133 is evaluated before the group-based 100132 at night |
| 3 | 100141 | Level 5 -> 2 (below the alert threshold) | 1800: one per mistyped password; 100142 still correlates them |
| 3 | 100102 | Only from outside `10.20.0.0/16` | 298: staff logging in from the office network at night |
| 3 | 100103 | New: night login to `root` / `admin` / `administrator` | Keeps the high-signal part of the old 100102 |
| 3 | 100145 | New: account created then added to an admin group within 10 min | Two-step correlation (roadmap) |

Result after phase 3: **3** custom alerts in 24 h (all 100143, onboarding), from 2101
before the threshold changes. No frequency threshold had to move: the background
stays at half of each correlation threshold or less (headroom table in the report).

## Decoders

[`detection/decoders/0005-insurco_decoders.xml`](../detection/decoders/0005-insurco_decoders.xml)
gives the two JSON log types their own decoders, `insurco-db-audit` and
`insurco-winsec`, instead of the generic `json` decoder:

- rules say `<decoded_as>insurco-db-audit</decoded_as>`: an unrelated JSON log with a
  stray `log_type` key can no longer reach them;
- the DB client address is also decoded as the standard `srcip` (GeoIP, address lists,
  `same_source_ip` work on it);
- on Windows events, `account` is the account an account-management event is *about*
  (4720: `TargetUserName`, 4732: `MemberName`) - what the two-step correlation 100145
  compares. Real Windows uses different fields per event too (`TargetSid` / `MemberSid`).

The `0005-` prefix is required: Wazuh orders decoder files by file name across all
folders and the first matching parent wins, so a file sorting after
`0006-json_decoders.xml` would never be used.

## Why these detections for an insurer

An insurer holds identity, financial, health and claims data on the same
platforms, and most staff have legitimate access to part of it. Perimeter
controls (NGFW, IPS, XDR) were already strong at the company where this lab was
built; what was missing was **correlation**. So the rules focus on:

- **Credential attacks** that turn into a valid session (100100 -> 100101).
- **Insider misuse of customer data**: bulk reads, repeated, or at night
  (100131-100134). This is the most insurance-specific family.
- **Attacks on internal business web apps** (100120-100129).
- **Privilege changes** on Linux servers and Windows/AD (100110, 100143-100145),
  including the "create an account, then make it admin" pattern (100145).

## Coverage gaps (honest list)

Not detected yet - each one is a roadmap item or an accepted trade-off:

- Lateral movement (T1021, T1570) - needs authentication events across hosts.
- Windows persistence (T1053 scheduled tasks, T1547 autostart) - needs real
  Windows event logs (Sysmon) instead of simulated JSON.
- Exfiltration over network channels (T1041, T1048) and DNS tunnelling
  (T1071.004) - needs network telemetry (Suricata / Zeek).
- **Staff night logins from the office network** (accepted in phase 3 tuning): a
  personal account logging in at night from `10.20.0.0/16` no longer alerts on the
  login itself (it was ~300 alerts a day). Night access to customer data still alerts
  (100133, 100134).
- **Allow-listed service account abused.** `db-service-accounts` matches the account
  name only: `svc_reporting` used from another host would be silent. Next step: pair
  each account with its expected source host (a second list keyed by `srcip`).
- **Allow-listed scanner compromised.** The scanner IP is silent on web rules
  100120-100123 / 100129 (not on authentication rules).
- **Two-step correlation across more than 10 minutes** (100145): an attacker who waits
  is only caught by 100143 and 100144 separately.

## One event, one alert

Wazuh gives each event a single rule: the deepest child that matches. So the
event that completes a correlation raises the correlation rule **instead of** its
own. In the `web_campaign` scenario the 5th attack raises 100129, not 100120-100123;
every attack kind is therefore sent twice so each rule still shows up. In
`rogue_admin` the 4732 raises 100145 instead of 100144. Keep this in mind when
counting alerts per rule.

## End-to-end check

`scripts/e2e.sh` (CI: `.github/workflows/e2e.yml`) injects every scenario into a
running lab and asserts that each rule of its `expected_rules` is indexed in
`wazuh-alerts-*`. **Night-only rules** - those with a `<time>` element (100102, 100103,
100133, 100134) - are excluded: whether they fire depends on the manager clock, not on
the scenario. The workflow pins the manager clock to about 12:00 so the day rules
(100131, 100132) are not replaced by their night variant. Night-only rules stay
covered by the `clock: night` cases in `detection/tests/cases.yaml`.
