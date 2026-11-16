# Detection catalog

All rules live in [`detection/rules/insurco_rules.xml`](../detection/rules/insurco_rules.xml)
(ID range `100100-100199`). Every rule has at least one **positive and one negative**
case in [`detection/tests/cases.yaml`](../detection/tests/cases.yaml), run against the
real Wazuh engine (`detection/tests/test_rule_coverage.py` fails if a rule has none).

The tables marked *generated* are produced from the XML by `python scripts/gen_catalog.py`
(CI runs `--check`); everything else is hand-written.

The main detections also exist as **Sigma rules** ([below](#sigma-rules)), tested against
the same cases, and a **threat-intel** list raises activity from known-bad IPs
([below](#threat-intel-known-bad-source-ips)).

<!-- BEGIN GENERATED: summary (scripts/gen_catalog.py - do not edit by hand) -->
30 rules (25 raise alerts, 5 are building blocks below the alert level), 13 ATT&CK techniques.
<!-- END GENERATED: summary -->

## Rules (generated)

<!-- BEGIN GENERATED: rules (scripts/gen_catalog.py - do not edit by hand) -->
| ID | Level | Detection | Built on | Correlation / conditions | MITRE ATT&CK | Groups |
|---|---|---|---|---|---|---|
| 100100 | 10 | [SSH brute force: 6 failed logins from $(srcip) in 2 minutes](runbooks/ssh-brute-force.md) | after 5760 | 6 in 120 s; same `srcip`; then quiet 60 s | T1110.001 Password Guessing | `insurco_auth`, `brute_force` |
| 100101 | 14 | [CRITICAL: successful SSH login from $(srcip) right after a brute force](runbooks/ssh-brute-force.md) | 5715, after 100100 | within 300 s; same `srcip` | T1110.001 Password Guessing<br>T1078 Valid Accounts | `insurco_auth`, `account_compromise` |
| 100102 | 8 | [SSH login outside office hours by $(dstuser) from outside the internal network ($(srcip))](runbooks/ssh-brute-force.md) | 5715 | only 10 pm - 6 am | T1078 Valid Accounts | `insurco_auth`, `after_hours` |
| 100103 | 10 | [SSH login to privileged account $(dstuser) outside office hours from $(srcip)](runbooks/ssh-brute-force.md) | 5715 | only 10 pm - 6 am | T1078.003 Valid Accounts: Local Accounts | `insurco_auth`, `after_hours`, `privileged_account` |
| 100110 | 12 | [Suspicious sudo command (root shell or credential file change) by $(srcuser)](runbooks/privilege-escalation.md) | 5402, 5403 | - | T1548.003 Sudo and Sudo Caching | `insurco_privesc`, `privilege_escalation` |
| 100120 | 11 | [SQL injection attempt on a business web app from $(srcip)](runbooks/web-attack-campaign.md) | 31103, 31164, 31170, 31171 | not in list `scanner-ips` (srcip) | T1190 Exploit Public-Facing Application | `insurco_web`, `web_attack`, `sqli` |
| 100121 | 10 | [Cross-site scripting attempt on a business web app from $(srcip)](runbooks/web-attack-campaign.md) | 31105 | not in list `scanner-ips` (srcip) | T1190 Exploit Public-Facing Application | `insurco_web`, `web_attack`, `xss` |
| 100122 | 10 | [Path traversal attempt from $(srcip)](runbooks/web-attack-campaign.md) | 31104 | not in list `scanner-ips` (srcip) | T1190 Exploit Public-Facing Application<br>T1083 File and Directory Discovery | `insurco_web`, `web_attack`, `path_traversal` |
| 100123 | 8 | [Probe for secrets or backup files from $(srcip)](runbooks/web-attack-campaign.md) | 31100, 31101, 31108 | not in list `scanner-ips` (srcip) | T1595.003 Wordlist Scanning | `insurco_web`, `web_scan` |
| 100129 | 13 | [Coordinated web attack campaign from $(srcip)](runbooks/web-attack-campaign.md) | after group `insurco_web` | 5 in 300 s; same `srcip`; then quiet 120 s | T1190 Exploit Public-Facing Application | `insurco_web`, `coordinated_attack` |
| 100130 | 0 | Database audit event | decoder `insurco-db-audit` | - | - | `insurco_db` |
| 100131 | 7 | [Bulk read of sensitive table $(table) by $(db_user)](runbooks/insider-data-access.md) | 100130, 100136 | not in list `db-service-accounts` (db_user) | T1213 Data from Information Repositories | `insurco_db`, `insurco_bulk_read`, `data_access` |
| 100135 | 0 | PostgreSQL audit event (pgaudit) | decoder `insurco-pgaudit` | - | - | `insurco_db` |
| 100136 | 0 | PostgreSQL read (pgaudit) | 100135 | - | - | `insurco_db` |
| 100137 | 7 | [Bulk read of sensitive table $(table) by $(db_user) (PostgreSQL audit)](runbooks/insider-data-access.md) | 100136 | not in list `db-service-accounts` (db_user) | T1213 Data from Information Repositories | `insurco_db`, `insurco_bulk_read`, `data_access` |
| 100138 | 13 | [Bulk customer data read OUTSIDE office hours by $(db_user) (PostgreSQL audit)](runbooks/insider-data-access.md) | 100137 | only 10 pm - 6 am | T1213 Data from Information Repositories<br>T1078 Valid Accounts | `insurco_db`, `insurco_bulk_read`, `insider_threat`, `after_hours` |
| 100132 | 12 | [Mass customer data access by $(db_user): possible insider fraud](runbooks/insider-data-access.md) | after group `insurco_bulk_read` | 5 in 300 s; same `db_user`; then quiet 300 s | T1213 Data from Information Repositories<br>T1530 Data from Cloud Storage | `insurco_db`, `insider_threat` |
| 100133 | 13 | [Bulk customer data read OUTSIDE office hours by $(db_user)](runbooks/insider-data-access.md) | 100131 | only 10 pm - 6 am | T1213 Data from Information Repositories<br>T1078 Valid Accounts | `insurco_db`, `insurco_bulk_read`, `insider_threat`, `after_hours` |
| 100134 | 14 | [Mass customer data access OUTSIDE office hours by $(db_user): possible insider fraud](runbooks/insider-data-access.md) | 100133, 100138, after group `insurco_bulk_read` | 5 in 300 s; same `db_user`; then quiet 300 s | T1213 Data from Information Repositories<br>T1530 Data from Cloud Storage<br>T1078 Valid Accounts | `insurco_db`, `insider_threat`, `after_hours` |
| 100140 | 0 | Windows security event | decoder `insurco-winsec` | - | - | `insurco_windows` |
| 100141 | 2 | [Windows logon failure for $(TargetUserName)](runbooks/windows-password-guessing.md) | 100140 | - | - | `insurco_windows`, `authentication_failed` |
| 100142 | 10 | [Windows password guessing from $(IpAddress)](runbooks/windows-password-guessing.md) | after 100141 | 8 in 120 s; same `IpAddress`; then quiet 60 s | T1110 Brute Force | `insurco_windows`, `brute_force` |
| 100143 | 8 | [New user account $(TargetUserName) created by $(SubjectUserName)](runbooks/privilege-escalation.md) | 100140 | - | T1136.001 Create Account: Local Account | `insurco_windows`, `account_management` |
| 100144 | 13 | [CRITICAL: $(MemberName) added to $(GroupName)](runbooks/privilege-escalation.md) | 100140 | - | T1098 Account Manipulation | `insurco_windows`, `privilege_escalation` |
| 100145 | 15 | [CRITICAL: account $(account) created and added to $(GroupName) within 10 minutes](runbooks/privilege-escalation.md) | 100144, after 100143 | within 600 s; same `account` | T1136.001 Create Account: Local Account<br>T1098 Account Manipulation | `insurco_windows`, `privilege_escalation`, `account_compromise` |
| 100150 | 12 | [SSH login accepted from known-bad IP $(srcip) (threat intel) for $(dstuser)](runbooks/threat-intel-hit.md) | 5715 | only 6 am - 10 pm; in list `ti-bad-ips` (srcip) | T1078 Valid Accounts | `insurco_ti`, `threat_intel`, `insurco_auth`, `authentication_success` |
| 100151 | 6 | [Page view from known-bad IP $(srcip) (threat intel), no attack pattern](runbooks/threat-intel-hit.md) | 31108 | in list `ti-bad-ips` (srcip) | T1595 Active Scanning | `insurco_ti`, `threat_intel` |
| 100152 | 15 | [CRITICAL: SSH login outside office hours from known-bad IP $(srcip) (threat intel) for $(dstuser)](runbooks/threat-intel-hit.md) | 100102, 100103 | in list `ti-bad-ips` (srcip) | T1078 Valid Accounts | `insurco_ti`, `threat_intel`, `insurco_auth`, `after_hours` |
| 100153 | 15 | [CRITICAL: coordinated web attack campaign from known-bad IP $(srcip) (threat intel)](runbooks/threat-intel-hit.md) | 100129 | in list `ti-bad-ips` (srcip) | T1190 Exploit Public-Facing Application | `insurco_ti`, `threat_intel`, `insurco_web`, `coordinated_attack` |
| 100154 | 5 | [Request with a query string from known-bad IP $(srcip) (threat intel), no attack pattern](runbooks/threat-intel-hit.md) | 31100 | in list `ti-bad-ips` (srcip) | T1595 Active Scanning | `insurco_ti`, `threat_intel` |
<!-- END GENERATED: rules -->

## Allow-lists (generated)

CDB lists in [`detection/lists/`](../detection/lists/), loaded by the manager as
`etc/lists/insurco/<name>` (declared in `stack/config/wazuh_cluster/wazuh_manager.conf`).
Adding an entry is a reviewed change, like a rule: the value says why and who owns it.

<!-- BEGIN GENERATED: lists (scripts/gen_catalog.py - do not edit by hand) -->
| List (`etc/lists/insurco/`) | Entries | Used by | Effect |
|---|---|---|---|
| `db-service-accounts` | `svc_reporting` - BI and regulatory reporting extracts - owner data team | 100131, 100137 | skip on `db_user` |
| `scanner-ips` | `10.20.5.10` - internal vulnerability scanner - owner security team | 100120, 100121, 100122, 100123 | skip on `srcip` |
| `ti-bad-ips` | `192.0.2.` - sample-feed<br>`198.51.100.200` - sample-feed<br>`198.51.100.201` - sample-feed<br>... **13 entries** (see the file) | 100150, 100151, 100152, 100153, 100154 | require on `srcip` |
<!-- END GENERATED: lists -->

## MITRE ATT&CK coverage (generated)

<!-- BEGIN GENERATED: mitre (scripts/gen_catalog.py - do not edit by hand) -->
| Technique | Rules |
|---|---|
| T1078 Valid Accounts | 100101, 100102, 100138, 100133, 100134, 100150, 100152 |
| T1078.003 Valid Accounts: Local Accounts | 100103 |
| T1083 File and Directory Discovery | 100122 |
| T1098 Account Manipulation | 100144, 100145 |
| T1110 Brute Force | 100142 |
| T1110.001 Password Guessing | 100100, 100101 |
| T1136.001 Create Account: Local Account | 100143, 100145 |
| T1190 Exploit Public-Facing Application | 100120, 100121, 100122, 100129, 100153 |
| T1213 Data from Information Repositories | 100131, 100137, 100138, 100132, 100133, 100134 |
| T1530 Data from Cloud Storage | 100132, 100134 |
| T1548.003 Sudo and Sudo Caching | 100110 |
| T1595 Active Scanning | 100151, 100154 |
| T1595.003 Wordlist Scanning | 100123 |
<!-- END GENERATED: mitre -->

## Sigma rules

[`detection/sigma/rules/`](../detection/sigma/rules/) holds Sigma versions of the main
detections (brute force, web attacks, insider bulk read, rogue admin), one rule per file,
so they can be converted to another SIEM (`sigma convert -t <backend> -p <pipeline>`) or
published to a Sigma collection. Each rule names the Wazuh rules it stands for in a custom
`wazuh_rules` attribute. Correlations use the Sigma v2 correlation format
(`event_count`, `temporal_ordered`, `group-by`, `aliases`).

<!-- BEGIN GENERATED: sigma (scripts/gen_catalog.py - do not edit by hand) -->
| Sigma rule | Kind | Logsource | Level | Wazuh rule(s) |
|---|---|---|---|---|
| [`insurco_db_bulk_read`](../detection/sigma/rules/database/insurco_db_bulk_read.yml)<br>Bulk Read Of A Sensitive Insurance Table | rule | product: `insurco`, service: `db_audit` | medium | 100131, 100133 |
| [`insurco_db_mass_access`](../detection/sigma/rules/database/insurco_db_mass_access.yml)<br>Mass Customer Data Access By One User | event_count (db_user, 5m, >= 5) | correlation of `insurco_db_bulk_read`, `insurco_pgaudit_bulk_read` | high | 100132, 100134 |
| [`insurco_pgaudit_bulk_read`](../detection/sigma/rules/database/insurco_pgaudit_bulk_read.yml)<br>Bulk Read Of A Sensitive Insurance Table - PostgreSQL Audit | rule | product: `postgresql`, service: `pgaudit` | medium | 100137, 100138 |
| [`insurco_ssh_brute_force`](../detection/sigma/rules/linux/insurco_ssh_brute_force.yml)<br>SSH Brute Force From One Source | event_count (src_ip, 2m, >= 6) | correlation of `insurco_sshd_failed_password` | high | 100100 |
| [`insurco_sshd_failed_password`](../detection/sigma/rules/linux/insurco_sshd_failed_password.yml)<br>SSH Failed Password | rule | product: `linux`, service: `sshd` | informational | 5760 |
| [`insurco_web_attack_campaign`](../detection/sigma/rules/web/insurco_web_attack_campaign.yml)<br>Coordinated Web Attack Campaign From One Source | event_count (c-ip, 5m, >= 5) | correlation of `insurco_web_sql_injection`, `insurco_web_xss`, `insurco_web_path_traversal`, `insurco_web_secrets_probe` | critical | 100129 |
| [`insurco_web_path_traversal`](../detection/sigma/rules/web/insurco_web_path_traversal.yml)<br>Path Traversal Attempt In Web Request | rule | category: `webserver` | high | 100122 |
| [`insurco_web_secrets_probe`](../detection/sigma/rules/web/insurco_web_secrets_probe.yml)<br>Probe For Secrets Or Backup Files | rule | category: `webserver` | medium | 100123 |
| [`insurco_web_sql_injection`](../detection/sigma/rules/web/insurco_web_sql_injection.yml)<br>SQL Injection Attempt In Web Request | rule | category: `webserver` | high | 100120 |
| [`insurco_web_xss`](../detection/sigma/rules/web/insurco_web_xss.yml)<br>Cross-Site Scripting Attempt In Web Request | rule | category: `webserver` | high | 100121 |
| [`insurco_win_account_created`](../detection/sigma/rules/windows/insurco_win_account_created.yml)<br>User Account Created | rule | product: `windows`, service: `security` | medium | 100143 |
| [`insurco_win_admin_group_member_added`](../detection/sigma/rules/windows/insurco_win_admin_group_member_added.yml)<br>Member Added To An Administrators Group | rule | product: `windows`, service: `security` | critical | 100144 |
| [`insurco_win_rogue_admin`](../detection/sigma/rules/windows/insurco_win_rogue_admin.yml)<br>New Account Added To An Administrators Group Within 10 Minutes | temporal_ordered (account_sid, 10m) | correlation of `insurco_win_account_created`, `insurco_win_admin_group_member_added` | critical | 100145 |
<!-- END GENERATED: sigma -->

**How they are tested** ([`detection/tests/test_sigma.py`](../detection/tests/test_sigma.py), CI):

- pySigma 2.1 loads every rule and runs all its validators (the ATT&CK tag validator
  downloads the ATT&CK dataset: required in CI, skipped offline);
- every `wazuh_rules` id exists (or is a built-in rule a case expects), the ATT&CK
  techniques equal those of the main Wazuh rule, and each correlation's window and
  threshold equal the Wazuh `timeframe` / `frequency`;
- **agreement**: every case of `cases.yaml` that expects one of the rule's Wazuh ids must
  make the Sigma rule fire on its last line, and every case with that id in `expect_not`
  must not (unless what fired instead is built on it - see "one event, one alert"). Each
  Sigma rule needs at least one of each, like the Wazuh rules. These are the cases the
  real Wazuh engine runs, so both languages are checked on the same events. The events go
  through a small evaluator ([`sigma_eval.py`](../detection/tests/sigma_eval.py)) over
  pySigma's parsed rules; it is a test tool, not a backend. 66 agreement checks today.

**Field mapping (the "pipeline" a backend needs).** The Sigma rules use standard schemas
where they exist; the test evaluator turns the lab's lines into them:

| Source | Sigma logsource | Fields used | From the lab's logs |
|---|---|---|---|
| sshd (syslog) | `product: linux`, `service: sshd` | keywords; `src_ip` for the group-by | `src_ip` = the `from <ip> port` of the line (Wazuh: `srcip`) |
| Apache / nginx access log | `category: webserver` | `c-ip`, `cs-uri-stem`, `cs-uri-query` (raw, URL-encoded) | split at the first `?` |
| Lab DB audit (JSON) | `product: insurco`, `service: db_audit` | `db_user`, `table`, `rows_returned` | as logged |
| PostgreSQL pgaudit | `product: postgresql`, `service: pgaudit` | `user` (jsonlog), `class`, `object_name`, `rows` ([pgaudit's names](https://github.com/pgaudit/pgaudit#format)) | CSV message parsed |
| Windows Security | `product: windows`, `service: security` | `EventID`, `TargetSid`, `MemberSid` | the lab's JSON carries names only: the evaluator gives each account a stable fake SID; Administrators `S-1-5-32-544`, Domain Admins RID 512 |
| Allow-lists | placeholders `%insurco_scanner_ips%`, `%insurco_db_service_accounts%` (`expand`) | | the keys of `detection/lists/scanner-ips` and `db-service-accounts` |

**Limits of the translation** (what the Sigma version does not say, or says differently):

- **Time of day.** Sigma has no `<time>`: the night variants 100133 / 100134 / 100138 have
  no Sigma twin; day and night rules map to one Sigma rule, which fires at any hour. Put the
  escalation in the backend (a scheduled search window, a risk score).
- **`ignore` (suppression)** is not part of Sigma: the quiet periods of 100100 (60 s),
  100129 (120 s) and 100132 / 100134 (300 s) belong in the SIEM's alert throttling.
- **"One event, one alert".** Sigma raises the base rule *and* the correlation; Wazuh raises
  only the correlation for the completing event. Same detections, different alert counts.
- **Built on Wazuh's own rules.** 100120 (SQL injection) sits on four built-in rules
  (31103, 31164, 31170, 31171), 100121 on 31105, 100122 on 31104: long, Wazuh-specific
  regexes. The Sigma rules list explicit patterns instead; they agree on the tested cases,
  not on every request the built-in rules would catch. 5760 (failed password) becomes a
  keyword search for `Failed password for`.
- **Raw, not decoded.** Web values are matched on the URL-encoded query string, like
  Wazuh; a backend that stores decoded URLs needs the decoded forms too (both are listed for
  `<script` / `%3cscript`, not for every SQL pattern).
- **Fields the backend must extract.** The SSH correlation groups by `src_ip`, which a
  keyword rule does not carry; pgaudit's `class` / `object_name` / `rows` live inside one CSV
  message. Both need the parsing our Wazuh decoders do.
- **Windows: SIDs, not names, and 4728 too.** The Sigma rules match the group SID (names
  are localised: "Administrateurs" on a French Windows) and correlate 4720 `TargetSid` with
  4728 / 4732 `MemberSid`. Real domain controllers log a Domain Admins change as **4728**
  (global group), which the Wazuh rule 100144 does not read (it follows the lab's simulated
  events, which use 4732): a gap of the Wazuh rule, listed below.
- **Case.** Sigma strings are case-insensitive; the Wazuh table regex (`^(clients|...)$`)
  is case-sensitive. Here the Sigma rule is the stricter detector.
- **Not translated:** 100101 (success after a brute force: a correlation on a correlation,
  which few backends support), 100102 / 100103 (time of day), 100110 (sudo, on built-in
  5402 / 5403), 100141 / 100142 (Windows password guessing), the threat-intel rules (the list
  is a lookup table, not a Sigma construct) and the level-0 building blocks.

## Threat intel: known-bad source IPs

`scripts/update_ti.py` builds the CDB list `ti-bad-ips` from a public feed (default: abuse.ch
[Feodo Tracker](https://feodotracker.abuse.ch/) "recommended" botnet C2 list, CC0; `--url` or
`TI_FEED_URL` for another one, `file://` for a local file). The download is cached in `out/ti/`
for 24 h; without network it uses the last cached copy, then the **sample feed** of the repo
([`detection/ti/sample-feed.txt`](../detection/ti/sample-feed.txt), RFC 5737 addresses only).
The committed list is the sample build (CI: `update_ti.py --sample --check`); a live list is a
local refresh: `make ti` / `scripts/lab.ps1 ti` rebuilds it and restarts the manager, which
compiles CDB lists at start. CIDRs become `address_match_key` prefix keys (`192.0.2.`) or are
expanded; private, loopback, CGNAT, multicast and reserved ranges - so the lab itself - are
never listed, whatever the feed says.

**Why five rules and not "any alert + 1".** Wazuh cannot add to an alert's level: a matching
child rule *replaces* the alert, and only the final rule feeds correlation memory. A blanket
child (`<if_level>3</if_level>` + srcip in the list) was tried on the real engine: six failed
passwords from a listed IP gave six TI alerts and **no 100100**, the following login **no
100101 - so no active response** - and a SQL injection no 100120 (so no campaign). The TI
rules therefore only take events that feed no correlation and trigger no response:

| Rule | Takes | Level | Why there |
|---|---|---|---|
| 100150 | 5715 SSH login accepted, 06:00-22:00 | 3 -> 12 | a listed IP *got in* |
| 100151 | 31108 plain page view (2xx / 3xx, no query string) | 0 -> 6 | reconnaissance or a bot on the portal |
| 100152 | 100102 / 100103 night logins | 8-10 -> 15 | the night rules take the event first |
| 100153 | 100129 web campaign | 13 -> 15 | final detection, nothing correlates on it |
| 100154 | 31100 request with a query string, 2xx / 3xx | 0 -> 5 | 31108 never takes a `?` URL; level 5 keeps every attack sibling (6-13) first |

Left unchanged on purpose, and tested: 5760 / 100100 (brute force), 100101 (the active
response trigger), 100120-100123 (campaign inputs), 31101 (feeds the built-in 400 rules) and
the Shellshock rules 31168 / 31169 (level 15). A listed IP's attack still raises its normal
rule; the runbook ([threat-intel-hit.md](runbooks/threat-intel-hit.md)) starts with a search
by IP for that reason.

Two engine facts this work found (both in CLAUDE.md): **sibling rules are tried by level,
highest first** (ties: load order), not in file order - 100150 at level 12 first took the
night logins of 100102 (level 8), hence its day window and 100151's low level; and Wazuh's
own IoC rules (`0999-malicious-ioc-rules.xml`: 99904 under 5716, 99905 under the SQL
injection rules) are children of correlation inputs, so their list
`etc/lists/malicious-ioc/malicious-ip` (declared, absent from the image) must stay absent here.

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
| 100135 | Level 0 building block (every pgaudit line): no alert | - |
| 100136 | Level 0 building block (pgaudit READ): no alert | - |
| 100137 | Same as 100131, on the real PostgreSQL audit trail; also a JOIN logs one line per table, so one wide query can count twice | Same as 100131; review the query, not just the count |
| 100138 | Same as 100133, on the real PostgreSQL audit trail | Same as 100133 |
| 100140 | Level 0 building block: no alert | - |
| 100141 | Level 2 (no alert since phase 3): users mistyping passwords | Feeds 100142 only |
| 100142 | A device with a cached old password | Find and fix the device |
| 100143 | Normal onboarding by IT (~1-3 a day) | Match with the HR / IAM ticket; accepted noise |
| 100144 | Approved admin change | Check the change ticket |
| 100145 | A new admin account created and promoted under an approved change | Check the change ticket; should be very rare |
| 100150 | A staff member's home router or VPN exit listed by the feed (infected or reused address) | Check the listing date on the feed; still treat the account as at risk; report false listings to the feed |
| 100151 | Shared hosting / cloud addresses reused after a takedown | Low level (6); refresh the list (`make ti`), never a local ignore rule |
| 100152 | Same as 100150, at night | Same as 100150 |
| 100153 | Authorised penetration test from a listed cloud address | Announce tests; temporary `scanner-ips` entry |
| 100154 | Same as 100151 (a search or an API call instead of a page) | Same as 100151 |

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
| 4 | 100135-100138 | New: real PostgreSQL audit trail (pgaudit) feeding the same correlations 100132 / 100134 | Real logs (phase 4); the background has no pgaudit traffic, so the 24 h budget is unchanged |
| 7 | 100150-100153 | New: threat intel (`ti-bad-ips`); 100150 day only, 100151 at level 6 | Sibling rules are tried by level; the simulator's attacker pool is not in the sample list, so the background raises no TI alert |
| 7 | 100154 | New: closes the query-string gap of 100151 (child of 31100, `?` URL, 2xx / 3xx, level 5) | Tested below the attack siblings: XSS / SQLi answered 200 and a 404 from a listed IP keep 100121 / 100120 / 31101 |

Result after phase 3: **3** custom alerts in 24 h (all 100143, onboarding), from 2101
before the threshold changes - still 3 with the rules of phases 4-7 (replay rerun for v1.0.0). No frequency threshold had to move: the background
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

`insurco-pgaudit` (same file) decodes the **real** PostgreSQL audit trail of `real-db-01`
(PostgreSQL 18 `jsonlog`, pgaudit with `log_relation` and `log_rows`) into the *same field
names* as the simulated trail: `db_user`, `table` (schema stripped), `rows_returned`, `srcip`,
plus `audit_class`, `command`, `object_type`, `db_name`. It uses regexes, not the JSON plugin,
because the server log's `user` key would land in a static field. Non-audit server lines
(startup, errors) are left to the generic `json` decoder; the built-in rule 1002 matches them
on the word `error` of the `error_severity` key, at level 2 (no alert).
See [real-services.md](real-services.md) for simulated vs real logs.

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
- **A second attacker inside a correlation's `ignore` window** (found by the phase 4 e2e
  run): Wazuh's `ignore` mutes the *whole rule* after it fires, whatever the source address
  or user. A brute force from another IP within 60 s of a first one raises no 100100 (and so
  no 100101); likewise 120 s for 100129 and 300 s for 100132 / 100134. The underlying
  per-event alerts (5760, 100120-100123, 100131 / 100137) still fire. Mitigation to study:
  shorter `ignore` values, measured against the noise budget. Since phase 6 this also means
  **no active response** for the second attacker (the block hangs on 100101); found again by
  `scripts/check_response.py`, where a random simulated brute force muted the real one. The
  built-in 40112 (level 12, failures then a success) still fires and reaches the webhook
  ([response.md](response.md)).
- **Active response trusts the log.** firewall-drop blocks the `srcip` decoded from the
  sshd line. Lab only, on 100101 only, 10 minutes, on the targeted host only; in production
  add jump hosts, monitoring and partner ranges to the manager's `<white_list>`.
- **A burst of exactly N events within milliseconds** (phase 4, GitHub Actions): five bulk
  reads ~40 ms apart once raised five 100137 and no 100132 - likely analysisd matching on
  several threads. A scripted export that fast may evade the correlation; each read still
  alerts (100131 / 100137, level 7). Mitigation to study: a lower frequency, or a rule on
  rows summed per session.
- **Two-step correlation across more than 10 minutes** (100145): an attacker who waits
  is only caught by 100143 and 100144 separately.
- **Domain Admins on event 4728** (found writing the Sigma rule): real domain controllers
  log a member added to Domain Admins (a global group) as 4728; 100144 only reads 4732, as the
  lab's simulated events do. The Sigma rule covers both.
- **Threat intel does not re-level correlation inputs** (see above): a brute force or a single
  web attack from a listed IP keeps its normal level (by design: a child rule would replace
  the input and break the correlation or the active response; the runbook searches by IP
  instead). A 4xx / 5xx without an attack pattern from a listed IP stays 31101 / 31120. The
  list is only as fresh as the last `make ti`.

## Real logs (compose profile `real`)

Since phase 4 the same rules also run on genuine logs: real `sshd` (`real-linux-01`), real
nginx (`real-web-01`) and a real PostgreSQL + pgaudit (`real-db-01`), with scripted test traffic
from a lab test client. The SSH and web rules apply unchanged; the database family gets its
own entry rules (100135-100138) and shares the correlations. Details, differences and limits:
[real-services.md](real-services.md).

## One event, one alert

Wazuh gives each event a single rule: the deepest child that matches. So the
event that completes a correlation raises the correlation rule **instead of** its
own. Among siblings (children of one parent) Wazuh tries the **highest level first**, not
the first in the file. In the `web_campaign` scenario the 5th attack raises 100129, not 100120-100123;
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
