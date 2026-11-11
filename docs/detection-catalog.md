# Detection catalog

All rules live in [`detection/rules/insurco_rules.xml`](../detection/rules/insurco_rules.xml)
(ID range `100100-100199`). Every rule has test cases in
[`detection/tests/cases.yaml`](../detection/tests/cases.yaml) that run against
the real Wazuh engine.

| ID | Level | Detection | Built on | MITRE ATT&CK | Known false positives |
|---|---|---|---|---|---|
| 100100 | 10 | 6 failed SSH logins from one IP in 2 min | 5760 | T1110.001 Password Guessing | Monitoring tools with an expired password |
| 100101 | 14 | Successful SSH login from an IP that just brute-forced | 5715 + 100100 | T1110.001, T1078 | Admin who mistyped 6 times, then succeeded |
| 100102 | 8 | SSH login between 22:00 and 06:00 | 5715 | T1078 Valid Accounts | Night batch jobs, on-call IT staff |
| 100110 | 12 | sudo to a root shell or change to `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` | 5402, 5403 | T1548.003 Sudo | Admins who use `sudo bash` out of habit |
| 100120 | 11 | SQL injection on a business web app | 31103, 31164, 31170, 31171 | T1190 | Vulnerability scans by the security team |
| 100121 | 10 | Cross-site scripting attempt | 31105 | T1190 | Same as above |
| 100122 | 10 | Path traversal (`../`, `%2e%2e`) | 31104 | T1190, T1083 | Rare |
| 100123 | 8 | Probe for `.env`, `.git/`, `*.sql`, `*.bak` | 31100, 31101, 31108 | T1595.003 Wordlist Scanning | Internet background noise |
| 100129 | 13 | 5 web attacks from one IP in 5 min | group `insurco_web` | T1190 | Authorised penetration test |
| 100131 | 7 | One bulk read (100+ rows) of a sensitive table | DB audit JSON | T1213 | Monthly reporting extracts |
| 100132 | 12 | 5 bulk reads by the same user in 5 min | 100131 | T1213, T1530 | Service accounts for BI/reporting (allow-list them) |
| 100133 | 13 | Bulk read of customer data between 22:00 and 06:00 | 100131 | T1213, T1078 | Scheduled exports |
| 100141 | 5 | Windows logon failure (4625) | winsec JSON | - | Users mistyping passwords |
| 100142 | 10 | 8 Windows logon failures from one IP in 2 min | 100141 | T1110 | A device with a cached old password |
| 100143 | 8 | New user account created (4720) | winsec JSON | T1136.001 | Normal onboarding by IT |
| 100144 | 13 | Member added to Administrators / Domain Admins (4732) | winsec JSON | T1098 Account Manipulation | Approved admin changes (check the ticket) |

## Why these detections for an insurer

An insurer holds identity, financial, health and claims data on the same
platforms, and most staff have legitimate access to part of it. Perimeter
controls (NGFW, IPS, XDR) were already strong at the company where this lab was
built; what was missing was **correlation**. So the rules focus on:

- **Credential attacks** that turn into a valid session (100100 -> 100101).
- **Insider misuse of customer data**: bulk reads, repeated, or at night
  (100131-100133). This is the most insurance-specific family.
- **Attacks on internal business web apps** (100120-100129).
- **Privilege changes** on Linux servers and Windows/AD (100110, 100143, 100144).

## Coverage gaps (honest list)

Not detected yet - each one is a roadmap item:

- Lateral movement (T1021, T1570) - needs authentication events across hosts.
- Windows persistence (T1053 scheduled tasks, T1547 autostart) - needs real
  Windows event logs (Sysmon) instead of simulated JSON.
- Exfiltration over network channels (T1041, T1048) and DNS tunnelling
  (T1071.004) - needs network telemetry (Suricata / Zeek).
- Account created **and then** promoted to admin by the same actor - a
  two-step correlation (100143 -> 100144) planned for phase 4.
