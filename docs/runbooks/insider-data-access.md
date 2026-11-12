# Runbook - Mass customer data access (rules 100131, 100132, 100133)

**Severity:** 100131 low (7) · 100132 high (12) · 100133 critical (13)
**MITRE:** T1213 Data from Information Repositories, T1530, T1078
**Why it matters at an insurer:** one export of the `clients` or `claims`
tables is enough for identity theft, organised insurance fraud or resale to a
competitor. The person doing it usually has a legitimate account.

## 1. Triage (L1, 10 minutes)

1. Open the alert and note `data.db_user`, `data.table`, `data.rows_returned`,
   `data.source_ip`, and the time.
2. Is `db_user` a known service account for reporting/BI? If yes and the
   activity matches its schedule -> **false positive**, propose an allow-list.
3. How many bulk reads did this user do today? (Dashboard filter:
   `rule.id:100131 and data.db_user:"<user>"`)
4. Did it happen outside office hours (100133, or 100134 for repeated reads)? Escalate immediately.

## 2. Investigation (L2)

- Which workstation is `source_ip`? Who was logged on (4624 / 4625 events in the archives)?
- Is the user on leave, resigning, or recently moved to another department?
  (ask HR through the security manager - never contact the user directly)
- Any other alerts for the same user or IP: failed logins, sudo, new accounts?
- Did large outbound transfers follow (proxy / firewall logs)?

## 3. Containment (with management approval)

- Disable or lock the database account; revoke active sessions.
- Preserve evidence: export the related alerts and the DB audit trail.
- If customer data left the company, inform the DPO: personal-data breach
  notification duties apply (Algeria: law 18-07, authority: ANPDP).

## 4. Close

Record: true/false positive, root cause, tuning applied (allow-list,
threshold), time to detect and time to contain.
