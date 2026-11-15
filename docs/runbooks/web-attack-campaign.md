# Runbook - Web attack campaign (rules 100120, 100121, 100122, 100123, 100129)

**Severity:** 100120 high (11) · 100121 / 100122 medium (10) · 100123 low (8) · 100129 critical (13)
**MITRE:** T1190 Exploit Public-Facing Application, T1083 File and Directory Discovery, T1595.003 Wordlist Scanning
**Why it matters at an insurer:** the customer and broker portals (quotes, claims
follow-up, document downloads) sit in front of the policy database. One working
SQL injection or path traversal there exposes customer identities, medical
details of claims and bank details (IBAN) for refunds.

| Rule | Means |
|---|---|
| 100120 | SQL injection pattern in a request (built-in 31103 / 31164 / 31170 / 31171) |
| 100121 | Cross-site scripting pattern (31105) |
| 100122 | Path traversal (`../`, `%2e%2e`) |
| 100123 | Probe for secrets or backups (`.env`, `.git/`, `*.sql`, `wp-config.php`) |
| 100129 | **5 of the above from one IP in 5 minutes**: someone is working on the site |

The internal vulnerability scanner (`scanner-ips` list) never raises these rules.

## 1. Triage (L1, 10 minutes)

1. Note `data.srcip`, `agent.name` (which portal), `data.url`, `data.id` (HTTP
   status) and the time.
2. **Look at the status codes**, not only the payloads. `400` / `403` / `404`
   = blocked or nothing there. `200` on a SQL injection or traversal URL, or an
   unusually large response, = it may have worked: escalate immediately.
3. Is `srcip` an announced penetration test (change calendar)? Yes -> false
   positive, propose a temporary entry in `scanner-ips` for the test window only.
4. 100129 without any `200` on attack URLs: escalate as "campaign, no success
   seen" (L2, same day). With a `200`: escalate as an incident (now).
5. Scope: dashboard *Insurer Security* -> "web campaigns by technique", or
   `rule.groups:insurco_web and data.srcip:"<ip>"`.

## 2. Investigation (L2)

- Replay the requests of `srcip` in order (archives or the web server's access
  log): what did they try, in which parameter, and what came back?
- For a `200` on SQL injection: the application and database logs at the same
  second (DB audit: 100130 / 100135 events, bulk reads 100131 / 100137).
- For a `200` on path traversal or a secrets probe: was a file really served
  (`.env`, a backup)? Treat every secret in it as leaked.
- Same `srcip` in other families (SSH 100100, Windows 100142)?
- Is it a known scanner range or a single targeted source (user agent, pace,
  only our business URLs)?

## 3. Containment

- Block `srcip` on the WAF / reverse proxy (not on the web server itself, which
  usually sees the proxy's address).
- If something was served: rotate the leaked secrets, take the vulnerable page
  offline or put a virtual patch on the WAF, open a fix ticket with the
  application owner.
- If customer data was read: management and the DPO decide on a personal-data
  breach notification (Algeria: law 18-07, authority: ANPDP).

## 4. Close

Record: true/false positive, attempted techniques, any successful request,
the fix (WAF rule, code change, secret rotation), tuning (scanner list entry
with an end date), time to detect and time to contain.
