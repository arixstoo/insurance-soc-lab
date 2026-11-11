# SOC runbooks

One runbook per alert family: what to check, who to call, when to escalate.

| Alert family | Rules | Runbook |
|---|---|---|
| Mass customer data access | 100131-100133 | [insider-data-access.md](insider-data-access.md) |
| SSH brute force / compromise | 100100-100102 | planned (roadmap phase 6) |
| Web attack campaign | 100120-100129 | planned (roadmap phase 6) |
| Privilege escalation / rogue admin | 100110, 100143, 100144 | planned (roadmap phase 6) |

Template for new runbooks: **Severity · MITRE · Why it matters ·
1. Triage · 2. Investigation · 3. Containment · 4. Close.**
