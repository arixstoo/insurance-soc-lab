# SOC runbooks

One runbook per alert family: what to check, who to call, when to escalate.
Each rule links its runbook with Wazuh's `<info type="link">` element, so the link is in
the rule, in the [detection catalog](../detection-catalog.md) and in the webhook message
of every alert of level 12 or more ([response.md](../response.md)).
`scripts/gen_catalog.py --check` fails if an alerting rule (level >= 3) links no runbook
or a runbook that does not exist.

| Alert family | Rules | Runbook | Automatic response (lab) |
|---|---|---|---|
| SSH brute force / compromise | 100100-100103 | [ssh-brute-force.md](ssh-brute-force.md) | 100101: webhook + source IP blocked 10 min on the targeted host |
| Web attack campaign | 100120-100123, 100129 | [web-attack-campaign.md](web-attack-campaign.md) | 100129: webhook |
| Mass customer data access | 100131-100134, 100137, 100138 | [insider-data-access.md](insider-data-access.md) | 100132, 100133, 100134, 100138: webhook |
| Privilege escalation / rogue admin | 100110, 100143-100145 | [privilege-escalation.md](privilege-escalation.md) | 100110, 100144, 100145: webhook |
| Windows password guessing | 100141, 100142 | [windows-password-guessing.md](windows-password-guessing.md) | - |

Template for new runbooks: **Severity · MITRE · Why it matters ·
1. Triage · 2. Investigation · 3. Containment · 4. Close.**
