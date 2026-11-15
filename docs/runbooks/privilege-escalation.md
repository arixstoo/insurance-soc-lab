# Runbook - Privilege escalation and rogue admin (rules 100110, 100143, 100144, 100145)

**Severity:** 100110 high (12) · 100143 low (8) · 100144 critical (13) · 100145 critical (15)
**MITRE:** T1548.003 Sudo and Sudo Caching, T1136.001 Create Account: Local Account, T1098 Account Manipulation
**Why it matters at an insurer:** an administrator account opens everything
the business relies on - claims validation, payment runs, the customer
database, the logs that would show the fraud. Creating a fresh admin account is
how an intruder stays after the first password is changed, and how an insider
approves their own claim payments.

| Rule | Means |
|---|---|
| 100110 | `sudo` to a root shell (`sudo bash`, `sudo su`) or a change to `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `passwd root` |
| 100143 | a new Windows account was created (event 4720) |
| 100144 | an account was added to `Administrators` / `Domain Admins` (event 4732) |
| 100145 | **an account created and made admin within 10 minutes** (100143 then 100144, same account) |

## 1. Triage (L1, 10 minutes)

1. Note who did it and to what:
   - 100110: `data.srcuser` (who ran sudo), `data.command`, `agent.name`.
   - 100143-100145: `data.SubjectUserName` (the actor), `data.account` /
     `data.TargetUserName` / `data.MemberName` (the account), `data.GroupName`.
2. **Is there a change ticket?** Ask the IAM / system team for an approved
   request matching the account and the time. 100143 with an onboarding
   ticket is normal (1-3 a day): close it.
3. 100144 or 100145 with no ticket: escalate **now**, both are level 13+.
   An account named like a temporary or test account (`tmp_*`, `test*`)
   promoted to admin is the classic persistence pattern.
4. 100110: is `srcuser` an administrator during a maintenance window?
   `sudo bash` out of habit is the known false positive (coach, keep the
   alert). A non-admin user, a service account, or a change to
   `/etc/shadow` / `/etc/sudoers`: escalate.

## 2. Investigation (L2)

- Who is the actor (`SubjectUserName` / `srcuser`) and how did they log in just
  before? SSH alerts 100100-100103, Windows logons 4624 / failures 100142 on the
  same host.
- What did the new admin account do next? Logons with it, further group
  changes, other accounts created by the same actor.
- 100110: the commands that followed on the same host (archives), new users,
  new SSH keys, cron jobs, changes under `/etc`.
- Was the actor's own account compromised (brute force, unusual source IP)?

## 3. Containment (with the system owner)

- Remove the account from the admin group and disable it; keep it (do not
  delete) until the investigation is over.
- If the actor's account is suspected: disable it too, reset its password,
  revoke sessions and tokens.
- Linux: restore `/etc/sudoers`, `/etc/passwd`, `/etc/shadow` from a known
  good state if they changed; rotate the root password.
- Preserve evidence: the Windows security log / `auth.log`, the alerts.

## 4. Close

Record: true/false positive, accounts created or promoted, the actor, the
ticket (or its absence), tuning (none on 100144 / 100145: an approved change is
checked, not muted), time to detect and time to contain.
