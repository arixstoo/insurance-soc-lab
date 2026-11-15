# Runbook - Windows password guessing (rules 100141, 100142)

**Severity:** 100141 building block (2, no alert) · 100142 medium (10)
**MITRE:** T1110 Brute Force (password guessing and spraying)
**Why it matters at an insurer:** agency and claims workstations are shared,
used by many staff and sometimes by brokers. One internal machine trying many
passwords - one account after the other (spraying) or the same account again
and again - is either malware moving laterally or a person looking for a
colleague's access to claims approval.

| Rule | Means |
|---|---|
| 100141 | one failed Windows logon (event 4625). Level 2: counted, never shown as an alert (it was ~1800 alerts a day at level 5) |
| 100142 | **8 failed logons from the same `IpAddress` in 2 minutes**, whatever the account |

## 1. Triage (L1, 10 minutes)

1. Note `data.IpAddress` (the source machine), `agent.name`, and the accounts
   tried. 100141 is below the alert level, so the individual failures are not
   in the alerts index: read the 4625 events of that `IpAddress` in the manager
   archives (`logall`, `/var/ossec/logs/archives/archives.json`) or on the
   workstation itself.
2. **One account, many failures** = a device or a script with an old cached
   password (the known false positive): find the device, fix it, close.
3. **Many accounts, a few failures each** = spraying: escalate to L2 now.
4. Did any of the tried accounts then log on successfully (4624) from the same
   `IpAddress`? If yes, treat that account as compromised: escalate now.

## 2. Investigation (L2)

- Which machine is `IpAddress` and who was logged on it (DHCP / inventory,
  4624 events)? A server or a workstation nobody uses at that hour is worse.
- Which accounts were tried? Admin accounts, service accounts, or a list of
  real staff names (someone knows the naming scheme)?
- Any other alert from the same source: web attacks, SSH brute force, account
  creation or admin group changes (100143-100145)?
- Malware on the source machine: EDR / antivirus alerts, unusual processes.

## 3. Containment (with the IT team)

- Isolate the source machine from the network (EDR isolation or switch port),
  do not power it off (memory evidence).
- Reset the password of every account that logged on successfully from it, and
  force a password change for the tried accounts if the attempts were close to
  the lockout threshold.
- Check the lockout policy actually applies (a spray stays under it on purpose).

## 4. Close

Record: true/false positive, source machine, accounts tried and any success,
root cause (cached credential, malware, person), tuning (fix the device rather
than raising the threshold), time to detect and time to contain.
