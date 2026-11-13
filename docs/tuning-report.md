# False-positive review: 24 h of background traffic

**Question:** how many alerts of our custom rules does *normal* activity alone
produce in a working day? Phase 3 budget: **fewer than 20**.

**Answer (current rules):** see the generated section below - it is rewritten by
`python scripts/noise_report.py` from a real replay, never by hand.

## Method

1. `insurco_sim.timeline.background_timeline` produces 24 h of background events
   with the lab's own mix and office-hours profile (peak 0.7 ev/s = compose default,
   10% at night), for a Monday (a working day in Algeria). **No attack scenario.**
   The mix includes legitimate activity that *looks* malicious, as a real SOC sees
   it: bulk extracts by the reporting service account, web attack payloads from the
   internal vulnerability scanner, onboarding (account creation), access granted to
   business groups, mistyped passwords.
2. The events are replayed through the **real Wazuh 4.14.9 engine** (`wazuh-logtest`
   socket, one session) with the lab's manager configuration, decoders, CDB lists and
   rules. The replay image (`detection/replay/`) moves the analysisd clock to each
   event's simulated time, so `frequency` / `timeframe` / `ignore` windows and `<time>`
   rules behave as over a real day - in about 3 minutes.
3. Counted: alerts (level >= 3) of rules `100100-100199`. Built-in Wazuh rules
   (5715, 31108, ...) are reported but not counted: they are the platform's baseline,
   not our detections.

### How the clock is moved (and why it is trustworthy)

`clockshim.c` is a ~120-line `LD_PRELOAD` library, active only in `wazuh-analysisd`. It
adds an offset (read from a file the driver rewrites before each event) to the
realtime and monotonic clocks. One Wazuh detail made this harder than expected:
analysisd compares correlation windows against a **cached** `time(NULL)` refreshed by a
thread that loops on `sleep(1)` (`w_get_current_time()` in `analysisd.c`), so in
analysisd the shim also turns `sleep(n)` into `n` milliseconds.

Proof that it is exact, not approximate: with a 120 s window, 6 SSH failures 23 s apart
(115 s) fire 100100 and 6 failures 25 s apart (125 s) do not - repeated 5 times. The
same mechanism runs the `at:` cases of `detection/tests/cases.yaml` (e.g. a promotion 9
minutes after an account creation fires 100145, 11 minutes after does not).

## Tuning log

Each change is also recorded next to the rule in `docs/detection-catalog.md`.

| Step | Change | Custom alerts / 24 h |
|---|---|---|
| 0 | Phase 3 rules with the CDB allow-lists, before any threshold change | **2101** (100141: 1800, 100102: 298, 100143: 3) |
| 1 | **100141** Windows logon failure: level 5 -> **2** (below `log_alert_level` 3). Still matched and still counted by the correlation 100142 (8 failures / 2 min / IP), proven by the `windows password guessing` case | 301 (derived: step 0 minus the 1800 alerts of 100141, which feeds no other alert in this background; not replayed separately) |
| 2 | **100102** SSH login at night: only from **outside** `10.20.0.0/16`; new **100103** (level 10): night login to `root` / `admin` / `administrator` from anywhere | **3** |
| - | For reference: step 2 rules **without** the allow-lists (`--lists` pointing to placeholder lists) | 605 (100131: 253, scanner web rules: 243, 100129: 70, 100132: 15, 100133: 21, 100143: 3) |

### Why these changes, and what they cost

- **100141 (1800/day).** A single mistyped Windows password is not something an analyst
  can act on; 1800 of them a day would bury everything else. The signal is the
  *pattern* (100142), which keeps working. Cost: one-off failures are no longer
  alerts (still in the archives, `logall`).
- **100102 (298/day).** Every one was a staff account logging in from the office
  network at night (the night residue of the profile: on-call, backups, people
  finishing work). Nobody triages 300 alerts a night, so the rule was useless as it
  was. What stays alerting is what a human should look at: a night login from outside
  the internal network (100102) and a night login to a privileged or shared account
  (100103). **Cost - accepted gap:** an insider logging in at night *from the office
  network* with their own account no longer alerts on the login itself. The insurer's
  real night-time risk - customer data - stays covered by 100133 (any bulk read at
  night, level 13) and 100134 (mass access at night, level 14).
- **100143 (3/day, kept).** Account creation is normal onboarding, rare, and auditors
  want each one seen. It is the whole remaining budget and is accepted.
- **No frequency threshold had to move.** The headroom table below shows how far the
  background stays from each correlation threshold: tightening them would buy nothing,
  loosening them would cost detections.
- **Allow-lists are deliberately narrow.** `scanner-ips` silences the scanner on the web
  rules only (100120-100123, so 100129) - not on authentication. `db-service-accounts`
  is matched on the account name only: a stolen `svc_reporting` password used from
  another host would also be silent (gap, see the catalog).

## Limits of this review

- One simulated day, one seed. The background is a weighted random mix, not a real
  insurer's logs; phase 4 replays real services.
- Weekend days (x0.2 activity) produce fewer alerts; the working day is the worst case.
- The count is per rule *alert*; an analyst would group some of them into one case.

## Result (generated)

<!-- BEGIN GENERATED: noise (scripts/noise_report.py - do not edit by hand) -->
Replay of **24 h** of background traffic (no attacks), Monday from 00:00, seed `7`, peak rate 0.7 ev/s, office-hours profile; rules from `detection/rules/insurco_rules.xml` as committed.

- Events replayed: **30904** (db 6344, linux 8748, web 9365, workstation 6447)
- Alerts of built-in Wazuh rules (not counted): 9251
- **Custom alerts: 3** - budget < 20: **within**

| Rule | Level | Detection | Alerts in 24 h |
|---|---|---|---|
| 100143 | 8 | New user account $(TargetUserName) created by $(SubjectUserName) | 3 |

Custom alerts per hour: 15h: 1, 16h: 1, 17h: 1.

Headroom of the frequency rules: the most events one entity (IP or user) reached in any
window of the rule, in this background, against the rule's threshold.

| Rule | Threshold | Window | Max reached by one entity | Entity |
|---|---|---|---|---|
| 100100 | 6 | 120 s | 3 | 10.20.10.22 |
| 100129 | 5 | 300 s | 0 | - |
| 100132 | 5 | 300 s | 0 | - |
| 100142 | 8 | 120 s | 3 | 10.20.10.14 |

Examples (first two per rule):

```text
100143  15:56:15 workstation: {"log_type": "winsec", "timestamp": "2026-11-16T15:56:15", "EventID": 4720, "WorkstationName": "WS-CLAIMS-02", "SubjectUserName": "it.admin", "TargetU
100143  16:43:41 workstation: {"log_type": "winsec", "timestamp": "2026-11-16T16:43:41", "EventID": 4720, "WorkstationName": "WS-CLAIMS-02", "SubjectUserName": "it.admin", "TargetU
```
<!-- END GENERATED: noise -->
