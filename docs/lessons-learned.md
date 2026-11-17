# Lessons learned

What building this lab taught me, phase by phase. Each point was found by a failing test, a
red e2e run or a replay, not by reading documentation; the commit or release that found it is
in the [CHANGELOG](https://github.com/arixstoo/insurance-soc-lab/blob/main/CHANGELOG.md), and
the short form lives in `CLAUDE.md` ("Wazuh facts learned the hard way").

## 1. A rule is only real once the engine has run it

Reading the XML is not enough. Every rule here has a positive and a negative case run through
`wazuh-logtest` on the same image, configuration, decoders and lists as the lab
(`detection/tests/run_tests.py`, 98 cases), and a unit test fails when a rule has no case.
The first runs broke several "obviously correct" rules:

- `frequency`, `timeframe` and `ignore` are **attributes** of `<rule>`, not child elements.
- Parent rule IDs must come from the upstream ruleset of the exact version
  (`wazuh/wazuh` tag `v4.14.9`): sshd failed password is `5760`, accepted is `5715`.
- Until v0.4.0 the tests ran on the image's default `ossec.conf`, not the lab's: they
  passed on a configuration nobody deployed.

## 2. How the Wazuh engine really picks a rule

The behaviours that cost the most time, all now covered by tests:

- **One event raises one alert.** The event that completes a correlation raises the
  correlation *instead of* its own rule, so a scenario must send each kind of event more
  than once (the first e2e run lost 100122 that way).
- **Sibling rules are tried by level, highest first**, not in file order. A level 12
  threat-intel child of 5715 took the night logins of 100102 (level 8); a new child must sit
  below the siblings it must not shadow.
- **A child rule replaces its parent's alert.** A blanket "known-bad IP" rule on every event
  starved the brute-force correlation and therefore the active response. Threat-intel rules
  only go on events nothing correlates on - Wazuh's own IoC rules have the same flaw.
- **`ignore` mutes the whole rule**, not one source: a second attacker inside the window
  raises no correlation. Documented as a coverage gap rather than hidden.
- An `if_matched_group` rule only sees group rules defined **before** it in the file, and two
  parents on a rule that feeds a group correlation broke it: real-trail twins instead
  (100137 / 100138), kept identical by a test.
- Decoder files are ordered by **file name** across folders and the first matching parent
  wins: the `0005-` prefix is what lets the lab's JSON decoders beat the generic one.
- `<same_field>` compares a field with itself, so the account is normalised in the decoder.

## 3. Time is the hardest input

- `<time>` uses the **manager's clock at analysis time**, not the log timestamp. Night rules
  are tested by starting the engine at 02:00 or 12:00.
- analysisd runs chrooted without zoneinfo: `TZ=Africa/Algiers` silently falls back to UTC,
  POSIX strings work.
- Correlation windows use a cached clock refreshed every second. To test "9 minutes vs
  11 minutes" without waiting, `detection/replay/clockshim.c` (`LD_PRELOAD`) moves
  analysisd's clock to each line's simulated time; the same engine replays 24 h of traffic in
  about 3 minutes.
- A busy CI runner exposed every assumption about settling times (5 ms was not enough, hour
  boundaries need longer): each was fixed by measurement, with the value in the code.

## 4. Noise is a feature to measure, not a feeling

24 h of normal activity, replayed through the real engine, first gave **2101** custom alerts.
Two documented decisions brought it to **3**: a single Windows logon failure dropped below the
alert level (it still feeds the password-guessing correlation) and night SSH logins only alert
from outside the network or to privileged accounts. Each cut has its accepted gap written down
next to it in [the tuning report](tuning-report.md); the report is regenerated, never edited.
Allow-lists (service accounts, the internal scanner) are CDB lists in git, not exceptions in
the rules.

## 5. End-to-end tests find what unit tests cannot

The e2e workflow starts the whole lab on a GitHub runner and checks every expected rule in the
indexer. It found:

- log files created after the agent started were never read, and agents restart their daemons
  when the shared configuration arrives ~30 s after enrolment;
- `rogue_admin` flaked for two releases: the two Windows events were 0.2 s apart, inside one
  2-second logcollector poll, so they could be analysed in the wrong order. The first
  explanation ("milliseconds apart") was wrong and was corrected in the changelog;
- a burst of reads 40 ms apart could miss a correlation on a loaded runner.

A release note says what was verified and what was not: `v0.7.0` records that `main` went red
after its merge and why.

## 6. Response must be scoped before it is automated

Active response only blocks the source of one critical rule (100101), on the targeted host, for
10 minutes, with `NET_ADMIN` on that container only, never `privileged`. The live check proves
the block **and** its expiry. The webhook receiver escapes every attacker-controlled field and
is read-only on the host port.

## 7. Portability has limits worth writing down

The Sigma versions are checked to **agree with the Wazuh rules on the same test cases**, which
is stronger than "they validate". What Sigma cannot express here - time of day, `ignore`,
Wazuh built-in parents - is listed in the catalog instead of pretending the translation is
complete.

## 8. Engineering habits that paid off

- **Configuration as code**: no `docker exec ... sed`. Every fix is a file in the repo and a
  rebuild, so `down -v` never loses one.
- **Generated docs with a `--check` in CI** (rule catalog, ATT&CK layer, threat-intel sample,
  dashboards): docs and code cannot drift silently.
- **Pinned everything**: Wazuh version for every image and the agent, GitHub Actions by SHA,
  scanner images by digest.
- **Anonymisation as a rule, checked by grep**: only `10.20.0.0/16` and RFC 5737 addresses,
  a fictional insurer, synthetic data.
- Windows host quirks (Git Bash path rewriting, Hyper-V reserved ports, auditd refused in
  WSL2 containers) are written down once, in `CLAUDE.md`.
