# Lessons learned - from the internship lab to this repository

The first version of this lab was built in April-May 2026, during my internship
in the IT security team of a large Algerian insurance company, on a single Kali
VM with Docker. It worked well enough for a demo, but the custom detection
rules - the actual point of the project - **never fired**. The last diagnostic
showed only Wazuh's built-in rule IDs in the index.

This repository is the rebuild. Below is what went wrong, why, and what changed.

| # | Symptom in 2026 | Root cause | Fix in this repo |
|---|---|---|---|
| 1 | Agents refused to enroll: `Agent version must be lower or equal to manager version` | Dockerfile installed the latest agent (4.8) against a 4.7 manager | One `WAZUH_VERSION` variable pins manager, indexer, dashboard **and** agent (`agents/Dockerfile`) |
| 2 | socat "proxy" container exited, agents could not reach port 1515 | Unneeded extra hop; `host-gateway` did not route between Docker networks | No proxy: all services share one Docker network and use DNS names |
| 3 | `PermissionError` writing `/var/log/<company>-simulation` | Generator wrote to a root-owned system path; a `sudo` test run then left root-owned folders | Simulator runs in its own container as an unprivileged user and owns its volume |
| 4 | Events arrived "in waves" | Fixed `sleep(10)` loop plus logcollector batching | Exponential inter-arrival times (`rng.expovariate`) - irregular, continuous flow |
| 5 | Every event appeared on all 4 agents | All agents read the same shared log files | One folder per host; each agent mounts **only** its folder, read-only |
| 6 | Config fixes "disappeared" | Changes were made with `docker exec ... sed` inside containers; they were lost each time a container was recreated | Configuration as code: agent config rendered from a template at start; rules mounted from git |
| 7 | Agent IDs 001, 002, 004, 005 (003 missing) | Recreated containers enrolled again and got new IDs | `<auth><force>` on the manager: same name replaces the old key |
| 8 | Brute-force rule never fired | Parent was rule **5710** (non-existent user only). `Failed password` lines match **5760** | Parent `5760` - verified with `wazuh-logtest` |
| 9 | "Login after brute force" and "after-hours login" never fired | Parent was **5501** (PAM session). `Accepted password` lines match **5715** | Parent `5715` - verified |
| 10 | Correlation rules were ignored | `frequency`/`timeframe` written as child elements; in Wazuh they are attributes of `<rule>` (see built-in rule 5763) | Attribute syntax, covered by tests |
| 11 | After-hours rules could not be demonstrated | `<time>` is checked against the **manager clock at analysis time**, not the log timestamp; injecting `02:30` in a log line has no effect | Test runner starts the manager with a TZ where it is 02:00 or 12:00 |
| 12 | Insider-threat rule only matched because the log said so | Generator wrote `"alert": "MASS_DATA_ACCESS"` into the log, and the rule matched that field | Rule now looks at what a DB audit log really contains: table name and `rows_returned`, then correlates 5 bulk reads per user |
| 13 | Dashboard 2 panels were empty | Filters on `rule.groups` values that no rule produced (because custom rules never fired) | Fixed rules first; dashboards filter on rule IDs and groups that tests prove exist |
| 14 | Nothing proved a rule worked until it showed up (or not) in the UI | No tests | 24 test cases run against the real engine, locally and in CI |
| 15 | The whole project was lost when the internship ended | Code lived only on the company VM; nothing was pushed anywhere | This repository |

## What I would tell myself in April 2026

1. **Test the rule before you build the dashboard.** `wazuh-logtest` answers in
   one second the question I spent two weeks asking the dashboard.
2. **Never fix a container from the inside.** If the fix is not in a file in git,
   it does not exist.
3. **Read the parent rule.** A child rule is only as good as the rule it hangs
   from. Open `0095-sshd_rules.xml` and check what actually fires.
4. **Push your work every day** - even to a private repository.
