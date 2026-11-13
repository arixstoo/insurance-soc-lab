# Roadmap

Each phase ends with something that **works and is shown**: a tagged release,
and one piece of content (LinkedIn post / Instagram "LE LAB" episode).
Status: ✅ done · 🔨 in progress · ⬜ planned

| Phase | Theme | Release | Status |
|---|---|---|---|
| 0 | Foundations: repo, CI, tested rules | `v0.1.0` | ✅ |
| 1 | Hardened one-command SIEM | `v0.2.0` | ✅ |
| 2 | Endpoints and telemetry v3 | `v0.3.0` | ✅ |
| 3 | Detection engineering v2 | `v0.4.0` | ✅ |
| 4 | Real services, real attacks in the lab | `v0.5.0` | ✅ |
| 5 | SOC dashboards as code + MITRE layer | `v0.6.0` | 🔨 |
| 6 | Response: runbooks, alerting, active response | `v0.7.0` | ⬜ |
| 7 | Portability: Sigma rules + threat intel | `v0.8.0` | ⬜ |
| 8 | Publication: docs, demo, v1.0 | `v1.0.0` | ⬜ |

---

## Phase 0 - Foundations ✅

**Goal:** a clean, public-ready repository where every rule is proven to work.

- [x] Repository layout, MIT license, third-party notice, security notes
- [x] Wazuh pinned to 4.14.9 (manager, indexer, dashboard **and** agent)
- [x] 16 custom rules with their parent rules and correlation syntax
- [x] 24 detection test cases run against the real engine (`wazuh-logtest`)
- [x] Simulator rewritten as a tested Python package (17 unit tests)
- [x] GitHub Actions: lint, unit tests, XML check, compose check, detection tests
- [x] Secret scanning (gitleaks) and CodeQL; Dependabot; issue/PR templates; contributing guide
- [x] Anonymization: insurer name, employees, real IPs, hostnames and credentials removed

**Done when:** `python detection/tests/run_tests.py` -> 24/24, CI green.

## Phase 1 - Hardened one-command SIEM ✅

**Goal:** `docker compose up -d` gives a working, reasonably secure SIEM.

- [x] All ports bound to `127.0.0.1`; secrets read from `.env`
- [x] Manager: `logall` on, agent re-enrollment without duplicates
- [x] `scripts/rotate-passwords.sh` (+ `.ps1`): generate strong passwords, hash them into
      a git-ignored `internal_users.yml`, update `.env`; `--apply` rotates a running lab
- [x] `make up / down / reset / status / test / lint / rotate` (and `scripts/lab.ps1`)
- [x] Health checks on manager / indexer / dashboard; agents wait for a healthy manager
- [x] Indexer retention policy (ISM): delete alert indices after 30 days (`scripts/apply_ism.py`)
- [x] Image scanning in CI (Trivy) for the agent and simulator images; fail on critical CVEs
- [x] Pin GitHub Actions to commit SHAs (supply-chain hygiene)
- [x] Deliberate base-image upgrades (Dependabot PRs #1 and #4): agent image on
      Ubuntu 26.04 (`wazuh-agent 4.14.9-1`), simulator on Python 3.15; verified with a
      clean lab start, all tests and a Trivy scan (0 critical)

**Done when:** a fresh clone reaches 4 active agents and a first custom alert
in under 10 minutes, with no default password left.
**Content:** LinkedIn - "A one-command SOC lab for an insurance company, built during my internship".

## Phase 2 - Endpoints and telemetry ✅

**Goal:** realistic, continuous telemetry, one agent per host.

- [x] Agent image with config rendered from a template (no `docker exec` edits)
- [x] One log folder per host, mounted read-only (no duplicated events)
- [x] Simulator v3: weighted daily activity + 6 attack scenarios, seedable
- [x] Office-hours profile: full activity 08:00-18:00 with 1 h ramps, 10% at night, x0.2 on
      Fri/Sat (the Algerian weekend); configurable (`SIM_PROFILE`, `SIM_OFFICE_HOURS`, ...),
      unit tested with a fake clock. Attacks keep their own schedule.
- [x] Trigger any scenario on demand: `docker compose exec simulator insurco-sim inject <scenario>`
- [x] Measure: `insurco-sim stats` (events per host per minute, ev/s) and
      `scripts/measure_latency.py` (log line -> alert -> searchable in `wazuh-alerts-*`)
- [x] **End-to-end test in CI** (`e2e.yml`, `scripts/e2e.sh`): start the full lab on a GitHub
      runner, wait for 4 active agents, inject every scenario, assert each expected rule
      appears in the indexer, then tear down (compose logs uploaded on failure).
      Night-only rules (100102, 100133) are excluded and the manager clock is pinned to midday

**Done when:** `scripts/lab_status.py` shows 4 active agents and every
scenario's expected rules in alerts within 10 minutes.
**Content:** Instagram LE LAB - "a fake insurance company that attacks itself every 3 minutes".

## Phase 3 - Detection engineering v2 ✅

**Goal:** go from "rules that fire" to "rules a SOC can trust".

- [x] Two-step correlation: account created **then** added to an admin group, same account,
      within 10 min (100145, level 15). The account is normalised by the decoder (4720
      `TargetUserName`, 4732 `MemberName`); the actor may differ. Tested both ways, including
      9 vs 11 minutes on the replay engine
- [x] Night-time insider gap (found by the e2e work): 100132 now counts the group
      `insurco_bulk_read` shared by 100131 and 100133, and a night variant 100134 (child of
      100133, which Wazuh evaluates first) fires at night; reads across 22:00 add up
- [x] Allow-lists as CDB lists (`detection/lists/`: `db-service-accounts`, `scanner-ips`), mounted
      through `/wazuh-config-mount`; ~600 fewer false positives a day
- [x] Custom decoders for the DB audit and Windows JSON formats (`insurco-db-audit`,
      `insurco-winsec`), instead of the generic JSON decoder
- [x] Negative tests for every rule (normal activity that must stay quiet), enforced by a unit test;
      time-window cases (`at:`) on a replay engine whose clock follows the simulated time
- [x] Rule documentation generated from the XML into `docs/detection-catalog.md`
      (`scripts/gen_catalog.py`, CI `--check`)
- [x] False-positive review on 24 h of simulated traffic replayed through the real engine
      (`scripts/noise_report.py`, `docs/tuning-report.md`): 2101 -> 3 custom alerts
- [x] Release `v0.4.0` (CI green, lab restarted from a clean state)

**Done when:** each rule has at least one positive and one negative test, and
24 h of background traffic produces fewer than 20 custom alerts.
**Content:** LinkedIn - "What a detection rule really is, and how to test one".

## Phase 4 - Real services in the lab ✅

**Goal:** add real telemetry next to the simulated one
([docs/real-services.md](docs/real-services.md)).

- [x] Compose profile `real` (`docker compose --profile real up -d`, `make up REAL=1`): the
      default lab is unchanged; real hosts built FROM the lab agent image
- [x] Linux host `real-linux-01` running real `sshd` (OpenSSH 10) + `rsyslog` + `auditd`; its
      agent reads the real `/var/log/auth.log`. auditd is best effort: most Docker kernels
      refuse an audit daemon in a container (documented, rules and agent input in place)
- [x] Web host `real-web-01`: real nginx serving a static claims portal; its agent reads the
      real access log (its own agent, next to the simulated `srv-web-01`)
- [x] Database host `real-db-01`: PostgreSQL 18 + `pgaudit`, FAKE seed data (Faker, seeded),
      decoder `insurco-pgaudit`, rules 100135-100138 feeding the shared correlations 100132 / 100134
- [x] Safe, scripted test traffic from inside the lab network only (`real-client`,
      `lab-traffic`): failed + successful SSH logins (sshpass), the `real: true` malformed
      requests of `cases.yaml` (curl), normal queries and a bulk export (psql); internal
      network, lab targets only, per-lab generated passwords
- [x] `e2e.yml` runs with the profile: expected rules asserted per real host, and every
      detection family seen on both simulated and real logs
- [ ] Optional: Windows VM with Sysmon for real Windows events
- [x] Release `v0.5.0` (CI green, e2e with the real profile green)

**Done when:** the same rules fire on both simulated and real logs.

## Phase 5 - SOC dashboards as code 🔨

**Goal:** dashboards that rebuild themselves after a reset.

- [x] "SOC Overview" and "Insurer Security" dashboards exported as `.ndjson` in `dashboards/`,
      defined in `scripts/build_dashboards.py` and built through the saved-objects API
      (`_bulk_create`, then `_export`), not clicked together by hand
- [x] `scripts/import_dashboards.py` (saved-objects `_import?overwrite=true`, idempotent),
      run by `make up` / `lab.ps1 up` and therefore by the e2e workflow
- [x] Panels filter on rule IDs and groups that tests prove exist
      (`detection/tests/test_dashboards.py`: alert level >= 3 and a positive case)
- [x] MITRE ATT&CK Navigator layer (`docs/mitre-layer.json`) generated from the rules
      (`scripts/gen_mitre_layer.py`, CI `--check`), colour = number of rules per technique
- [x] Screenshots for the README, taken headless (`scripts/screenshot_dashboards.py`) on a lab
      restarted from `down -v` with every scenario injected
- [ ] Release `v0.6.0` (CI green)

**Done when:** after `make reset`, both dashboards show data with no manual click.
**Content:** Instagram carousel - "what an analyst sees in the first 30 seconds".

## Phase 6 - Response ⬜

- [ ] Runbooks for every alert family (template in `docs/runbooks/`)
- [ ] Alert routing: level >= 12 to a webhook (e.g. a self-hosted notification channel)
- [ ] Active response: temporary block of the source IP on brute force (lab only)
- [ ] Optional: Shuffle SOAR workflow (enrich IP -> open ticket -> notify)

## Phase 7 - Portability and threat intel ⬜

- [ ] Sigma versions of the main rules (feeds the `sigma-rules-collection` repo)
- [ ] Threat-intel CDB list of known-bad IPs, refreshed by a script
- [ ] Optional: send IoCs to an `ioc-hunter` CLI (separate repo)

## Phase 8 - Publication ⬜

- [ ] README with architecture diagram, GIF demo, screenshots, badges
- [ ] Social preview image, topics, pinned as repo #1
- [ ] `v1.0.0` release notes
- [x] French summary (`docs/README.fr.md`)
- [ ] Documentation site (MkDocs Material on GitHub Pages) built from `docs/`
- [ ] Talk / workshop material: "Build a SOC lab in an afternoon"
