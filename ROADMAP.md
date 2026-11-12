# Roadmap

Each phase ends with something that **works and is shown**: a tagged release,
and one piece of content (LinkedIn post / Instagram "LE LAB" episode).
Status: ✅ done · 🔨 in progress · ⬜ planned

| Phase | Theme | Release | Status |
|---|---|---|---|
| 0 | Foundations: repo, CI, tested rules | `v0.1.0` | ✅ |
| 1 | Hardened one-command SIEM | `v0.2.0` | ✅ |
| 2 | Endpoints and telemetry v3 | `v0.3.0` | ✅ |
| 3 | Detection engineering v2 | `v0.4.0` | ⬜ |
| 4 | Real services, real attacks in the lab | `v0.5.0` | ⬜ |
| 5 | SOC dashboards as code + MITRE layer | `v0.6.0` | ⬜ |
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

## Phase 3 - Detection engineering v2 ⬜

**Goal:** go from "rules that fire" to "rules a SOC can trust".

- [ ] Two-step correlation: account created **then** promoted to admin by the same actor
- [ ] Night-time insider gap (found by the e2e work): between 22:00 and 06:00 every bulk read
      fires 100133 *instead of* 100131, so the mass-access correlation 100132 never fires at
      night. Correlate on a group shared by 100131 and 100133 (+ a night test case)
- [ ] Allow-lists as CDB lists (service accounts, scanner IPs) to cut false positives
- [ ] Custom decoder for the DB audit format (instead of generic JSON)
- [ ] Negative tests for every rule (normal activity that must stay quiet)
- [ ] Rule documentation generated from the XML into `docs/detection-catalog.md`
- [ ] False-positive review on 24 h of simulated traffic; tune thresholds

**Done when:** each rule has at least one positive and one negative test, and
24 h of background traffic produces fewer than 20 custom alerts.
**Content:** LinkedIn - "What a detection rule really is, and how to test one".

## Phase 4 - Real services in the lab ⬜

**Goal:** add real telemetry next to the simulated one.

- [ ] Linux host running real `sshd` + `rsyslog` + `auditd`
- [ ] Web host running a real web server whose access log feeds `srv-web-01`
- [ ] Database host with a real PostgreSQL and `pgaudit` (real audit trail for rules 10013x)
- [ ] Safe, scripted test traffic from inside the lab network only (failed logins,
      malformed web requests), to validate the rules on genuine logs
- [ ] Optional: Windows VM with Sysmon for real Windows events

**Done when:** the same rules fire on both simulated and real logs.

## Phase 5 - SOC dashboards as code ⬜

**Goal:** dashboards that rebuild themselves after a reset.

- [ ] "SOC Overview" and "Insurer Security" dashboards exported as `.ndjson` in `dashboards/`
- [ ] `scripts/import-dashboards.sh` (Dashboards saved-objects API)
- [ ] Panels filter on rule IDs and groups that tests prove exist
- [ ] MITRE ATT&CK Navigator layer (`docs/mitre-layer.json`) generated from the rules
- [ ] Screenshots for the README

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
