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
| 5 | SOC dashboards as code + MITRE layer | `v0.6.0` | ✅ |
| 6 | Response: runbooks, alerting, active response | `v0.7.0` | ✅ |
| 7 | Portability: Sigma rules + threat intel | `v0.8.0` | ✅ |
| 8 | Publication: docs, demo, v1.0 | `v1.0.0` | ✅ |

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

## Phase 5 - SOC dashboards as code ✅

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
- [x] Release `v0.6.0` (CI and e2e green, lab restarted from a clean state)

**Done when:** after `make reset`, both dashboards show data with no manual click.
**Content:** Instagram carousel - "what an analyst sees in the first 30 seconds".

## Phase 6 - Response ✅

**Goal:** an alert becomes an action: a runbook, a message, a timed block
([docs/response.md](docs/response.md)).

- [x] Runbooks for every alert family (`docs/runbooks/`, same template): SSH brute force /
      compromise, web campaign, insider data access, privilege escalation / rogue admin,
      Windows password guessing. Each rule links its runbook (`<info type="link">`), shown
      in the catalog; `gen_catalog.py --check` fails on an alerting rule without one
- [x] Alert routing: level >= 12 to a webhook through a custom Wazuh integration
      (`response/integrations/`, Slack/Mattermost-compatible `text`, retries), received
      offline by the lab's `webhook-receiver` (ingest on the lab network, read-only viewer on
      `localhost:8088`, attacker text escaped)
- [x] Active response (lab only): on 100101, `firewall-drop` blocks the source IP on the
      targeted host (`location local`) for 600 s, then execd lifts it; `NET_ADMIN` on the two
      SSH hosts only. Proven live by `scripts/check_response.py` (simulated and real host:
      the real client's TCP connections to sshd time out, then work again)
- [x] Response flow documented with a mermaid sequence diagram
- [x] Release `v0.7.0` (CI green; e2e green on the release branch, red once on `main` after the
      merge - the `rogue_admin` / 100145 flake, fixed after the release; lab restarted from a clean state)
- [ ] Optional: Shuffle SOAR workflow (enrich IP -> open ticket -> notify)

**Done when:** injecting `brute_force` produces the alert, the webhook message and the
timed block, and the block expires by itself.

## Phase 7 - Portability and threat intel ✅

**Goal:** detections that leave Wazuh, and alerts that know about the outside world.

- [x] Sigma versions of the main rules (feeds the `sigma-rules-collection` repo):
      `detection/sigma/rules/`, 13 rules (brute force, web attacks + campaign, insider bulk
      read on both audit trails + mass access, rogue admin), Sigma v2 correlations
      (`event_count`, `temporal_ordered`, aliases), allow-lists as placeholders
- [x] Sigma tests in CI (`detection/tests/test_sigma.py`): pySigma 2.1 validators (ATT&CK tags
      included), mapping to existing Wazuh rules, same ATT&CK techniques, same windows and
      thresholds, and **agreement with the Wazuh rules on the cases of `cases.yaml`**
      (positive and negative for every Sigma rule)
- [x] Catalog: which Wazuh rule each Sigma rule stands for (generated), field mapping,
      limits of the translation (time of day, `ignore`, built-in parents, SIDs, ...)
- [x] Threat-intel CDB list of known-bad IPs, refreshed by a script: `scripts/update_ti.py`
      (public feed configurable, cached 24 h, offline fallback to the cache then to a sample
      list in the repo, private ranges never listed), `make ti` / `lab.ps1 ti`; CI checks the
      committed list is the sample build
- [x] TI rules 100150-100154 raise activity from a listed IP without breaking the
      correlations or the active response (proven by tests: a blanket child rule would
      have); runbook `threat-intel-hit.md`
- [x] Release `v0.8.0` (CI and e2e green, lab restarted from a clean state)
- [ ] Optional: send IoCs to an `ioc-hunter` CLI (separate repo)

**Done when:** CI validates the Sigma rules; the TI rules are tested with the sample list.

## Phase 8 - Publication ✅

**Goal:** a stranger can clone, follow the README and see alerts in about 10 minutes.

- [x] README with architecture diagram, GIF demo (`scripts/make_demo_gif.py`, from a recorded
      `make up` + `make status`), screenshots, badges, "What I learned"
      ([docs/lessons-learned.md](docs/lessons-learned.md))
- [x] Social preview image `docs/img/social-preview.png` (1280x640, `scripts/make_social_preview.py`)
- [x] French summary (`docs/README.fr.md`), updated for phases 4-7
- [x] Documentation site (MkDocs Material on GitHub Pages) built from `docs/` (`docs.yml`)
- [x] Final review: docs and code consistent (counts, IDs, commands), dead code removed,
      confidentiality grep; found and fixed `make up` on Python 3.13+ and a receiver race
- [x] Fresh-clone check of the quick start (WSL Kali, Python 3.13): it found that `make up`
      could not read the CA certificate on a native Linux host (fixed in `certs.compose.yml`);
      after the fix, clone -> `make status` OK with custom alerts in 5 min 6 s (lab healthy at
      59 s; Wazuh images already pulled, ~7.5 GB more on a first run)
- [x] `v1.0.0` release notes

**Done when:** README quick start verified from a fresh clone; CI, e2e and docs green; release published.

## After 1.0

- [ ] Repository settings by the owner: upload the social preview, topics, pin as repo #1
- [ ] Talk / workshop material: "Build a SOC lab in an afternoon"
- [ ] CI unit tests on Python 3.13 too (the host scripts' TLS issue only showed there)
- [ ] Optional items above: Windows VM with Sysmon, Shuffle SOAR, `ioc-hunter`
