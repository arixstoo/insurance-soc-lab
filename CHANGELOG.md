# Changelog

## [0.4.0] - 2026-11-12 - Detection engineering v2

### Added
- **100145** (level 15): account created (100143) then added to an admin group (100144) for
  the same account within 10 minutes. The account is normalised by the decoder (`account`:
  4720 `TargetUserName`, 4732 `MemberName`) because `<same_field>` compares a field with itself.
- **100134** (level 14): mass customer data access at night (night variant of 100132).
- **100103** (level 10): SSH login to `root` / `admin` / `administrator` between 22:00 and 06:00.
- Custom decoders `insurco-db-audit` and `insurco-winsec`
  (`detection/decoders/0005-insurco_decoders.xml`) replace the generic JSON decoder; the DB
  client address is also decoded as `srcip`. The `0005-` prefix is what makes them win.
- CDB allow-lists `detection/lists/db-service-accounts` (`svc_reporting`) and
  `detection/lists/scanner-ips` (`10.20.5.10`), declared in the manager config and mounted
  through `/wazuh-config-mount` (the manager compiles lists next to the text file).
- Every rule has a positive and a negative case (25 -> 60 cases);
  `detection/tests/test_rule_coverage.py` fails when one is missing.
- Time-window cases (`at:` offsets) run on `detection/replay/`: the manager image plus
  `clockshim`, a small `LD_PRELOAD` library that moves analysisd's clock to each line's
  simulated time (proven exact to the second against the 120 s window of 100100).
- `scripts/gen_catalog.py`: rule, allow-list and ATT&CK tables of `docs/detection-catalog.md`
  generated from the XML; `--check` in CI, also fails when a rule has no false-positive row.
- `scripts/noise_report.py` + `docs/tuning-report.md`: 24 h of background traffic replayed
  through the real engine in ~3 minutes, alert count per rule, headroom of each frequency rule.
- Simulator: `insurco_sim.timeline.background_timeline` (traffic without sleeping); the
  background now includes legitimate activity that looks malicious (reporting extracts,
  internal scanner, onboarding, non-admin group changes). Unit tests 67 -> 72.
- `make catalog`, `make noise`; `make unit` / `lab.ps1 test` also run the static detection checks.

### Changed
- **Detection tests use the lab's own manager configuration**, decoders and lists (they used
  the image's default `ossec.conf`).
- 100132 counts the group `insurco_bulk_read` (100131 + 100133) instead of 100131.
- 100120-100123 skip `scanner-ips`; 100131 skips `db-service-accounts`.
- Tuning (24 h of background: 2101 -> 3 custom alerts): 100141 level 5 -> 2 (still feeds
  100142); 100102 only for logins from outside `10.20.0.0/16`.
- `rogue_admin` expects 100143 + 100145 (the promotion now raises 100145 *instead of*
  100144); `password_spray` expects 100142 only.

### Fixed
- Night-time insider gap: 5 bulk reads by one user at night now raise 100134 (100132 could
  never fire between 22:00 and 06:00).
- e2e lost the DB and Windows scenarios (6/13 rules missing on CI): their log files did not
  exist yet when the agents' logcollector started, and every agent restarts its daemons
  when it receives the shared configuration ~30 s after enrolment, while the scenarios were
  being injected. The simulator now creates every log file at start; `scripts/e2e.sh` waits
  for each agent's "Buffer agent.conf updated" (`E2E_RELOAD_TIMEOUT`, 90 s) before injecting.

## [0.3.0] - 2026-11-12 - Endpoints and telemetry v3, end-to-end test

### Added
- Office-hours activity profile in `insurco-sim run` (`simulator/src/insurco_sim/profile.py`):
  full activity 08:00-18:00 local time with a one-hour ramp on each side, 10% of the peak at
  night, the whole day x0.2 on Friday and Saturday (weekend in Algeria). `--rate` is now the
  peak rate. Configurable with `--profile office|flat`, `--office-hours`, `--night-factor`,
  `--weekend-factor`, `--weekend-days` (compose: `SIM_PROFILE`, `SIM_OFFICE_HOURS`, ...).
  Implemented by thinning, so sleeps stay short. Attack scenarios ignore the profile.
- `insurco-sim stats`: events per host per minute and events/second, parsed from the log files.
- `insurco-sim list --json` and `insurco-sim marker <tag>` (one tagged SSH login line).
- `scripts/measure_latency.py`: injects marker events and measures log line -> alert
  (manager) and -> searchable in `wazuh-alerts-*`. Measured on Docker Desktop:
  median 0.13 s to the alert, 9 s until searchable.
- `.github/workflows/e2e.yml` + `scripts/e2e.sh`: the full lab on `ubuntu-latest` (certificates,
  generated passwords, build), 4 active agents, all 6 scenarios injected, the 14 expected rules
  asserted in the indexer with `curl` against the lab CA; compose logs uploaded on failure.
  Night-only rules are excluded; the manager clock is pinned to midday.
- Detection test: brute force then success at night still fires 100101 (25 cases).
- Unit tests 17 -> 67 (many parametrized): profile curve and runner under a fake clock, stats, CLI helpers.

### Fixed
- `web_campaign` could miss a rule: the event completing the 100129 correlation raises 100129
  *instead of* its own rule, and the traversal line was sent only once. Every attack kind is now
  sent twice (found by the first e2e run: 100122 missing).

### Known issue
- At night 100133 replaces 100131, so 100132 cannot fire (ROADMAP phase 3).


## [0.2.0] - 2026-11-11 - Hardened one-command SIEM

### Added
- `scripts/rotate-passwords.sh` / `.ps1`: generated passwords for the indexer `admin` and
  `kibanaserver` users and the `wazuh-wui` API user, hashed with the indexer's own `hash.sh`,
  written to git-ignored `stack/secrets/` and `.env`; `--apply` / `-Apply` rotates a running
  lab with `securityadmin`. The upstream demo users are dropped.
- `make` targets `up / down / reset / status / test / lint / rotate / certs` and `scripts/lab.ps1`
  with the same verbs; `make up` waits until every container is healthy.
- Health checks on `wazuh.manager`, `wazuh.indexer` and `wazuh.dashboard`; the agents start
  only once the manager is healthy, the dashboard once indexer and manager are.
- ISM policy `insurco-alerts-retention` (delete `wazuh-alerts-*` after 30 days), applied by
  `scripts/apply_ism.py` after startup.
- `lab_status.py` checks that every public default password is rejected and that the
  retention policy exists.
- CI: Trivy scan of the agent and simulator images (fails on any CRITICAL), `shellcheck`,
  ISM policy JSON check, `ruff` on `scripts/`.

### Changed
- Agent image on Ubuntu 26.04 (was 22.04), simulator on Python 3.15 (was 3.12),
  verified end to end: clean lab start, 4 agents, first custom alert in 71 s.
- Every GitHub Action pinned to a full commit SHA (version in a comment); gitleaks and
  Trivy images pinned to digests.
- Compose mounts `INDEXER_USERS_FILE` / `DASHBOARD_API_CONFIG` (defaults: the committed
  upstream files).

## [0.1.0] - 2026-11-11 - Foundations

Public, anonymized release of the lab: the insurer's name, its employees and its
real IP addresses, hostnames and credentials were removed.

### Added
- One-command lab: Wazuh 4.14.9 single node, 4 agents, telemetry simulator.
- 16 custom rules (`100100-100144`) with 24 test cases run against `wazuh-logtest`.
- `insurco-sim` v3: seedable background activity and 6 attack scenarios, on-demand `inject`, 17 unit tests.
- CI: lint, unit tests, XML and compose validation, detection tests.
- Docs: architecture, detection catalog, runbook, production plan, roadmap, French summary.
- Repository tooling: contributing guide, code of conduct, issue/PR templates, Dependabot,
  pre-commit, gitleaks secret scanning, CodeQL, `CLAUDE.md` for AI-assisted development.
