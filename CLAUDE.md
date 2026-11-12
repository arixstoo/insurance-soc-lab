# CLAUDE.md - working on insurance-soc-lab

A one-command SOC lab for a fictional insurer (**InsurCo**): Wazuh 4.14.9
single node, 4 agents, a telemetry simulator, custom detection rules with tests.
Public portfolio project of a SOC / Blue Team engineer: code quality,
honesty and documentation matter as much as features.

## Non-negotiable rules

1. **Confidentiality.** The lab was first built during an internship at a real
   Algerian insurer. Never write the real company name, people's names, real
   IPs, hostnames, credentials, or figures that identify it (number of
   agencies, regional offices...). Allowed wording: "a major Algerian
   insurance company". Use only `10.20.0.0/16` and RFC 5737 ranges.
2. **Defensive scope.** Detections, telemetry, response, documentation. No
   offensive tooling, exploits or attack scripts aimed at anything outside the
   lab's own containers.
3. **No rule without tests.** Every rule needs a positive (`expect`) and a negative
   (`expect_not`) case in `detection/tests/cases.yaml`, verified with the real engine
   (`test_rule_coverage.py` enforces it), and a row in the catalog's false-positive table.
4. **Configuration as code.** Never "fix" a running container with
   `docker exec ... sed`. Change a file in the repo, rebuild, verify.
5. **Never commit** `.env`, `stack/certs/`, keys, or anything under `out/`.

## Commands

| Task | Command |
|---|---|
| Lint | `ruff check simulator detection/tests scripts` |
| Unit tests | `cd simulator && python -m pytest -q` + `python -m pytest -q detection/tests` (rule coverage, catalog) |
| Detection tests | `python detection/tests/run_tests.py` (`-k <regex>` to filter) |
| Detection catalog | `python scripts/gen_catalog.py` (CI: `--check`) - never edit the generated tables by hand |
| Noise budget (24 h replay) | `python scripts/noise_report.py` -> `docs/tuning-report.md` (budget < 20 custom alerts) |
| Certificates (once) | `docker compose -f stack/certs.compose.yml run --rm generator` |
| Passwords (once, fresh lab) | `make rotate` / `scripts/rotate-passwords.sh` (running lab: `--apply`) |
| Start lab | `make up` (PowerShell: `scripts/lab.ps1 up`) = `docker compose up -d --build --wait` + `scripts/apply_ism.py` |
| Lab health | `python scripts/lab_status.py` |
| Trigger a scenario | `docker compose exec simulator insurco-sim inject <name>` |
| E2E check (running lab) | `bash scripts/e2e.sh` (CI: `e2e.yml`, manager clock pinned to midday) |
| Measure | `docker compose exec simulator insurco-sim stats` · `python scripts/measure_latency.py` |
| Stop / wipe | `docker compose down` / `docker compose down -v` |

## Wazuh facts learned the hard way

- `frequency`, `timeframe`, `ignore` are **attributes** of `<rule>`, not child elements.
- Check parent IDs in the upstream ruleset (`wazuh/wazuh` tag `v4.14.9`,
  `ruleset/rules/`). sshd: `5760` failed password, `5715` accepted.
  sudo: `5402`, and `5403` the first time a user runs sudo.
  Web: SQLi `31103,31164,31170,31171`, XSS `31105`, common attack `31104`, 400 `31101`.
- `<time>` uses the **manager clock at analysis time**, not the log timestamp.
  The test runner sets the container TZ to make it 02:00 or 12:00.
- Agent version must be `<=` manager version; both come from `WAZUH_VERSION`.
- `wazuh-logtest` (not the old `ossec-logtest`); each run is one session.
- One event = one alert: the event that completes a correlation raises the correlation rule
  *instead of* its own. Scenarios must send each kind more than once.
- At night 100133 (child of 100131) replaces 100131, and an `if_sid` child is evaluated
  before an `if_matched_group` rule: the night correlation needs its own child (100134).
- JSON logs use our decoders `insurco-db-audit` / `insurco-winsec`
  (`detection/decoders/0005-insurco_decoders.xml`). Decoder files are ordered by FILE NAME
  across folders and the first matching parent wins: the `0005-` prefix beats the generic
  `json` decoder (`0006-json_decoders.xml`). Children of a JSON parent replace its output,
  so the JSON plugin runs in a sibling child.
- `<same_field>` compares a field with itself: normalise in the decoder (`account`).
- CDB lists are compiled next to their text file (`.cdb`): mount `detection/lists` under
  `/wazuh-config-mount/etc/lists/insurco` (copied at start), never read-only in place.
- Rules below `log_alert_level` (3) still match and still feed `if_matched_sid` (100141).
- Correlation windows use a cached `time(NULL)` refreshed every second
  (`w_get_current_time`); `<time>` uses the wall clock. Time-dependent tests (`at:`) and the
  noise replay use `detection/replay/` (clockshim) to move both.

## Environment gotchas (Windows host)

- Git Bash rewrites `/var/...` arguments: set `MSYS_NO_PATHCONV=1` for `docker exec`.
- Windows reserves TCP ports around 55000 (Hyper-V): the Wazuh API is not published.
- Keep LF line endings (`.gitattributes`); shell scripts run in Linux containers.

## Definition of done (every change)

- Lint, unit tests and detection tests pass locally; CI green after push.
- Docs updated in the same change: `docs/detection-catalog.md` (run `gen_catalog.py`, fill
  the false-positive row), `ROADMAP.md` checkboxes, `CHANGELOG.md` (Unreleased).
- Rule changes: `scripts/noise_report.py` still under budget; record tuning in the catalog.
- For lab changes: `docker compose up -d --build` from a clean state
  (`down -v`) reaches 4 active agents and `lab_status.py` prints `OK`.
- Conventional Commits, small focused commits (`feat(detection): ...`).

## Where things are

`ROADMAP.md` (phases and acceptance criteria) · `docs/architecture.md` ·
`docs/detection-catalog.md` (tables generated) · `docs/tuning-report.md` · `docs/runbooks/` ·
`docs/production-integration.md`.
