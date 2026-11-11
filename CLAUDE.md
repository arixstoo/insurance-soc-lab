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
3. **No rule without tests.** Every rule needs a positive and a negative case in
   `detection/tests/cases.yaml`, verified with the real engine.
4. **Configuration as code.** Never "fix" a running container with
   `docker exec ... sed`. Change a file in the repo, rebuild, verify.
5. **Never commit** `.env`, `stack/certs/`, keys, or anything under `out/`.

## Commands

| Task | Command |
|---|---|
| Lint | `ruff check simulator detection/tests scripts` |
| Unit tests | `cd simulator && python -m pytest -q` |
| Detection tests | `python detection/tests/run_tests.py` (`-k <regex>` to filter) |
| Certificates (once) | `docker compose -f stack/certs.compose.yml run --rm generator` |
| Start lab | `docker compose up -d --build` |
| Lab health | `python scripts/lab_status.py` |
| Trigger a scenario | `docker compose exec simulator insurco-sim inject <name>` |
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
- JSON logs are decoded by the generic JSON decoder; our rules key on the
  `log_type` field (`db_audit`, `winsec`).

## Environment gotchas (Windows host)

- Git Bash rewrites `/var/...` arguments: set `MSYS_NO_PATHCONV=1` for `docker exec`.
- Windows reserves TCP ports around 55000 (Hyper-V): the Wazuh API is not published.
- Keep LF line endings (`.gitattributes`); shell scripts run in Linux containers.

## Definition of done (every change)

- Lint, unit tests and detection tests pass locally; CI green after push.
- Docs updated in the same change: `docs/detection-catalog.md`, `ROADMAP.md`
  checkboxes, `CHANGELOG.md` (Unreleased).
- For lab changes: `docker compose up -d --build` from a clean state
  (`down -v`) reaches 4 active agents and `lab_status.py` prints `OK`.
- Conventional Commits, small focused commits (`feat(detection): ...`).

## Where things are

`ROADMAP.md` (phases and acceptance criteria) · `docs/architecture.md` ·
`docs/detection-catalog.md` · `docs/runbooks/` ·
`docs/production-integration.md`.
