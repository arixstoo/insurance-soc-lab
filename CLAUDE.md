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
| Lint | `ruff check simulator detection/tests scripts real response` |
| Unit tests | `cd simulator && python -m pytest -q` + `python -m pytest -q detection/tests` (rule coverage, catalog, runbook links) + `python -m pytest -q response/tests` (integration, receiver, response config) |
| Detection tests | `python detection/tests/run_tests.py` (`-k <regex>` to filter) |
| Python deps (tests) | `pip install -e "simulator[dev]" -r detection/requirements.txt` (pyyaml, pysigma) |
| Sigma rules | `python -m pytest -q detection/tests/test_sigma.py` (pySigma validators + agreement with the Wazuh rules on `cases.yaml`) |
| Threat intel | `python scripts/update_ti.py` (feed, cached; `--offline`; `--sample` = what is committed, CI `--sample --check`) · `make ti` = rebuild + restart manager |
| Detection catalog | `python scripts/gen_catalog.py` (CI: `--check`) - never edit the generated tables by hand |
| MITRE layer | `python scripts/gen_mitre_layer.py` (CI: `--check`) -> `docs/mitre-layer.json` |
| Dashboards | `python scripts/import_dashboards.py` (run by `make up`) · edit panels in `scripts/build_dashboards.py`, then run it (lab up) to rebuild + re-export `dashboards/*.ndjson` · `python scripts/screenshot_dashboards.py` |
| Noise budget (24 h replay) | `python scripts/noise_report.py` -> `docs/tuning-report.md` (budget < 20 custom alerts) |
| Certificates (once) | `docker compose -f stack/certs.compose.yml run --rm generator` |
| Passwords (once, fresh lab) | `make rotate` / `scripts/rotate-passwords.sh` (running lab: `--apply`) |
| Start lab | `make up` (PowerShell: `scripts/lab.ps1 up`) = `docker compose up -d --build --wait` + `scripts/apply_ism.py` + `scripts/import_dashboards.py` |
| Lab health | `python scripts/lab_status.py` |
| Trigger a scenario | `docker compose exec simulator insurco-sim inject <name>` |
| E2E check (running lab) | `bash scripts/e2e.sh` (CI: `e2e.yml`, manager clock pinned to midday) |
| Response check (running lab) | `python scripts/check_response.py [--target both] [--no-expiry]` (`make response`): 100101 -> webhook -> 10 min block -> expiry · alerts on <http://localhost:8088> |
| Measure | `docker compose exec simulator insurco-sim stats` · `python scripts/measure_latency.py` |
| Real services (profile `real`) | `make up REAL=1` · `make traffic` (= `docker compose --profile real exec real-client lab-traffic all`) · `docs/real-services.md` |
| Stop / wipe | `make down` / `make reset` (include the `real` profile) |

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
- `ignore` mutes the WHOLE rule after it fires, not per srcip / user: a second source inside
  the window raises nothing. e2e sends the real traffic first, then waits > the largest ignore.
- A rule with only `<if_matched_group>` (100132) is attached to the group's rules defined
  BEFORE it in the file. Two parents (`<if_sid>a,b</if_sid>` or `<if_group>`) on a rule that
  feeds a group correlation broke it (100131): real-trail twins 100137 / 100138 instead,
  kept identical by `test_rule_coverage.py`.
- Correlation memory is shared by all logtest sessions of one engine: give every correlated
  test case its own srcip / user.
- analysisd runs chrooted without zoneinfo: a named `TZ` (Africa/Algiers) falls back to UTC;
  POSIX strings (`LAB-14`) work.
- Correlation windows use a cached `time(NULL)` refreshed every second
  (`w_get_current_time`); `<time>` uses the wall clock. Time-dependent tests (`at:`) and the
  noise replay use `detection/replay/` (clockshim) to move both.
- Every alerting rule (level >= 3) needs `<info type="link">` to its runbook
  (`docs/runbooks/`, GitHub URL): `gen_catalog.py --check` fails otherwise. Wazuh copies it
  into the alert as `rule.info`, so the webhook message carries it.
- Integrations: `wazuh-integratord` runs `integrations/custom-<name>` with
  `<alert file> <api_key> <hook_url>`; the script is copied in through
  `/wazuh-config-mount/integrations/` (keep the git exec bit, LF). Bundled Python is 3.10.
- Active response `firewall-drop` needs `iptables` in the agent image and `NET_ADMIN` on the
  container; `location local` = the agent that raised the alert. Its `check_keys` exchange
  aborts a duplicate block. A block on real-linux-01 cuts `real-client` off sshd for 10 min.
- Random simulator attacks can open 100100's `ignore` window at any time: any live check of
  a brute force needs `SIM_ATTACK_MIN/MAX=86400` (as `e2e.yml`).
- **Sibling rules are tried by LEVEL, highest first** (ties: load order), not in file order:
  a child at level 12 of 5715 beat 100102 (level 8). A new child must sit below the levels
  of the siblings it must not shadow (100151 at 6 under 31108), or exclude their cases (100150
  day window).
- A child rule REPLACES its parent's alert: a TI child of a correlation input (5760, 100100,
  100120-100123) starves the correlation and the active response. TI rules only go on events
  nothing correlates on. Wazuh's IoC rules (`0999-malicious-ioc-rules.xml`) are children of
  inputs: keep their list `etc/lists/malicious-ioc/malicious-ip` absent.
- `address_match_key` matches prefix keys `a.b.c.` / `a.b.` / `a.` (verified): CIDRs become prefix
  keys or are expanded (`update_ti.py`). The committed `ti-bad-ips` is the sample build (RFC 5737).
- Sigma: one rule per file, `name` = file stem, `wazuh_rules` lists the Wazuh ids it stands for;
  every Sigma rule needs a positive and a negative case in `cases.yaml` (`test_sigma.py`).
  pySigma 2.x downloads ATT&CK / D3FEND for two validators (cached in `~/.cache/pysigma`).
- Dashboards: a saved `heatmap` vis needs its full `params` (`valueAxes`...): the editor merges
  no defaults. The `range` agg with custom `label`s returns HTTP 400 (use `filters`). Panels may
  only filter on `rule.id` / `rule.groups` proven by tests (`test_dashboards.py`).

## Environment gotchas (Windows host)

- Git Bash rewrites `/var/...` arguments: set `MSYS_NO_PATHCONV=1` for `docker exec`.
- Windows reserves TCP ports around 55000 (Hyper-V): the Wazuh API is not published.
- Keep LF line endings (`.gitattributes`); shell scripts run in Linux containers.
- auditd cannot run in Docker Desktop containers (WSL2 kernel refuses audit netlink).
- A rebuilt agent container is refused under its old name until the manager sees the old one
  disconnected (10 min): `docker compose restart wazuh.manager` instead of waiting.

## Definition of done (every change)

- Lint, unit tests and detection tests pass locally; CI green after push.
- Docs updated in the same change: `docs/detection-catalog.md` (run `gen_catalog.py`, fill
  the false-positive row), `ROADMAP.md` checkboxes, `CHANGELOG.md` (Unreleased).
- Rule changes: `scripts/noise_report.py` still under budget; record tuning in the catalog.
- For lab changes: `docker compose up -d --build` from a clean state
  (`down -v`) reaches 4 active agents (7 with `--profile real`) and `lab_status.py` prints `OK`.
- Conventional Commits, small focused commits (`feat(detection): ...`).

## Where things are

`ROADMAP.md` (phases and acceptance criteria) · `docs/architecture.md` ·
`docs/detection-catalog.md` (tables generated) · `docs/tuning-report.md` · `docs/runbooks/` ·
`docs/production-integration.md` · `docs/dashboards.md` · `docs/mitre-layer.json` ·
`docs/response.md` (alert routing + active response) · `response/` (integration, receiver, tests) ·
`detection/sigma/rules/` (Sigma) · `detection/ti/` (sample feed) · `detection/lists/ti-bad-ips` (generated).
