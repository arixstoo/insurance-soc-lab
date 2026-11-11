# Contributing

Thanks for your interest! Issues and pull requests are welcome - especially new
detections for the insurance / financial sector.

## Ground rules

- **Synthetic data only.** No real logs, company names, employee names or IPs.
  Use the lab ranges (`10.20.0.0/16`) and RFC 5737 ranges (`203.0.113.0/24`,
  `198.51.100.0/24`) for "external" addresses.
- **Defensive scope.** Rules, telemetry and documentation for detection and
  response. No offensive tooling.
- **Every rule ships with tests** - at least one case that must fire and one
  normal-activity case that must not.

## Development setup

```bash
pip install -e "simulator[dev]"
pre-commit install            # optional, runs ruff and basic checks on commit
```

| Task | Command |
|---|---|
| Lint | `ruff check simulator detection/tests scripts` |
| Unit tests | `pytest simulator` |
| Detection tests (needs Docker) | `python detection/tests/run_tests.py` |
| Run the lab | `docker compose up -d --build` then `python scripts/lab_status.py` |

## Adding a detection

1. Pick the next free ID in `100100-100199` (keep families together: auth
   `10010x`, privesc `10011x`, web `10012x`, database `10013x`, Windows `10014x`).
2. Add the rule to `detection/rules/insurco_rules.xml`. Check the parent rule in
   the [Wazuh ruleset](https://github.com/wazuh/wazuh/tree/v4.14.9/ruleset/rules)
   - do not guess its ID.
3. Add positive and negative cases to `detection/tests/cases.yaml`. Use
   `clock: night` / `clock: day` for rules with `<time>`.
4. If a simulator scenario should trigger it, add the ID to its
   `expected_rules` (a unit test checks the IDs exist and are tested).
5. Document it in `docs/detection-catalog.md` (MITRE mapping, false positives).

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(detection): add rogue admin correlation`, `fix(agents): ...`, `docs: ...`.
- Small, focused PRs. CI must be green.
- Update `CHANGELOG.md` under "Unreleased".
