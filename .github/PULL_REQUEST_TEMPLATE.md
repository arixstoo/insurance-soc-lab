## What and why

<!-- One or two sentences. Link the issue: Closes #123 -->

## Checklist

- [ ] `ruff check simulator detection/tests scripts` passes
- [ ] `pytest simulator` passes
- [ ] New or changed rules have positive **and** negative cases in `detection/tests/cases.yaml`
- [ ] `python detection/tests/run_tests.py` passes (or CI is green)
- [ ] Docs updated (`docs/detection-catalog.md`, `CHANGELOG.md`)
- [ ] No real data: IPs, hostnames, usernames and company names are synthetic
