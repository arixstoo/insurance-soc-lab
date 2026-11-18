## What and why

<!-- One or two sentences. Link the issue: Closes #123 -->

## Type

- [ ] Detection (rule, decoder, CDB list, Sigma)
- [ ] Response (integration, active response, runbook)
- [ ] Lab / simulator / dashboards
- [ ] Documentation
- [ ] CI / tooling / dependencies

## Checklist

- [ ] `ruff check simulator detection/tests scripts real response` passes
- [ ] `make unit` passes (simulator, detection static checks, response, generated files)
- [ ] New or changed rules have positive **and** negative cases in `detection/tests/cases.yaml`
      and a row in the catalog's false-positive table
- [ ] `python detection/tests/run_tests.py` passes (or CI is green)
- [ ] Generated files rebuilt, not edited by hand (`gen_catalog.py`, `gen_mitre_layer.py`, `dashboards/*.ndjson`)
- [ ] Docs updated (`CHANGELOG.md`, and the catalog / runbook / README if counts or behaviour changed)
- [ ] No real data: IPs, hostnames, usernames and company names are synthetic
