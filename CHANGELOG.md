# Changelog

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
