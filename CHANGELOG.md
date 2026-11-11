# Changelog

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
