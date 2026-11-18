# Getting help

This is a personal portfolio lab maintained on a best-effort basis.

| You want to... | Go to |
|---|---|
| Run the lab for the first time | [Quick start](README.md#quick-start-about-10-minutes) and the [documentation site](https://arixstoo.github.io/insurance-soc-lab/) |
| Understand a rule, its false positives or its runbook | [Detection catalog](docs/detection-catalog.md) · [runbooks](docs/runbooks/README.md) |
| Report something that does not work as documented | [Bug report](https://github.com/arixstoo/insurance-soc-lab/issues/new?template=bug_report.yml) (include `python scripts/lab_status.py`) |
| Suggest a detection | [Detection request](https://github.com/arixstoo/insurance-soc-lab/issues/new?template=detection_request.yml) |
| Suggest an improvement to the lab or the docs | [Improvement idea](https://github.com/arixstoo/insurance-soc-lab/issues/new?template=feature_request.yml) |
| Report a security issue | **Privately**, through a [security advisory](https://github.com/arixstoo/insurance-soc-lab/security/advisories/new) - see [SECURITY.md](SECURITY.md) |
| Contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |

Before opening an issue, run `make status` (or `python scripts/lab_status.py`): it checks the
agents, the default passwords, the response chain and the custom rules, and its output answers
most "no alerts" questions.

Please never paste real logs, IP addresses, hostnames, usernames or credentials: the lab only
uses synthetic data, and so should its issues.
