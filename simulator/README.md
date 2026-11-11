# insurco-sim

Synthetic security telemetry for **InsurCo**, the fictional insurer of this lab.
No dependencies beyond the Python 3.10+ standard library.

```bash
pip install -e ".[dev]"
insurco-sim list                          # attack scenarios and the rules they target
insurco-sim emit brute_force --seed 1     # print one scenario
insurco-sim run --out ./out --duration 60 # write logs: out/<host>/<file>
pytest
```

| Host | File | Format | Read by |
|---|---|---|---|
| `srv-linux-01` | `auth.log` | syslog (sshd, sudo) | agent `srv-linux-01` |
| `srv-web-01` | `access.log` | Apache combined | agent `srv-web-01` |
| `srv-db-01` | `db_audit.json` | JSON lines | agent `srv-db-01` |
| `ws-claims-01` | `winsec.json` | JSON lines (Windows event IDs) | agent `ws-claims-01` |

Each agent reads **only its own folder**, so an event is ingested once.
