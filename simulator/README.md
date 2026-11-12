# insurco-sim

Synthetic security telemetry for **InsurCo**, the fictional insurer of this lab.
No dependencies beyond the Python 3.10+ standard library.

```bash
pip install -e ".[dev]"
insurco-sim list                          # attack scenarios and the rules they target
insurco-sim emit brute_force --seed 1     # print one scenario
insurco-sim run --out ./out --duration 60 # write logs: out/<host>/<file>
insurco-sim run --out ./out --profile flat # constant rate instead of office hours
insurco-sim stats --out ./out --minutes 5  # events per host per minute, ev/s
insurco-sim list --json                    # scenarios and expected rules, for scripts
pytest
```

## Office-hours profile

`run` draws candidate events at `--rate` (the **peak**, events/second) and keeps each
one with the probability given by the profile at the current local time:

| Local time | Working day (Sun-Thu) | Weekend (Fri, Sat) |
|---|---|---|
| 08:00-18:00 | 100% | 20% |
| 07:00-08:00 / 18:00-19:00 | linear ramp 10% <-> 100% | x0.2 |
| night | 10% | 2% |

Options: `--profile office|flat`, `--office-hours 08-18`, `--night-factor 0.1`,
`--weekend-factor 0.2`, `--weekend-days fri,sat` (compose: `SIM_PROFILE`,
`SIM_OFFICE_HOURS`, `SIM_NIGHT_FACTOR`, `SIM_WEEKEND_FACTOR`, `SIM_WEEKEND_DAYS`).
Attack scenarios keep their own schedule (`--attack-min/--attack-max`). The runner takes
an injectable clock, so the tests simulate whole hours in milliseconds.

`stats` counts lines by the timestamp written in them (all hosts, attacks included).
`marker <tag>` writes one SSH login for user `<tag>` on srv-linux-01; it is the probe used
by `scripts/measure_latency.py`.

| Host | File | Format | Read by |
|---|---|---|---|
| `srv-linux-01` | `auth.log` | syslog (sshd, sudo) | agent `srv-linux-01` |
| `srv-web-01` | `access.log` | Apache combined | agent `srv-web-01` |
| `srv-db-01` | `db_audit.json` | JSON lines | agent `srv-db-01` |
| `ws-claims-01` | `winsec.json` | JSON lines (Windows event IDs) | agent `ws-claims-01` |

Each agent reads **only its own folder**, so an event is ingested once.
