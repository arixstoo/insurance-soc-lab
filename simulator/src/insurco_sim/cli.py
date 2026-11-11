"""Command line entry point.

    insurco-sim list
    insurco-sim emit brute_force            # print a scenario to stdout
    insurco-sim inject insider              # write a scenario into the host logs now
    insurco-sim run --out /var/log/insurco  # continuous background + attacks
    insurco-sim run --out ./out --duration 60 --seed 7
"""

from __future__ import annotations

import argparse
import logging
import random
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from . import catalog as c
from .scenarios import SCENARIOS, background_event

log = logging.getLogger("insurco_sim")


class LogWriter:
    """Appends lines to <out>/<host>/<file>, one folder per simulated host."""

    def __init__(self, out_dir: Path) -> None:
        self.paths = {}
        for role, host in c.HOSTS.items():
            folder = out_dir / host.name
            folder.mkdir(parents=True, exist_ok=True)
            self.paths[role] = folder / host.log_file

    def write(self, role: str, line: str) -> None:
        with self.paths[role].open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def run(out_dir: Path, *, seed: int | None, duration: float, rate: float,
        attack_every: tuple[int, int], only: list[str] | None) -> int:
    rng = random.Random(seed)
    writer = LogWriter(out_dir)
    stop = {"now": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(now=True))

    names = only or list(SCENARIOS)
    started = time.monotonic()
    next_attack = started + rng.uniform(*attack_every)
    count = 0
    log.info("writing to %s (scenarios: %s)", out_dir, ", ".join(names))
    try:
        while not stop["now"] and (duration <= 0 or time.monotonic() - started < duration):
            writer.write(*background_event(rng, datetime.now()))
            count += 1
            if time.monotonic() >= next_attack:
                scenario = SCENARIOS[rng.choice(names)]
                log.info("scenario %s -> expects rules %s", scenario.name, ",".join(scenario.expected_rules))
                for role, line in scenario.build(rng, datetime.now()):
                    writer.write(role, line)
                    time.sleep(0.2)  # attacks are bursts, not one block
                next_attack = time.monotonic() + rng.uniform(*attack_every)
            time.sleep(rng.expovariate(rate))  # steady, irregular flow (no "waves")
    except KeyboardInterrupt:
        pass
    log.info("stopped after %d background events", count)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="insurco-sim", description="InsurCo log simulator")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list attack scenarios")

    emit = sub.add_parser("emit", help="print one scenario to stdout")
    emit.add_argument("scenario", choices=sorted(SCENARIOS))
    emit.add_argument("--seed", type=int)

    inject = sub.add_parser("inject", help="write one scenario now into the host log folders")
    inject.add_argument("scenario", choices=sorted(SCENARIOS))
    inject.add_argument("--out", type=Path, default=Path("/var/log/insurco"))
    inject.add_argument("--seed", type=int)

    run_p = sub.add_parser("run", help="write continuous logs to disk")
    run_p.add_argument("--out", type=Path, required=True, help="root folder (one sub-folder per host)")
    run_p.add_argument("--seed", type=int)
    run_p.add_argument("--duration", type=float, default=0, help="seconds, 0 = forever")
    run_p.add_argument("--rate", type=float, default=0.7, help="average background events per second")
    run_p.add_argument("--attack-min", type=int, default=120, help="min seconds between attacks")
    run_p.add_argument("--attack-max", type=int, default=300, help="max seconds between attacks")
    run_p.add_argument("--only", nargs="+", choices=sorted(SCENARIOS), help="restrict attack scenarios")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.command == "list":
        for s in SCENARIOS.values():
            print(f"{s.name:15} rules {','.join(s.expected_rules):35} {s.summary}")
        return 0
    if args.command == "emit":
        rng = random.Random(args.seed)
        for role, line in SCENARIOS[args.scenario].build(rng, datetime.now()):
            print(f"{c.HOSTS[role].name}\t{line}")
        return 0
    if args.command == "inject":
        scenario = SCENARIOS[args.scenario]
        writer = LogWriter(args.out)
        for role, line in scenario.build(random.Random(args.seed), datetime.now()):
            writer.write(role, line)
            time.sleep(0.2)
        print(f"injected {scenario.name} -> expect rules {', '.join(scenario.expected_rules)}")
        return 0
    if args.attack_min > args.attack_max:
        parser.error("--attack-min must be <= --attack-max")
    return run(args.out, seed=args.seed, duration=args.duration, rate=args.rate,
               attack_every=(args.attack_min, args.attack_max), only=args.only)


if __name__ == "__main__":
    sys.exit(main())
