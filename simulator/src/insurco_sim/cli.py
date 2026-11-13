"""Command line entry point.

    insurco-sim list [--json]
    insurco-sim emit brute_force            # print a scenario to stdout
    insurco-sim inject insider              # write a scenario into the host logs now
    insurco-sim run --out /var/log/insurco  # continuous background (office hours) + attacks
    insurco-sim run --out ./out --duration 60 --seed 7 --profile flat
    insurco-sim stats --minutes 10          # events per host per minute, from the log files
    insurco-sim marker latency-1a2b         # one tagged SSH login, for latency measurement
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
import signal
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import catalog as c
from . import events as e
from . import stats
from .profile import Flat, Profile, parse_days, parse_hours
from .scenarios import SCENARIOS, background_event

log = logging.getLogger("insurco_sim")
DEFAULT_OUT = Path("/var/log/insurco")


class LogWriter:
    """Appends lines to <out>/<host>/<file>, one folder per simulated host.

    Every log file is created up front: an agent whose file is missing when its logcollector
    starts only finds it on a later rescan and skips what was written before (seen in e2e:
    the first DB / Windows events after the agents' start-up reload were never read).
    """

    def __init__(self, out_dir: Path) -> None:
        self.paths = {}
        for role, host in c.HOSTS.items():
            folder = out_dir / host.name
            folder.mkdir(parents=True, exist_ok=True)
            self.paths[role] = folder / host.log_file
            self.paths[role].touch(exist_ok=True)

    def write(self, role: str, line: str) -> None:
        with self.paths[role].open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


@dataclass
class Clock:
    """Wall clock, monotonic clock and sleep, injectable so tests can fake time."""

    now: Callable[[], datetime] = datetime.now
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


@dataclass
class RunStats:
    candidates: int = 0
    background: int = 0
    attacks: list[str] = field(default_factory=list)


def run(out_dir: Path, *, seed: int | None, duration: float, rate: float,
        attack_every: tuple[int, int], only: list[str] | None,
        profile: Profile | Flat | None = None, clock: Clock | None = None) -> RunStats:
    """Write background events (peak `rate`/s scaled by `profile`) and attacks until `duration` elapses."""
    rng = random.Random(seed)
    profile = profile or Profile()
    clock = clock or Clock()
    writer = LogWriter(out_dir)
    stop = {"now": False}
    try:
        signal.signal(signal.SIGTERM, lambda *_: stop.update(now=True))
    except ValueError:  # not the main thread (embedded use): rely on duration / KeyboardInterrupt
        pass

    names = only or list(SCENARIOS)
    started = clock.monotonic()
    next_attack = started + rng.uniform(*attack_every)
    result = RunStats()
    log.info("writing to %s (peak %.2f ev/s, profile %s, scenarios: %s)",
             out_dir, rate, profile, ", ".join(names))
    try:
        while not stop["now"] and (duration <= 0 or clock.monotonic() - started < duration):
            now = clock.now()
            result.candidates += 1
            # Thinning: keep the candidate with probability factor(now). The draw is made
            # even when factor == 1 so a seed gives the same sequence with every profile.
            if rng.random() < profile.factor(now):
                writer.write(*background_event(rng, now))
                result.background += 1
            if clock.monotonic() >= next_attack:
                scenario = SCENARIOS[rng.choice(names)]
                log.info("scenario %s -> expects rules %s", scenario.name, ",".join(scenario.expected_rules))
                for role, line in scenario.build(rng, clock.now()):
                    writer.write(role, line)
                    clock.sleep(0.2)  # attacks are bursts, not one block
                result.attacks.append(scenario.name)
                next_attack = clock.monotonic() + rng.uniform(*attack_every)
            clock.sleep(rng.expovariate(rate))  # steady, irregular flow (no "waves")
    except KeyboardInterrupt:
        pass
    log.info("stopped after %d background events (%d candidates), %d attacks",
             result.background, result.candidates, len(result.attacks))
    return result


def build_profile(args: argparse.Namespace) -> Profile | Flat:
    if args.profile == "flat":
        return Flat()
    start, end = parse_hours(args.office_hours)
    return Profile(start=start, end=end, night=args.night_factor,
                   weekend=args.weekend_factor, weekend_days=parse_days(args.weekend_days))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="insurco-sim", description="InsurCo log simulator")
    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="list attack scenarios")
    list_p.add_argument("--json", action="store_true", help="machine-readable output")

    emit = sub.add_parser("emit", help="print one scenario to stdout")
    emit.add_argument("scenario", choices=sorted(SCENARIOS))
    emit.add_argument("--seed", type=int)

    inject = sub.add_parser("inject", help="write one scenario now into the host log folders")
    inject.add_argument("scenario", choices=sorted(SCENARIOS))
    inject.add_argument("--out", type=Path, default=DEFAULT_OUT)
    inject.add_argument("--seed", type=int)

    run_p = sub.add_parser("run", help="write continuous logs to disk")
    run_p.add_argument("--out", type=Path, required=True, help="root folder (one sub-folder per host)")
    run_p.add_argument("--seed", type=int)
    run_p.add_argument("--duration", type=float, default=0, help="seconds, 0 = forever")
    run_p.add_argument("--rate", type=float, default=0.7,
                       help="background events per second at peak (office hours); constant with --profile flat")
    run_p.add_argument("--attack-min", type=int, default=120, help="min seconds between attacks")
    run_p.add_argument("--attack-max", type=int, default=300, help="max seconds between attacks")
    run_p.add_argument("--only", nargs="+", choices=sorted(SCENARIOS), help="restrict attack scenarios")
    run_p.add_argument("--profile", choices=["office", "flat"], default="office",
                       help="office: daily curve (default); flat: constant rate")
    run_p.add_argument("--office-hours", default="08-18", help="full-activity local hours (default 08-18)")
    run_p.add_argument("--night-factor", type=float, default=0.1, help="share of the peak rate at night (0.1)")
    run_p.add_argument("--weekend-factor", type=float, default=0.2,
                       help="multiplier for the whole day on weekend days (0.2)")
    run_p.add_argument("--weekend-days", default="fri,sat", help="weekend days (Algeria: fri,sat)")

    stats_p = sub.add_parser("stats", help="events per host per minute, read from the log files")
    stats_p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    stats_p.add_argument("--minutes", type=int, default=10, help="full minutes to show (default 10)")

    marker = sub.add_parser("marker", help="write one tagged SSH login on srv-linux-01 (latency probe)")
    marker.add_argument("tag", help="user name to put in the line, e.g. latency-1a2b3c")
    marker.add_argument("--out", type=Path, default=DEFAULT_OUT)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.command == "list":
        if args.json:
            print(json.dumps([{"name": s.name, "expected_rules": list(s.expected_rules), "summary": s.summary}
                              for s in SCENARIOS.values()]))
        else:
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
    if args.command == "stats":
        if args.minutes < 1:
            parser.error("--minutes must be >= 1")
        now = datetime.now()
        print(stats.render(stats.count_per_minute(args.out, now, args.minutes), now, args.minutes))
        return 0
    if args.command == "marker":
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", args.tag):
            parser.error("tag: 1-64 characters among A-Z a-z 0-9 . _ -")
        LogWriter(args.out).write("linux", e.ssh_success(random.Random(), datetime.now(), user=args.tag))
        print(f"{time.time():.3f}")  # epoch seconds of the write, read by scripts/measure_latency.py
        return 0
    if args.attack_min > args.attack_max:
        parser.error("--attack-min must be <= --attack-max")
    if args.rate <= 0:
        parser.error("--rate must be > 0")
    try:
        profile = build_profile(args)
    except ValueError as exc:
        parser.error(str(exc))
    run(args.out, seed=args.seed, duration=args.duration, rate=args.rate,
        attack_every=(args.attack_min, args.attack_max), only=args.only, profile=profile)
    return 0


if __name__ == "__main__":
    sys.exit(main())
