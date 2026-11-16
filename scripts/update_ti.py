#!/usr/bin/env python3
"""Build the threat-intel CDB list of known-bad IPs (detection/lists/ti-bad-ips).

    python scripts/update_ti.py                  # public feed (cached), else last cache, else the sample
    python scripts/update_ti.py --offline        # no network: last cached feed, else the sample
    python scripts/update_ti.py --sample         # the sample feed of the repo (what is committed)
    python scripts/update_ti.py --sample --check # CI: the committed list is the sample build
    python scripts/update_ti.py --url URL        # another feed (or TI_FEED_URL); file:// works too

The manager compiles CDB lists at start: `make ti` (or `scripts/lab.ps1 ti`) runs this
script, then restarts wazuh.manager.

Feed format: one IPv4 address or CIDR per line; `#` and `;` start a comment; anything
after the first token is ignored (works for abuse.ch Feodo Tracker, Spamhaus DROP,
FireHOL netsets, plain lists). IPv6 is skipped: a CDB key cannot hold a ':'.

Wazuh's `address_match_key` looks up the full address, then its /24, /16 and /8 prefixes
written as "a.b.c.", "a.b.", "a.". A CIDR is therefore written as prefix keys on those
boundaries, or expanded (/25-/32 into addresses, /17-/23 into /24 keys, /9-/15 into /16 keys).

Safety: private, loopback, link-local, CGNAT, multicast and reserved ranges (so the lab's
own 10.20.0.0/16 and the scanner) are never listed, whatever the feed says, and nothing
wider than a /8 is accepted. The RFC 5737 documentation ranges are allowed: the sample uses them.

The committed list must stay the sample build (documentation addresses only, see
CLAUDE.md): a list built from a live feed is a local refresh, `--check` fails on it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "detection" / "lists" / "ti-bad-ips"
SAMPLE = ROOT / "detection" / "ti" / "sample-feed.txt"
CACHE_DIR = ROOT / "out" / "ti"
# abuse.ch Feodo Tracker, "recommended" blocklist: botnet C2 servers, low false positives, CC0.
DEFAULT_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
USER_AGENT = "insurance-soc-lab-update-ti/1.0"
MAX_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 100_000

NEVER = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
)]
TOKEN = re.compile(r"[\s,;]+")


@dataclass
class Parsed:
    networks: list[ipaddress.IPv4Network] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def parse_feed(text: str) -> Parsed:
    """Networks of a plain-text feed, with the count of each kind of skipped line."""
    parsed = Parsed()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        token = TOKEN.split(line, maxsplit=1)[0]
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            parsed.skip("not an address")
            continue
        if net.version != 4:
            parsed.skip("IPv6")
        elif net.prefixlen < 8:
            parsed.skip("wider than /8")
        elif any(net.overlaps(never) for never in NEVER):
            parsed.skip("private or reserved range")
        else:
            parsed.networks.append(net)
    return parsed


def _prefix_key(net: ipaddress.IPv4Network) -> str:
    """'a.b.c.' for a /24, 'a.b.' for a /16, 'a.' for a /8, the address for a /32."""
    octets = str(net.network_address).split(".")
    if net.prefixlen == 32:
        return ".".join(octets)
    return ".".join(octets[: net.prefixlen // 8]) + "."


def cdb_keys(net: ipaddress.IPv4Network) -> list[str]:
    """CDB keys that make address_match_key match exactly the addresses of `net`."""
    if net.prefixlen in (8, 16, 24, 32):
        return [_prefix_key(net)]
    boundary = next(b for b in (16, 24, 32) if b > net.prefixlen)
    return [_prefix_key(sub) for sub in net.subnets(new_prefix=boundary)]


def _covered(key: str, keys: set[str]) -> bool:
    """True if a broader prefix key already in `keys` covers `key`."""
    parts = key.rstrip(".").split(".")
    return any(".".join(parts[:n]) + "." in keys for n in range(1, len(parts)))


def _sort_key(key: str) -> tuple:
    parts = key.rstrip(".").split(".")
    return (*[int(p) for p in parts], *[-1] * (4 - len(parts)))


def build_list(networks: list[ipaddress.IPv4Network], label: str, max_entries: int = MAX_ENTRIES) -> str:
    """The CDB text list (`key:value` lines), deduplicated, broader prefixes winning."""
    keys: set[str] = set()
    for net in networks:
        keys.update(cdb_keys(net))
        if len(keys) > max_entries:
            raise ValueError(f"more than {max_entries} entries: is this really an IP blocklist?")
    kept = sorted((k for k in keys if not _covered(k, keys)), key=_sort_key)
    return "".join(f"{key}:{label}\n" for key in kept)


# ----------------------------------------------------------------------------- sources

def cache_paths(url: str, cache_dir: Path = CACHE_DIR) -> tuple[Path, Path]:
    digest = hashlib.sha256(url.encode()).hexdigest()[:12]
    return cache_dir / f"feed-{digest}.txt", cache_dir / f"feed-{digest}.json"


def fetch(url: str, timeout: float = 20.0) -> str:
    if not url.startswith(("https://", "file://")):
        raise ValueError(f"refusing {url!r}: use https:// (or file:// for a local feed)")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (scheme checked)
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"feed larger than {MAX_BYTES} bytes")
    return body.decode("utf-8", errors="replace")


def cached(url: str, max_age_hours: float | None, cache_dir: Path = CACHE_DIR,
           now: dt.datetime | None = None) -> str | None:
    """The cached copy of `url`, if any and (when max_age_hours is set) fresh enough."""
    data, meta = cache_paths(url, cache_dir)
    if not (data.is_file() and meta.is_file()):
        return None
    if max_age_hours is not None:
        fetched = dt.datetime.fromisoformat(json.loads(meta.read_text(encoding="utf-8"))["fetched_at"])
        now = now or dt.datetime.now(dt.timezone.utc)
        if now - fetched > dt.timedelta(hours=max_age_hours):
            return None
    return data.read_text(encoding="utf-8")


def store(url: str, text: str, cache_dir: Path = CACHE_DIR, now: dt.datetime | None = None) -> None:
    data, meta = cache_paths(url, cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    data.write_text(text, encoding="utf-8", newline="\n")
    meta.write_text(json.dumps({
        "url": url,
        "fetched_at": (now or dt.datetime.now(dt.timezone.utc)).isoformat(),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }, indent=2) + "\n", encoding="utf-8", newline="\n")


def feed_label(url: str) -> str:
    """Short source name for the CDB value, e.g. 'feodotracker.abuse.ch'."""
    host = re.sub(r"^[a-z]+://", "", url).split("/", 1)[0]
    return re.sub(r"[^A-Za-z0-9._-]", "-", host or "local-feed")


def load_source(args: argparse.Namespace, log=print) -> tuple[str, str]:
    """(feed text, label) following: sample | fresh cache | network | any cache | sample."""
    if args.sample:
        return args.sample_file.read_text(encoding="utf-8"), "sample-feed"
    label = feed_label(args.url)
    text = cached(args.url, None if args.offline else args.max_age, args.cache_dir)
    if text is not None:
        log(f"[*] using the cached feed ({'offline' if args.offline else f'< {args.max_age} h old'})")
        return text, label
    if not args.offline:
        try:
            text = fetch(args.url)
            store(args.url, text, args.cache_dir)
            log(f"[*] downloaded {args.url}")
            return text, label
        except (OSError, ValueError, urllib.error.URLError) as exc:
            log(f"[!] download failed ({exc}); falling back")
            text = cached(args.url, None, args.cache_dir)
            if text is not None:
                log("[*] using the last cached feed (stale)")
                return text, label
    log("[!] no cached feed: using the sample feed of the repo (documentation addresses only)")
    return args.sample_file.read_text(encoding="utf-8"), "sample-feed"


def main(argv: list[str] | None = None, log=print) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=os.environ.get("TI_FEED_URL", DEFAULT_URL),
                        help="feed URL (env TI_FEED_URL), default: abuse.ch Feodo Tracker")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--sample", action="store_true", help="build from the sample feed of the repo")
    source.add_argument("--offline", action="store_true", help="never download: cached feed, else sample")
    parser.add_argument("--max-age", type=float, default=24.0, help="hours a cached feed stays fresh")
    parser.add_argument("--check", action="store_true", help="fail if --output differs from the build")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--sample-file", type=Path, default=SAMPLE, help=argparse.SUPPRESS)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    text, label = load_source(args, log)
    parsed = parse_feed(text)
    content = build_list(parsed.networks, label)
    skipped = ", ".join(f"{n} {why}" for why, n in sorted(parsed.skipped.items())) or "none"
    entries = content.count("\n")

    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != content:
            log(f"ERROR: {args.output.name} is not the {label} build: "
                "run python scripts/update_ti.py --sample (never commit a live feed)")
            return 1
        log(f"{args.output.name} is up to date ({entries} entries from {label})")
        return 0
    if entries == 0:
        log("ERROR: the feed gave no usable address; list left unchanged")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")
    tmp.replace(args.output)
    log(f"wrote {args.output} : {entries} entries from {label} (skipped: {skipped})")
    log("load it: docker compose restart wazuh.manager   (make ti does both)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
