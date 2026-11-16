"""scripts/update_ti.py (no network, no Docker): feed parsing, CDB keys, safety filter,
cache and fallback order, and the committed list being the sample build.

The engine side (prefix keys and expanded CIDRs really match) is in cases.yaml ("ti - ...").
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import update_ti  # noqa: E402

NET = ipaddress.ip_network
URL = "https://feeds.example/blocklist.txt"


def run(tmp_path, *args, log=None):
    lines = []
    code = update_ti.main([*args, "--output", str(tmp_path / "ti-bad-ips"),
                           "--cache-dir", str(tmp_path / "cache"), "--url", URL], log=log or lines.append)
    return code, lines


# ----------------------------------------------------------------------------- parsing

def test_feed_parsing_keeps_first_token_and_skips_comments():
    parsed = update_ti.parse_feed("# header\n198.51.100.7  # C2\n203.0.113.0/24 ; SBL123\n\n192.0.2.9,botnet\n")
    assert parsed.networks == [NET("198.51.100.7/32"), NET("203.0.113.0/24"), NET("192.0.2.9/32")]
    assert parsed.skipped == {}


@pytest.mark.parametrize(("line", "reason"), [
    ("10.20.5.10", "private or reserved range"),       # the lab itself
    ("10.0.0.0/8", "private or reserved range"),
    ("192.168.1.1", "private or reserved range"),
    ("127.0.0.1", "private or reserved range"),
    ("100.64.0.1", "private or reserved range"),
    ("224.0.0.1", "private or reserved range"),
    ("192.0.0.0/7", "wider than /8"),
    ("2001:db8::1", "IPv6"),
    ("not-an-ip", "not an address"),
])
def test_unsafe_or_unusable_entries_are_skipped(line, reason):
    parsed = update_ti.parse_feed(line)
    assert parsed.networks == [] and parsed.skipped == {reason: 1}


def test_documentation_ranges_are_allowed():
    assert update_ti.parse_feed("192.0.2.1\n198.51.100.1\n203.0.113.1").networks


# ----------------------------------------------------------------------------- CDB keys

@pytest.mark.parametrize(("cidr", "keys"), [
    ("198.51.100.7/32", ["198.51.100.7"]),
    ("192.0.2.0/24", ["192.0.2."]),
    # cdb_keys is pure (the range filter is parse_feed's): lab addresses test the wide prefixes
    ("10.20.0.0/16", ["10.20."]),
    ("10.0.0.0/8", ["10."]),
    ("203.0.113.200/30", ["203.0.113.200", "203.0.113.201", "203.0.113.202", "203.0.113.203"]),
    ("10.20.0.0/23", ["10.20.0.", "10.20.1."]),
    ("10.20.0.0/22", ["10.20.0.", "10.20.1.", "10.20.2.", "10.20.3."]),
])
def test_cidrs_become_prefix_keys_or_are_expanded(cidr, keys):
    assert update_ti.cdb_keys(NET(cidr)) == keys


def test_list_is_sorted_deduplicated_and_broader_prefix_wins():
    nets = [NET("192.0.2.9/32"), NET("192.0.2.0/24"), NET("198.51.100.20/32"), NET("198.51.100.3/32"),
            NET("198.51.100.3/32")]
    assert update_ti.build_list(nets, "feed") == "192.0.2.:feed\n198.51.100.3:feed\n198.51.100.20:feed\n"


def test_list_size_is_capped():
    with pytest.raises(ValueError, match="more than 10 entries"):
        update_ti.build_list([NET("203.0.113.0/27")], "feed", max_entries=10)


def test_label_comes_from_the_feed_host():
    assert update_ti.feed_label(update_ti.DEFAULT_URL) == "feodotracker.abuse.ch"
    assert update_ti.feed_label("file:///tmp/my feed.txt") == "local-feed"


# ----------------------------------------------------------------------------- sources

def test_only_https_or_file_urls_are_fetched():
    with pytest.raises(ValueError, match="https"):
        update_ti.fetch("http://feeds.example/list.txt")


def test_fresh_cache_is_used_without_network(tmp_path, monkeypatch):
    update_ti.store(URL, "198.51.100.77\n", tmp_path / "cache")
    monkeypatch.setattr(update_ti, "fetch", lambda url: pytest.fail("must not download"))
    code, log = run(tmp_path)
    assert code == 0 and "198.51.100.77:feeds.example" in (tmp_path / "ti-bad-ips").read_text()


def test_stale_cache_is_refreshed(tmp_path, monkeypatch):
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=30)
    update_ti.store(URL, "198.51.100.77\n", tmp_path / "cache", now=old)
    monkeypatch.setattr(update_ti, "fetch", lambda url: "198.51.100.88\n")
    code, _ = run(tmp_path)
    assert code == 0 and (tmp_path / "ti-bad-ips").read_text() == "198.51.100.88:feeds.example\n"
    assert update_ti.cached(URL, 1, tmp_path / "cache") == "198.51.100.88\n"


def test_download_failure_falls_back_to_the_stale_cache(tmp_path, monkeypatch):
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)
    update_ti.store(URL, "198.51.100.77\n", tmp_path / "cache", now=old)

    def down(url):
        raise OSError("network unreachable")
    monkeypatch.setattr(update_ti, "fetch", down)
    code, log = run(tmp_path)
    assert code == 0 and "198.51.100.77" in (tmp_path / "ti-bad-ips").read_text()
    assert any("stale" in line for line in log)


def test_no_network_and_no_cache_falls_back_to_the_sample(tmp_path, monkeypatch):
    def down(url):
        raise OSError("network unreachable")
    monkeypatch.setattr(update_ti, "fetch", down)
    code, _ = run(tmp_path)
    assert (tmp_path / "ti-bad-ips").read_text() == update_ti.OUTPUT.read_text(encoding="utf-8")
    assert code == 0


def test_offline_never_downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(update_ti, "fetch", lambda url: pytest.fail("must not download"))
    code, _ = run(tmp_path, "--offline")
    assert code == 0 and "sample-feed" in (tmp_path / "ti-bad-ips").read_text()


def test_an_empty_feed_leaves_the_list_unchanged(tmp_path, monkeypatch):
    (tmp_path / "ti-bad-ips").write_text("198.51.100.1:old\n")
    monkeypatch.setattr(update_ti, "fetch", lambda url: "# nothing today\n10.0.0.1\n")
    code, _ = run(tmp_path)
    assert code == 1 and (tmp_path / "ti-bad-ips").read_text() == "198.51.100.1:old\n"


# ----------------------------------------------------------------------------- the committed list

def test_committed_list_is_the_sample_build():
    assert update_ti.main(["--sample", "--check"], log=lambda *_: None) == 0


def test_check_fails_on_a_live_feed_list(tmp_path):
    (tmp_path / "ti-bad-ips").write_text("203.0.113.99:feodotracker.abuse.ch\n")
    code, log = run(tmp_path, "--sample", "--check")
    assert code == 1 and "never commit a live feed" in log[0]


def test_committed_list_only_holds_documentation_addresses():
    doc = [NET("192.0.2.0/24"), NET("198.51.100.0/24"), NET("203.0.113.0/24")]
    for line in update_ti.OUTPUT.read_text(encoding="utf-8").splitlines():
        key = line.partition(":")[0]
        first = ipaddress.ip_address(".".join((key.rstrip(".").split(".") + ["0", "0", "0"])[:4]))
        assert any(first in net for net in doc), key
