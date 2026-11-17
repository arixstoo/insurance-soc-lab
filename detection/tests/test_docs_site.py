"""The documentation site (mkdocs.yml): every page of docs/ is in the nav, and the hook sends
links to repository files outside docs/ to GitHub. The build itself runs in docs.yml
(``mkdocs build --strict``)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"


class _Loader(yaml.SafeLoader):
    """safe_load that tolerates the !!python/name tag of the mermaid fence."""


_Loader.add_multi_constructor("tag:yaml.org,2002:python/", lambda _loader, _suffix, _node: None)


def _nav_pages(node) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, list):
        return [p for item in node for p in _nav_pages(item)]
    if isinstance(node, dict):
        return [p for value in node.values() for p in _nav_pages(value)]
    return []


def _config() -> dict:
    return yaml.load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=_Loader)


def _hooks():
    spec = importlib.util.spec_from_file_location("mkdocs_hooks", ROOT / "scripts" / "mkdocs_hooks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_page_is_in_the_nav_and_every_nav_entry_exists():
    nav = _nav_pages(_config()["nav"])
    pages = sorted(p.relative_to(DOCS).as_posix() for p in DOCS.rglob("*.md"))
    assert sorted(nav) == pages
    assert len(nav) == len(set(nav))


def test_links_outside_docs_go_to_github():
    hooks = _hooks()
    page = DOCS / "runbooks" / "ssh-brute-force.md"
    url = hooks.github_url("../../detection/rules/insurco_rules.xml", page, DOCS, ROOT)
    assert url == f"{hooks.REPO_URL}/blob/main/detection/rules/insurco_rules.xml"
    assert hooks.github_url("../../detection/lists/", page, DOCS, ROOT).endswith("/tree/main/detection/lists")


def test_links_inside_docs_and_urls_are_left_to_mkdocs():
    hooks = _hooks()
    page = DOCS / "runbooks" / "ssh-brute-force.md"
    for target in ("../response.md", "README.md", "https://example.org/x", "mailto:a@example.org",
                   "../../does-not-exist.md"):
        assert hooks.github_url(target, page, DOCS, ROOT) is None, target
