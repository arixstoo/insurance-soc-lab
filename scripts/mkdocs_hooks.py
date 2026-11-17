"""MkDocs hook: links from docs/ to repository files outside docs/ point to GitHub on the site.

The Markdown keeps relative links (``../detection/rules/insurco_rules.xml``) so it reads well on
GitHub; MkDocs cannot serve those files, so in the built site they become GitHub URLs. A link to
a missing file is left alone and ``mkdocs build --strict`` reports it.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_URL = "https://github.com/arixstoo/insurance-soc-lab"
BRANCH = "main"
LINK = re.compile(r"\]\((?P<target>[^)\s#]+)(?P<anchor>#[^)\s]*)?\)")


def github_url(target: str, page_src: Path, docs_dir: Path, repo_root: Path) -> str | None:
    """GitHub URL of a relative link that leaves docs/, or None if MkDocs handles it."""
    if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("/"):
        return None  # absolute URL, mailto:, site-absolute path
    resolved = (page_src.parent / target).resolve()
    if resolved.is_relative_to(docs_dir) or not resolved.is_relative_to(repo_root):
        return None
    if not resolved.exists():
        return None
    kind = "tree" if resolved.is_dir() else "blob"
    return f"{REPO_URL}/{kind}/{BRANCH}/{resolved.relative_to(repo_root).as_posix()}"


def on_page_markdown(markdown: str, page, config, files) -> str:  # noqa: ARG001 - MkDocs hook signature
    docs_dir = Path(config["docs_dir"]).resolve()
    repo_root = docs_dir.parent
    page_src = Path(page.file.abs_src_path)

    def replace(match: re.Match) -> str:
        url = github_url(match["target"], page_src, docs_dir, repo_root)
        return match[0] if url is None else f"]({url}{match['anchor'] or ''})"

    return LINK.sub(replace, markdown)
