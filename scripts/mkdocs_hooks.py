"""MkDocs hooks for the Paddock docs site (referenced from mkdocs.yml).

Several pages are written in parallel by different contributors, so the nav
in mkdocs.yml lists pages that may not exist yet in a given checkout. This
hook keeps ``mkdocs build --strict`` meaningful for the pages that DO exist:

* a nav entry pointing at a missing ``.md`` file is dropped (logged at INFO);
* a nav entry pointing at a directory (``trust/``) expands to every Markdown
  file in it (``index.md``/``README.md`` first), or is dropped if empty;
* sections left empty are dropped.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("mkdocs.hooks.paddock")


def _title(p: Path) -> str:
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    except OSError:
        pass
    return p.stem.replace("_", " ").replace("-", " ").title()


def _expand_dir(docs: Path, rel: str) -> list[Any]:
    d = docs / rel
    if not d.is_dir():
        return []
    files = sorted(d.rglob("*.md"), key=lambda p: (p.name.lower() not in ("index.md", "readme.md"), str(p)))
    return [{_title(p): str(p.relative_to(docs)).replace("\\", "/")} for p in files]


def _filter(items: list[Any], docs: Path) -> list[Any]:
    out: list[Any] = []
    for item in items:
        if isinstance(item, str):
            if item.startswith(("http://", "https://")) or (docs / item).is_file():
                out.append(item)
            else:
                log.info("nav: skipping missing page %s", item)
            continue
        if not isinstance(item, dict):
            out.append(item)
            continue
        for title, value in item.items():
            if isinstance(value, list):
                kept = _filter(value, docs)
                if kept:
                    out.append({title: kept})
            elif isinstance(value, str) and value.endswith("/"):
                pages = _expand_dir(docs, value)
                if pages:
                    out.append({title: pages})
                else:
                    log.info("nav: skipping empty section %s (%s)", title, value)
            elif isinstance(value, str) and not value.startswith(("http://", "https://")) and not (docs / value).is_file():
                log.info("nav: skipping missing page %s", value)
            else:
                out.append({title: value})
    return out


def on_config(config, **_kwargs):
    nav = config.get("nav")
    if nav:
        config["nav"] = _filter(nav, Path(config["docs_dir"]))
    return config


_LINK = re.compile(r"(\]\()([^)\s]+)(\))")


def on_page_markdown(markdown: str, page, config, **_kwargs) -> str:
    """Point links that leave docs/ (../SECURITY.md, ../sentry/...) at GitHub.

    The engineering notes link to source files elsewhere in the repo. Those
    links work on GitHub but not on the site; rewriting them to the repo's
    blob URL keeps them useful and lets the strict build still fail on
    genuinely broken links between site pages.
    """
    docs = Path(config["docs_dir"]).resolve()
    root = docs.parent
    repo = (config.get("repo_url") or "").rstrip("/")
    page_dir = (docs / page.file.src_path).parent

    def fix(m: re.Match[str]) -> str:
        target = m.group(2)
        if not repo or target.startswith(("http://", "https://", "mailto:", "#", "/")):
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = (page_dir / path).resolve()
        try:
            resolved.relative_to(docs)
            return m.group(0)  # inside docs/: let MkDocs validate it
        except ValueError:
            pass
        try:
            rel = resolved.relative_to(root).as_posix()
        except ValueError:
            return m.group(0)
        kind = "tree" if resolved.is_dir() else "blob"
        url = f"{repo}/{kind}/main/{rel}" + (f"#{anchor}" if anchor else "")
        return f"{m.group(1)}{url}{m.group(3)}"

    return _LINK.sub(fix, markdown)
