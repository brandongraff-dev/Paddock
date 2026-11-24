#!/usr/bin/env python3
"""Turn CHANGELOG.md into the data file the dashboard's Settings -> About page shows.

    python scripts/export_changelog.py            # write dashboard/src/pages/about/changelog.generated.ts
    python scripts/export_changelog.py --check    # exit 1 if the generated file is out of date

CHANGELOG.md is the source. Its shape (anything else is rejected, so a typo fails here and not on screen):

    ## State of the app          a table: | Area | State | Notes |   State is one of STATES
    ## [Unreleased]              or  ## [1.2.3] - 2026-01-31
    ### Added|Changed|Fixed|Security|Known issues|Removed|Deprecated    then "- " bullets
    ## Anything else             a plain bullet list (e.g. "Earlier work")
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "CHANGELOG.md"
OUT = ROOT / "dashboard" / "src" / "pages" / "about" / "changelog.generated.ts"

STATES = ("working", "beta", "unverified", "not released")
KINDS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security", "Known issues")
RELEASE_RE = re.compile(r"^\[(?P<version>Unreleased|\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\](?: - (?P<date>\d{4}-\d{2}-\d{2}))?$")
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


class ChangelogError(ValueError):
    pass


def plain(text: str) -> str:
    """Markdown the page does not render (links, bold, code) reduced to its words."""
    t = LINK_RE.sub(r"\1", text)
    t = re.sub(r"\*\*(.+?)\*\*", r"\1", t)
    t = re.sub(r"`([^`]+)`", r"\1", t)
    t = re.sub(r"(?<!\*)\*(?!\*)([^*]+)\*(?!\*)", r"\1", t)
    return t.strip()


def parse(text: str) -> dict:
    lines = text.splitlines()
    state: list[dict] = []
    releases: list[dict] = []
    other: list[dict] = []
    mode: tuple[str, dict | None] = ("intro", None)
    kind: str | None = None
    current: dict | None = None
    bullet: list[str] | None = None

    def flush_bullet() -> None:
        nonlocal bullet
        if bullet is None:
            return
        item = plain(" ".join(bullet))
        if mode[0] == "release" and current is not None and kind is not None:
            current["sections"][-1]["items"].append(item)
        elif mode[0] == "other" and current is not None:
            current["items"].append(item)
        bullet = None

    for no, raw in enumerate(lines, 1):
        line = raw.rstrip()
        if line.startswith("## "):
            flush_bullet()
            title = line[3:].strip()
            kind = None
            if title == "State of the app":
                mode, current = ("state", None), None
            elif RELEASE_RE.match(title):
                m = RELEASE_RE.match(title)
                if m["version"] != "Unreleased" and not m["date"]:
                    raise ChangelogError(f"line {no}: released version {title} needs a date: ## [1.2.3] - 2026-01-31")
                current = {"version": m["version"], "date": m["date"], "sections": []}
                releases.append(current)
                mode = ("release", None)
            elif title.startswith("["):
                raise ChangelogError(f"line {no}: unrecognised release heading {title!r}")
            else:
                current = {"title": title, "items": []}
                other.append(current)
                mode = ("other", None)
            continue
        if mode[0] == "intro":
            continue
        if line.startswith("### "):
            flush_bullet()
            if mode[0] != "release":
                raise ChangelogError(f"line {no}: ### is only valid inside a release")
            kind = line[4:].strip()
            if kind not in KINDS:
                raise ChangelogError(f"line {no}: unknown section {kind!r}; use one of {', '.join(KINDS)}")
            current["sections"].append({"kind": kind, "items": []})
            continue
        if mode[0] == "state":
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells[0] in ("Area",) or set("".join(cells)) <= set("-: "):
                continue
            if len(cells) != 3:
                raise ChangelogError(f"line {no}: a state row needs 3 cells (Area | State | Notes)")
            if cells[1] not in STATES:
                raise ChangelogError(f"line {no}: state {cells[1]!r} is not one of {', '.join(STATES)}")
            state.append({"area": plain(cells[0]), "state": cells[1], "notes": plain(cells[2])})
            continue
        if line.startswith("- "):
            flush_bullet()
            if mode[0] == "release" and kind is None:
                raise ChangelogError(f"line {no}: a bullet must be under a ### section")
            bullet = [line[2:].strip()]
        elif line.startswith("  ") and bullet is not None and line.strip():
            bullet.append(line.strip())
        elif not line.strip():
            flush_bullet()
        elif mode[0] in ("release", "other") and not line.startswith("#"):
            flush_bullet()   # a paragraph between bullets: not shown
    flush_bullet()

    if not state:
        raise ChangelogError("no 'State of the app' table found")
    if not releases:
        raise ChangelogError("no release section found (add ## [Unreleased])")
    if releases[0]["version"] != "Unreleased" and len({r["version"] for r in releases}) != len(releases):
        raise ChangelogError("duplicate release version")
    for r in releases:
        r["sections"] = [s for s in r["sections"] if s["items"]]
    return {"state": state, "releases": releases, "other": [o for o in other if o["items"]]}


def render(data: dict) -> str:
    body = json.dumps(data, indent=2, ensure_ascii=False)
    return (
        "// GENERATED from CHANGELOG.md by scripts/export_changelog.py. Do not edit; edit CHANGELOG.md.\n"
        "// `python scripts/export_changelog.py --check` (and the scripts tests) fail if this is out of date.\n"
        'import type { Changelog } from "./types";\n\n'
        f"export const CHANGELOG: Changelog = {body};\n"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if the generated file is not up to date")
    a = ap.parse_args(argv)
    try:
        out = render(parse(SRC.read_text(encoding="utf-8")))
    except ChangelogError as e:
        print(f"CHANGELOG.md: {e}", file=sys.stderr)
        return 1
    if a.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != out:
            print(f"{OUT.relative_to(ROOT)} is out of date: run python scripts/export_changelog.py", file=sys.stderr)
            return 1
        print("OK: changelog data is up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(out, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
