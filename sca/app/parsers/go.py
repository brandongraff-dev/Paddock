"""Go-ecosystem parser: go.sum (+ go.mod for direct markers). Emits ``Go``.

go.sum lists every module hash (two lines per module: one for the zip, one for
the ``/go.mod``). go.mod's ``require`` block marks the direct dependencies.
Both are untrusted DATA; parsed as text only.
"""
from __future__ import annotations

import re
from typing import Any

from ._util import component, dedupe

ECOSYSTEM = "Go"

_GOSUM_LINE = re.compile(r"^(\S+)\s+(v\S+?)(?:/go\.mod)?\s+h1:")
_REQUIRE_LINE = re.compile(r"^\s*(\S+)\s+(v\S+)")


def parse_go(content: str, go_mod: str | None = None) -> list[dict[str, Any]]:
    """Parse go.sum. If ``go_mod`` is given, its require block marks directs."""
    direct = _direct_from_gomod(go_mod) if go_mod else set()
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    if isinstance(content, str):
        for raw in content.splitlines():
            m = _GOSUM_LINE.match(raw.strip())
            if not m:
                continue
            name, version = m.group(1), m.group(2)
            # strip +incompatible suffix for cleaner version, keep original too
            key = (name, version)
            if key in seen:
                continue
            is_direct = name in direct
            seen[key] = component(
                ECOSYSTEM, name, version,
                direct=is_direct, depth=0 if is_direct else 1,
            )
    return dedupe(list(seen.values()))


def _direct_from_gomod(go_mod: str) -> set[str]:
    direct: set[str] = set()
    if not isinstance(go_mod, str):
        return direct
    in_block = False
    for raw in go_mod.splitlines():
        line = raw.strip()
        if line.startswith("require (") or line == "require (":
            in_block = True
            continue
        if in_block:
            if line.startswith(")"):
                in_block = False
                continue
            if line.startswith("//") or not line:
                continue
            m = _REQUIRE_LINE.match(line)
            if m and "// indirect" not in raw:
                direct.add(m.group(1))
            continue
        if line.startswith("require "):
            rest = line[len("require "):]
            m = _REQUIRE_LINE.match(rest)
            if m and "// indirect" not in raw:
                direct.add(m.group(1))
    return direct
