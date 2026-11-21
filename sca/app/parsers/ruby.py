"""Ruby-ecosystem parser: Gemfile.lock. Emits ``RubyGems``.

Gemfile.lock has a ``GEM`` section: ``specs:`` lists resolved gems (indent 4,
``name (version)``) and their runtime deps (indent 6, ``name (constraint)``),
and a trailing ``DEPENDENCIES`` section names the direct gems. Untrusted DATA.
"""
from __future__ import annotations

import re
from typing import Any

from ._util import component, dedupe

ECOSYSTEM = "RubyGems"

_SPEC = re.compile(r"^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$")
_SUBDEP = re.compile(r"^ {6}([A-Za-z0-9._-]+)")
_DEP = re.compile(r"^ {2}([A-Za-z0-9._-]+)")


def parse_gemfile_lock(content: str) -> list[dict[str, Any]]:
    if not isinstance(content, str):
        return []
    lines = content.splitlines()

    versions: dict[str, str] = {}
    edges: dict[str, list[str]] = {}
    direct: set[str] = set()

    section = None
    current_spec: str | None = None
    for raw in lines:
        if raw and not raw.startswith(" "):
            section = raw.strip()
            current_spec = None
            continue
        if section == "GEM":
            m = _SPEC.match(raw)
            if m:
                name, version = m.group(1), m.group(2).strip()
                versions[name] = version
                edges.setdefault(name, [])
                current_spec = name
                continue
            sm = _SUBDEP.match(raw)
            if sm and current_spec:
                edges.setdefault(current_spec, []).append(sm.group(1))
                continue
        elif section == "DEPENDENCIES":
            dm = _DEP.match(raw)
            if dm:
                direct.add(dm.group(1).rstrip("!"))

    if not versions:
        return []
    roots = [n for n in versions if n in direct] or None
    from ._util import resolve_graph
    return dedupe(resolve_graph(ECOSYSTEM, versions, edges, roots=roots))
