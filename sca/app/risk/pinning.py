"""Unpinned-dependency hygiene detector (DEFENSIVE, low severity).

A dependency declared with a version *range* (npm ``^``/``~``/``*``/``x``,
Python ``>=``/``~=``/``^`` without ``==``, etc.) rather than an exact pin lets
an upgrade pull in a version the owner never reviewed -- a soft supply-chain
hygiene risk. We read the range off ``metadata.spec`` where a parser recorded
it, and otherwise inspect the version string directly.
"""
from __future__ import annotations

import re
from typing import Any

RISK_TYPE = "unpinned"

_RANGE_MARKERS = ("^", "~", ">=", "<=", ">", "<", "!=", "~=", "*", "x", "||", " - ", "latest")


def _is_range(spec: str) -> bool:
    s = (spec or "").strip().lower()
    if not s:
        return False
    if s in ("*", "x", "latest"):
        return True
    return any(m in s for m in _RANGE_MARKERS)


def detect(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in components:
        meta = c.get("metadata") or {}
        spec = meta.get("spec")
        version = c.get("version") or ""
        unpinned = False
        reason_spec = None
        if meta.get("unpinned"):
            unpinned = True
            reason_spec = spec or version
        elif spec and _is_range(spec):
            unpinned = True
            reason_spec = spec
        elif _is_range(version):
            unpinned = True
            reason_spec = version
        if not unpinned:
            continue
        out.append({
            "risk_type": RISK_TYPE,
            "severity": "low",
            "summary": (
                f"'{c.get('name')}' ({c.get('ecosystem')}) is declared with a version "
                f"range ('{reason_spec}') instead of an exact pin"
            ),
            "detail": {
                "ecosystem": c.get("ecosystem"),
                "spec": reason_spec,
                "note": "Pin to an exact, reviewed version (or commit a lockfile) so "
                        "upgrades are deliberate.",
            },
            "ecosystem": c.get("ecosystem"),
            "name": c.get("name"),
            "version": c.get("version") or None,
        })
    return out
