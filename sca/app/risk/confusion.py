"""Dependency-confusion exposure detector (DEFENSIVE).

Flags dependencies that look internal/private -- scoped ``@org/*`` names, or
names matching common internal patterns -- so the owner can check whether the
same name is (or could be) claimed on the public registry and shadow their
private package.

This detects the owner's OWN exposure. It never resolves, publishes, registers,
or claims any name; the ``detail`` only explains the exposure and the check to
run. The optional ``public_names`` set lets a caller mark a name as known to
exist publicly (raising severity), but we never fetch to *create* that risk.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

RISK_TYPE = "dependency_confusion"

# Heuristic markers of an internal/private package name.
_INTERNAL_TOKENS = ("internal", "private", "corp", "intranet", "-inc", "-internal")


def _looks_internal(ecosystem: str, name: str) -> tuple[bool, str]:
    n = name.lower()
    if ecosystem == "npm" and name.startswith("@"):
        return True, "npm scoped name (@org/*) -- scope must be owned on the public registry"
    for tok in _INTERNAL_TOKENS:
        if tok in n:
            return True, f"name contains internal marker '{tok.strip('-')}'"
    # java reverse-DNS group that looks like a private/company domain
    if ecosystem == "Maven" and ":" in name:
        group = name.split(":", 1)[0]
        if any(t in group.lower() for t in ("internal", "corp", "private")):
            return True, "Maven group looks internal/private"
    return False, ""


def detect(
    components: list[dict[str, Any]],
    *,
    public_names: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    public = {str(p).lower() for p in (public_names or [])}
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for c in components:
        name = c.get("name") or ""
        eco = c.get("ecosystem") or ""
        if not name or not eco:
            continue
        key = (eco, name)
        if key in seen:
            continue
        internal, reason = _looks_internal(eco, name)
        if not internal:
            continue
        seen.add(key)
        claimable = name.lower() in public
        severity = "high" if claimable else "medium"
        summary = (
            f"'{name}' ({eco}) looks internal/private -- dependency-confusion "
            "exposure if an attacker claims the same name on the public registry"
        )
        if claimable:
            summary = (
                f"'{name}' ({eco}) looks internal yet a public package with this "
                "name exists -- active dependency-confusion exposure"
            )
        out.append({
            "risk_type": RISK_TYPE,
            "severity": severity,
            "summary": summary,
            "detail": {
                "ecosystem": eco,
                "reason": reason,
                "public_name_exists": claimable,
                "check": (
                    "Confirm this name is published under YOUR account/scope on the "
                    "public registry, pin to a trusted source, and configure the "
                    "installer to refuse public fallback for this scope."
                ),
            },
            "ecosystem": eco,
            "name": name,
            "version": c.get("version"),
        })
    return out
