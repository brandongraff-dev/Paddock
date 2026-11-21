"""Abandoned-dependency detector (DEFENSIVE, best-effort).

Flags components whose most recent public release is older than a threshold
(default 2 years): an unmaintained dependency is more likely to carry
unpatched vulnerabilities and to be a takeover target. Purely informational;
read-only registry metadata; skips cleanly when offline.

``detect`` is a pure function over a precomputed ``last_release`` map so it is
deterministic and testable; the service fills that map via
:mod:`app.risk._registry`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

RISK_TYPE = "abandoned"


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    for candidate in (s, s.split(".")[0] + "+00:00" if "." in s else s):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def detect(
    components: list[dict[str, Any]],
    last_release: dict[str, str] | None,
    *,
    now: datetime | None = None,
    max_age_days: int = 730,
) -> list[dict[str, Any]]:
    """``last_release`` maps ``"ecosystem|name"`` -> ISO timestamp. Components
    with no metadata (offline / unknown ecosystem) are skipped silently."""
    if not last_release:
        return []
    now = now or datetime.now(timezone.utc)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for c in components:
        eco, name = c.get("ecosystem") or "", c.get("name") or ""
        if not eco or not name:
            continue
        key = (eco, name)
        if key in seen:
            continue
        iso = last_release.get(f"{eco}|{name}")
        dt = _parse_dt(iso)
        if dt is None:
            continue
        age_days = (now - dt).days
        if age_days < max_age_days:
            continue
        seen.add(key)
        years = round(age_days / 365.0, 1)
        out.append({
            "risk_type": RISK_TYPE,
            "severity": "low" if age_days < max_age_days * 2 else "medium",
            "summary": (
                f"'{name}' ({eco}) last published {years}y ago -- likely unmaintained"
            ),
            "detail": {
                "ecosystem": eco,
                "last_release": iso,
                "age_days": age_days,
                "note": "Evaluate an actively maintained alternative or vendor the "
                        "dependency and track it yourself.",
            },
            "ecosystem": eco,
            "name": name,
            "version": c.get("version"),
        })
    return out
