"""Typosquat exposure detector (DEFENSIVE).

Flags components whose name is edit-distance <=N (default 2) from a *popular*
package in the SAME ecosystem, excluding exact matches. This surfaces a
look-alike that may have slipped into the build -- the owner's exposure.

It does NOT generate look-alike names, suggest registrations, or help anyone
publish a squat. It only compares the names the owner already depends on
against a bundled reference list of common impersonation targets.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

RISK_TYPE = "typosquat"

_DATA = os.path.join(os.path.dirname(__file__), "data", "popular_packages.json")


@lru_cache(maxsize=1)
def _popular() -> dict[str, set[str]]:
    try:
        with open(_DATA, encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return {}
    return {
        eco: {str(n).lower() for n in names}
        for eco, names in raw.items()
        if isinstance(names, list)
    }


def levenshtein(a: str, b: str, *, cap: int | None = None) -> int:
    """Classic edit distance. ``cap`` short-circuits once the best row minimum
    exceeds the cap (returns cap+1)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > (cap if cap is not None else max(la, lb)):
        return (cap + 1) if cap is not None else abs(la - lb)
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ca = a[i - 1]
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if cur[j] < row_min:
                row_min = cur[j]
        if cap is not None and row_min > cap:
            return cap + 1
        prev = cur
    return prev[lb]


def typo_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance: Levenshtein plus adjacent
    transposition as ONE edit. Swapped letters ("reqeust") are the most common
    real-world typosquat, and plain Levenshtein scores them as two edits."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _allowed_distance(name: str, target: str, max_distance: int) -> int:
    """Short names collide by accident: every 2-letter package is within 2 of
    'qs' or 'ws', and 'parse5' is 2 from 'parcel'. Real squats are almost all
    one edit, so: < 4 chars never compared, 4-7 chars allow 1, 8+ allow max."""
    shortest = min(len(name), len(target))
    if shortest < 4:
        return 0
    if shortest < 8:
        return min(1, max_distance)
    return max_distance


def nearest_popular(ecosystem: str, name: str, max_distance: int) -> tuple[str, int] | None:
    """Return (popular_name, distance) of the closest popular package within
    ``max_distance``, or None. Exact matches are excluded (distance 0)."""
    targets = _popular().get(ecosystem)
    if not targets:
        return None
    n = name.lower()
    if n in targets:
        return None
    best: tuple[str, int] | None = None
    for target in targets:
        allowed = _allowed_distance(n, target, max_distance)
        if allowed == 0 or levenshtein(n, target, cap=2 * allowed) > 2 * allowed:
            continue  # cheap prefilter: OSA <= allowed implies Levenshtein <= 2*allowed
        d = typo_distance(n, target)
        if 0 < d <= allowed and (best is None or d < best[1]):
            best = (target, d)
            if d == 1:
                break
    return best


def detect(components: list[dict[str, Any]], *, max_distance: int = 2) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in components:
        name = c.get("name") or ""
        eco = c.get("ecosystem") or ""
        if not name or not eco:
            continue
        hit = nearest_popular(eco, name, max_distance)
        if hit is None:
            continue
        target, dist = hit
        severity = "high" if dist == 1 else "medium"
        out.append({
            "risk_type": RISK_TYPE,
            "severity": severity,
            "summary": (
                f"'{name}' is edit-distance {dist} from the popular {eco} package "
                f"'{target}' -- possible typosquat that slipped into the build"
            ),
            "detail": {
                "ecosystem": eco,
                "resembles": target,
                "edit_distance": dist,
                "note": "Verify this dependency is the intended package, not a look-alike.",
            },
            "ecosystem": eco,
            "name": name,
            "version": c.get("version"),
        })
    return out
