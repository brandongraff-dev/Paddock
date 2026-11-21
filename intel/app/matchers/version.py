"""Version comparison that gracefully handles semver + loose vendor schemes.

Returns:
  -1  if a < b
   0  if a == b
   1  if a > b
  math.nan if the two versions are incomparable (e.g. "1.0.0-beta" vs "banana")

Design notes
------------
We split each version on any non-numeric boundary and compare component by
component. Numeric components compare as integers; alpha components compare
lexicographically with a mild SemVer-style tweak: a pre-release component
(alphanumeric segment after a number) sorts BEFORE no-component, so that
``1.2.3-beta.1 < 1.2.3`` as SemVer requires. We stop short of a full SemVer
parser on purpose — the vendor versions we match against in CVE feeds look
like ``14.04.1``, ``2019.1.3``, ``v1.0`` far more often than strict SemVer.
"""
from __future__ import annotations

import math
import re
from typing import Union

Number = Union[int, str]

_SPLIT = re.compile(r"[._\-+]")
_NUM = re.compile(r"^(\d+)(.*)$")
_V_PREFIX = re.compile(r"^[vV]")


def normalize(v: str) -> str:
    """Trim whitespace, a leading ``v``/``V``, and any build-metadata suffix."""
    if v is None:  # type: ignore[truthy-bool]
        return ""
    v = v.strip()
    if not v or v in {"*", "-", "ANY", "any"}:
        return ""
    # SemVer build metadata (after +) is explicitly non-ordering; drop it.
    if "+" in v:
        v = v.split("+", 1)[0]
    v = _V_PREFIX.sub("", v)
    return v


def _split(v: str) -> list[list[Number]]:
    """Break "1.2.3-beta.1" into [[1],[2],[3],["beta"],[1]] etc.

    Each "component" is itself a list so that mixed segments like "4a" become
    [4, "a"], which compares cleanly.
    """
    if not v:
        return []
    comps: list[list[Number]] = []
    for part in _SPLIT.split(v):
        if part == "":
            continue
        tokens: list[Number] = []
        remaining = part
        while remaining:
            m = _NUM.match(remaining)
            if m:
                tokens.append(int(m.group(1)))
                remaining = m.group(2)
            else:
                tokens.append(remaining.lower())
                remaining = ""
        if tokens:
            comps.append(tokens)
    return comps


def _is_prerelease(token: Number) -> bool:
    return isinstance(token, str)


def _cmp_tokens(a: Number, b: Number) -> int:
    if isinstance(a, int) and isinstance(b, int):
        if a < b: return -1
        if a > b: return 1
        return 0
    if isinstance(a, int):  # number < string ? use SemVer: numeric identifiers rank below alphanumeric
        return -1
    if isinstance(b, int):
        return 1
    # both strings
    if a < b: return -1
    if a > b: return 1
    return 0


def _cmp_components(ac: list[Number], bc: list[Number]) -> int:
    for a, b in zip(ac, bc):
        r = _cmp_tokens(a, b)
        if r != 0:
            return r
    if len(ac) < len(bc):
        return -1
    if len(ac) > len(bc):
        return 1
    return 0


def compare(a: str, b: str) -> float:
    """Compare two version strings. Returns -1/0/1, or math.nan if incomparable."""
    a_n = normalize(a)
    b_n = normalize(b)
    if a_n == "" and b_n == "":
        return 0
    if a_n == "":
        return -1
    if b_n == "":
        return 1

    a_comps = _split(a_n)
    b_comps = _split(b_n)

    # If neither parsed to any components, they are incomparable.
    if not a_comps and not b_comps:
        return math.nan
    if not a_comps:
        return -1
    if not b_comps:
        return 1

    # Split out pre-release tail: in SemVer, "X.Y.Z-pre" < "X.Y.Z".
    def _split_pre(comps: list[list[Number]]) -> tuple[list[list[Number]], list[list[Number]]]:
        for i, c in enumerate(comps):
            if c and _is_prerelease(c[0]):
                return comps[:i], comps[i:]
        return comps, []

    a_core, a_pre = _split_pre(a_comps)
    b_core, b_pre = _split_pre(b_comps)

    # Compare numeric cores first.
    n = max(len(a_core), len(b_core))
    for i in range(n):
        ac = a_core[i] if i < len(a_core) else [0]
        bc = b_core[i] if i < len(b_core) else [0]
        r = _cmp_components(ac, bc)
        if r != 0:
            return r

    # Equal cores: a pre-release ranks below no-pre-release.
    if a_pre and not b_pre:
        return -1
    if b_pre and not a_pre:
        return 1
    if not a_pre and not b_pre:
        return 0

    n = max(len(a_pre), len(b_pre))
    for i in range(n):
        ac = a_pre[i] if i < len(a_pre) else []
        bc = b_pre[i] if i < len(b_pre) else []
        if not ac and not bc:
            continue
        if not ac:
            return -1
        if not bc:
            return 1
        r = _cmp_components(ac, bc)
        if r != 0:
            return r
    return 0


def in_range(
    version: str,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
    exact: str | None = None,
) -> bool:
    """Return True if ``version`` falls within the given bounds.

    An unbounded side is open. ``exact`` short-circuits the bounds. If any
    comparison yields NaN the version is considered NOT in range (fail safe —
    we would rather miss a match than falsely open a finding).
    """
    v = normalize(version)
    if not v:
        return False

    if exact and normalize(exact) and normalize(exact) != "*":
        r = compare(v, exact)
        return not math.isnan(r) and r == 0

    def cmp_or_fail(a: str, b: str) -> float | None:
        r = compare(a, b)
        if math.isnan(r):
            return None
        return r

    if start_including:
        r = cmp_or_fail(v, start_including)
        if r is None or r < 0:
            return False
    if start_excluding:
        r = cmp_or_fail(v, start_excluding)
        if r is None or r <= 0:
            return False
    if end_including:
        r = cmp_or_fail(v, end_including)
        if r is None or r > 0:
            return False
    if end_excluding:
        r = cmp_or_fail(v, end_excluding)
        if r is None or r >= 0:
            return False
    return True
