"""Version ordering across ecosystems (semver, PEP 440, Go, Maven), stdlib only.

Good enough to answer "which of these fixed versions is the nearest one above
the version I have": numeric release segments compare numerically, a
pre-release suffix (``rc1``, ``-beta.2``, ``.dev3``, ``-SNAPSHOT``) sorts below
the release, and post/patch qualifiers sort above it. It is not a full
implementation of any one scheme; unparsable strings sort by their text.
"""
from __future__ import annotations

import re
from functools import cmp_to_key

_SPLIT = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$", re.I)
_PRE = ("dev", "snapshot", "alpha", "a", "beta", "b", "milestone", "m", "rc", "cr", "pre", "preview")
_POST = ("post", "sp", "patch", "p")


def _qualifier_rank(tail: str) -> tuple[int, int]:
    """(rank, number) for the text after the release numbers; 0 == plain release."""
    t = tail.strip().lstrip("-_.+").lower()
    if not t or t in ("final", "ga", "release"):
        return (0, 0)
    m = re.match(r"([a-z]+)[.\-_]?(\d*)", t)
    if not m:
        return (0, 0)
    word, num = m.group(1), int(m.group(2) or 0)
    if word in _POST:
        return (1, num)
    if word in _PRE:
        # earlier in _PRE sorts lower; rank is negative so a release beats them all
        return (-(len(_PRE) - _PRE.index(word)), num)
    # "+incompatible", "+build5", ".jre7" ... build metadata: ignore
    return (0, 0)


def parse(v: str) -> tuple[tuple[int, ...], tuple[int, int], str]:
    m = _SPLIT.match((v or "").strip())
    if not m:
        return ((), (0, 0), (v or "").strip())
    nums = tuple(int(x) for x in m.group(1).split("."))
    return (nums, _qualifier_rank(m.group(2)), "")


def compare(a: str, b: str) -> int:
    pa, pb = parse(a), parse(b)
    if not pa[0] or not pb[0]:
        return (a > b) - (a < b)
    na, nb = pa[0], pb[0]
    n = max(len(na), len(nb))
    na = na + (0,) * (n - len(na))
    nb = nb + (0,) * (n - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    if pa[1] != pb[1]:
        return -1 if pa[1] < pb[1] else 1
    return 0


sort_key = cmp_to_key(compare)


def is_prerelease(v: str) -> bool:
    return parse(v)[1][0] < 0


def major(v: str) -> int | None:
    nums = parse(v)[0]
    return nums[0] if nums else None


def newest(versions: list[str]) -> str | None:
    return max(versions, key=sort_key) if versions else None


def satisfies(spec: str, version: str) -> bool | None:
    """Does an npm-style range admit ``version``? ``None`` when we cannot tell."""
    s = (spec or "").strip()
    if not s or s in ("*", "x", "latest"):
        return True
    if "||" in s or " - " in s or " " in s.replace(">= ", ">=").replace("<= ", "<="):
        return None
    m = re.match(r"^(\^|~|>=|<=|>|<|=)?\s*v?(\d+(?:\.\d+)*(?:\.[xX*])?)(.*)$", s)
    if not m or m.group(3).strip() not in ("",) and not m.group(3).startswith(("-", "+")):
        return None
    op, base = m.group(1) or "=", m.group(2)
    parts = [p for p in base.split(".") if p not in ("x", "X", "*")]
    floor = ".".join(parts + ["0"] * (3 - len(parts))) + m.group(3)
    cmp = compare(version, floor)
    nums = [int(p) for p in parts]
    if op == "=":
        if len(parts) < 3:
            return parse(version)[0][: len(nums)] == tuple(nums)
        return cmp == 0
    if op == ">=":
        return cmp >= 0
    if op == ">":
        return cmp > 0
    if op == "<=":
        return compare(version, floor) <= 0
    if op == "<":
        return cmp < 0
    if cmp < 0:
        return False
    vn = parse(version)[0] + (0, 0, 0)
    if op == "~":
        k = 2 if len(nums) >= 2 else 1
        return tuple(vn[:k]) == tuple((nums + [0, 0])[:k])
    # caret: first non-zero component is the compatibility boundary
    nn = (nums + [0, 0, 0])[:3]
    if nn[0] > 0:
        return vn[0] == nn[0]
    if nn[1] > 0:
        return vn[0] == 0 and vn[1] == nn[1]
    return vn[:3] == tuple(nn)
