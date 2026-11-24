"""Port-interval arithmetic. Intervals are inclusive ``(lo, hi)``, always merged and sorted."""
from __future__ import annotations

from typing import Any, Iterable

Interval = tuple[int, int]
Intervals = tuple[Interval, ...]

FULL: Intervals = ((1, 65535),)
MAX_SPEC_LEN = 512


def merge(items: Iterable[Interval]) -> Intervals:
    out: list[list[int]] = []
    for lo, hi in sorted(items):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return tuple((a, b) for a, b in out)


def parse_ports(spec: Any) -> Intervals:
    """Accept ``80``, ``"80,443,8000-8100"`` or a list of those. Raises ``ValueError``."""
    if isinstance(spec, bool):
        raise ValueError("ports must be an integer, a string or a list")
    if isinstance(spec, int):
        parts: list[Any] = [spec]
    elif isinstance(spec, str):
        if len(spec) > MAX_SPEC_LEN:
            raise ValueError("port spec too long")
        parts = [p.strip() for p in spec.split(",") if p.strip()]
    elif isinstance(spec, (list, tuple)):
        parts = list(spec)
    else:
        raise ValueError("ports must be an integer, a string or a list")
    if not parts:
        raise ValueError("empty port spec")
    items: list[Interval] = []
    for p in parts:
        if isinstance(p, bool):
            raise ValueError("ports must be integers or ranges")
        if isinstance(p, int):
            lo = hi = p
        elif isinstance(p, str):
            a, sep, b = p.partition("-")
            try:
                lo = int(a)
                hi = int(b) if sep else lo
            except ValueError as exc:
                raise ValueError(f"bad port or range: {p!r}") from exc
        else:
            raise ValueError("ports must be integers or ranges")
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"port out of range 1-65535: {p!r}")
        items.append((lo, hi))
    return merge(items)


def format_ports(iv: Intervals) -> str:
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in iv)


def subtract(a: Intervals, b: Intervals) -> Intervals:
    """Ports in ``a`` that are not in ``b``."""
    out: list[Interval] = []
    for lo, hi in a:
        cur = lo
        for blo, bhi in b:
            if bhi < cur or blo > hi:
                continue
            if blo > cur:
                out.append((cur, blo - 1))
            cur = max(cur, bhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return merge(out)


def intersect(a: Intervals, b: Intervals) -> Intervals:
    out: list[Interval] = []
    for alo, ahi in a:
        for blo, bhi in b:
            lo, hi = max(alo, blo), min(ahi, bhi)
            if lo <= hi:
                out.append((lo, hi))
    return merge(out)


def count(iv: Intervals) -> int:
    return sum(b - a + 1 for a, b in iv)
