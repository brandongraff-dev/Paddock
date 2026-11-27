"""The N-day decision over a ``kev`` fact's ``data`` (contract 1.6.7), computed at evaluation time.

``evaluate_leaf(data, now, n_days)`` is ``host.kev.exploited_unpatched(N)``: ``True`` when a provable
violation exists, ``False`` only when nothing is overdue, nothing is undecided and the list is complete,
else ``None`` (unknown). It never reads more into the data than it proves: malformed or inconsistent
data, a stale snapshot window, a truncated list or any unknown item can only widen to ``None``, never
narrow to ``False``. A violation beats unknown items (violations win).

``data`` may be the plain dict from ``MatchResult.to_data()`` or the deep-frozen form a fact carries
(``Mapping`` proxies and tuples).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import re
from collections.abc import Mapping
from typing import Any, Optional

UTC = dt.timezone.utc
MAX_N = 3650
UNDECIDED = "kev_undecided"
STALE = "advisory_stale"
_ISO = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_BASES = ("advisory", "first_seen")


@dataclasses.dataclass(frozen=True)
class LeafResult:
    value: Optional[bool]                       # True | False | None (unknown)
    reason: str = ""                            # why unknown ("" when known)
    until: Optional[dt.datetime] = None         # a False flips by the clock alone no earlier than this
    definite: int = 0                           # overdue items
    pending: int = 0                            # decided non-violations that expire with the clock
    undecided: int = 0                          # unknown items + clock items that cannot be decided
    more: int = 0                               # overdue items besides ``worst``
    worst: Optional[dict] = None                # the most overdue item (earliest clock start)
    open_count: Optional[int] = None            # ``host.kev.open_count``
    unfixed_count: Optional[int] = None         # ``host.kev.unfixed_count`` (no published fix; informational)
    undecided_count: Optional[int] = None       # ``host.kev.undecided_count``


class _Bad(Exception):
    pass


def _unknown(reason: str = UNDECIDED) -> LeafResult:
    return LeafResult(value=None, reason=reason)


def _int(v: Any, lo: int = 0) -> int:
    if type(v) is not int or v < lo:
        raise _Bad
    return v


def _str(v: Any) -> str:
    if type(v) is not str:
        raise _Bad
    return v


def _t(v: Any) -> dt.datetime:
    if type(v) is not str or not _ISO.match(v):
        raise _Bad
    try:
        return dt.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise _Bad from None


def _seq(v: Any) -> Any:
    if not isinstance(v, (list, tuple)):
        raise _Bad
    return v


def _map(v: Any) -> Any:
    if not isinstance(v, Mapping):
        raise _Bad
    return v


def _need(m: Mapping, key: str) -> Any:
    if key not in m:
        raise _Bad
    return m[key]


def _parse(data: Any) -> dict:
    d = _map(data)
    if type(_need(d, "v")) is not int or d["v"] != 1:
        raise _Bad
    valid_until = _t(_need(_map(_need(d, "snap")), "valid_until"))
    counts = _map(_need(d, "counts"))
    n_open, n_nofix, n_undec = (_int(_need(counts, k)) for k in ("open_fix", "no_fix", "undecided"))
    _int(_need(counts, "relevant"))
    trunc = _need(d, "open_truncated")
    if type(trunc) is not bool:
        raise _Bad
    items = []
    for it in _seq(_need(d, "open")):
        it = _map(it)
        basis = _str(_need(it, "basis"))
        if basis not in _BASES:
            raise _Bad
        due = it.get("due")
        if due is not None and (type(due) is not str or not _DAY.match(due)):
            raise _Bad
        items.append({"cve": _str(_need(it, "cve")), "pkg": _str(_need(it, "pkg")), "inst": _str(_need(it, "inst")),
                      "fixed": _str(_need(it, "fixed")), "adv": _str(_need(it, "adv")), "basis": basis,
                      "fix_at_s": _str(_need(it, "fix_at")), "kev_at_s": _str(_need(it, "kev_at")),
                      "fix_at": _t(it["fix_at"]), "kev_at": _t(it["kev_at"])})
    if n_open < len(items) or (not trunc and n_open != len(items)):
        raise _Bad
    unknown = _seq(_need(d, "unknown"))
    total = _int(_need(d, "unknown_total"))
    for u in unknown:
        u = _map(u)
        _str(_need(u, "cve"))
        _str(_need(u, "pkg"))
        _str(_need(u, "reason"))
    reasons = _map(_need(d, "unknown_reasons"))
    rs = {}
    for k, v in reasons.items():
        rs[_str(k)] = _int(v)
    if total < len(unknown) or n_undec != total or sum(rs.values()) != total:
        raise _Bad
    no_fix_total = _int(_need(d, "no_fix_total"))
    if no_fix_total != n_nofix:
        raise _Bad
    return {"valid_until": valid_until, "items": items, "truncated": trunc, "unknown_total": total, "reasons": rs,
            "no_fix_total": no_fix_total, "n_open": n_open}


def evaluate_leaf(data: Any, now: dt.datetime, n_days: int) -> LeafResult:
    """``host.kev.exploited_unpatched(n_days)`` over one ``kev`` fact ``data`` at ``now``."""
    if type(n_days) is not int or not 0 <= n_days <= MAX_N:
        raise ValueError("n_days must be an int in 0..%d" % MAX_N)
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(UTC)
    try:
        p = _parse(data)
    except _Bad:
        return _unknown()
    window = dt.timedelta(days=n_days)
    overdue, pending, clock_undecided = [], [], 0
    for it in p["items"]:
        clock = max(it["fix_at"], it["kev_at"])
        it["clock"] = clock
        if now - clock > window:                       # strictly greater, second precision, no floor
            overdue.append(it)
        elif it["basis"] == "advisory":
            pending.append(clock + window)
        else:
            clock_undecided += 1
    unknown_total = p["unknown_total"]
    undecided = unknown_total + clock_undecided
    trunc = p["truncated"]
    open_count = None if (unknown_total or trunc) else p["n_open"]
    common = dict(definite=len(overdue), pending=len(pending), undecided=undecided, open_count=open_count,
                  unfixed_count=p["no_fix_total"], undecided_count=unknown_total)
    if overdue:
        overdue.sort(key=lambda i: (i["clock"], i["cve"], i["pkg"]))
        worst = {k: overdue[0][k] for k in ("cve", "pkg", "inst", "fixed", "adv", "basis")}
        worst["fix_at"], worst["kev_at"] = overdue[0]["fix_at_s"], overdue[0]["kev_at_s"]
        return LeafResult(value=True, more=len(overdue) - 1, worst=worst, **common)
    if undecided == 0 and not trunc:
        if now > p["valid_until"]:
            return LeafResult(value=None, reason=STALE, **common)       # never False on a stale evidence window
        until = min([p["valid_until"]] + pending)
        return LeafResult(value=False, until=until, **common)
    shared = [r for r, n in p["reasons"].items() if n]
    reason = shared[0] if (len(shared) == 1 and clock_undecided == 0 and unknown_total == sum(p["reasons"].values())) else UNDECIDED
    return LeafResult(value=None, reason=reason, **common)


_SAFE = re.compile(r"[^A-Za-z0-9 .+~:<>_,=/-]")


def _clean(s: str, n: int) -> str:
    return _SAFE.sub("?", s)[:n]


def describe_worst(result: LeafResult) -> str:
    """``CVE-2023-4911 libc6 2.36-9+deb12u2<2.36-9+deb12u3 fix 2023-10-03 kev 2023-11-21 +2 more`` (at most 120
    characters, restricted charset); empty when there is no overdue item."""
    w = result.worst
    if not w:
        return ""
    s = "%s %s %s<%s fix %s kev %s" % (_clean(w["cve"], 20), _clean(w["pkg"], 30), _clean(w["inst"], 24),
                                      _clean(w["fixed"], 24), _clean(w["fix_at"], 10), _clean(w["kev_at"], 10))
    if result.more:
        s += " +%d more" % result.more
    return s[:120]
