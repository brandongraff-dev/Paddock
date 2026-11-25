"""Host facts carried on a graph node: ``nodes[].facts.<collector> = {status, tier, observed_at, ...}``.

One fact is one collector's snapshot of one host. The library never verifies a signature (the
server did that at ingest); it only trusts ``signed: true`` and passes ``key_id``, ``seq`` and
``evidence_ref`` through into witnesses so a verifier can find the evidence again.

Strictness: every known key is type-checked and anything malformed is a ``FactError`` (the graph
loader turns it into a ``GraphError``); unknown keys are ignored, except one that looks like a
misspelt conflict marker (``conflicts``), which would otherwise read as "no conflict". Semantic gaps
are *not* errors:
a missing ``conf`` is read as ``approximate`` and a missing ``partial`` as ``True`` so that a
builder that forgot them yields UNKNOWN rather than a pass.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional

from .tier import Tier

MAX_COLLECTORS_PER_NODE = 16
MAX_ROWS = 5000                     # any list inside a fact's data
MAX_FACT_ELEMENTS = 100_000         # values (leaves and containers) inside one fact's data
MAX_TOTAL_ELEMENTS = 4_000_000      # across the whole graph document
MAX_DATA_DEPTH = 12
MAX_STRING = 2048
MAX_REF = 256
COLLECTOR_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
STATUSES = ("ok", "error", "unavailable")
CONFS = ("exact", "approximate")


class FactError(ValueError):
    pass


@dataclass(frozen=True, eq=False)
class Fact:
    collector: str
    status: str                      # ok | error | unavailable
    tier: Tier
    observed_at: dt.datetime
    signed: bool
    source: str
    key_id: str
    seq: int
    evidence_ref: str
    conflict: bool                   # True: an independent source disagrees (never usable)
    conf: str                        # exact | approximate (only meaningful for status ok)
    partial: bool                    # the section is known to be incomplete
    reason: str                      # why status is not ok (collector vocabulary), else ""
    data: Mapping[str, Any]          # deep-frozen: dicts are read-only proxies, lists are tuples


@dataclass(frozen=True, eq=False)
class HostFacts:
    facts: Mapping[str, Fact]

    def get(self, collector: str) -> Optional[Fact]:
        return self.facts.get(collector)

    def __len__(self) -> int:
        return len(self.facts)


EMPTY = HostFacts(MappingProxyType({}))


def _ts(value: Any, what: str) -> dt.datetime:
    if not isinstance(value, str):
        raise FactError(f"{what}: timestamp must be an ISO-8601 string")
    try:
        t = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise FactError(f"{what}: bad timestamp {value!r}") from exc
    if t.tzinfo is None:
        raise FactError(f"{what}: timestamp needs a timezone (use Z or +00:00)")
    try:
        return t.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise FactError(f"{what}: timestamp out of range {value!r}") from exc


def _str(raw: Mapping[str, Any], key: str, what: str, limit: int = MAX_REF) -> str:
    v = raw.get(key, "")
    if v is None:
        return ""
    if not isinstance(v, str):
        raise FactError(f"{what}: {key!r} must be a string")
    if len(v) > limit:
        raise FactError(f"{what}: {key!r} longer than {limit} characters")
    return v


def _freeze(value: Any, budget: list[int], depth: int, what: str) -> Any:
    """Deep copy into an immutable structure, enforcing the caps. ``budget`` is a one-element list
    holding the elements still allowed in this document."""
    budget[0] -= 1
    if budget[0] < 0:
        raise FactError(f"{what}: too many values in fact data")
    if depth > MAX_DATA_DEPTH:
        raise FactError(f"{what}: fact data nested deeper than {MAX_DATA_DEPTH} levels")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise FactError(f"{what}: floats are not allowed in fact data")
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise FactError(f"{what}: string longer than {MAX_STRING} characters in fact data")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ROWS:
            raise FactError(f"{what}: more than {MAX_ROWS} rows in a fact list")
        return tuple(_freeze(v, budget, depth + 1, what) for v in value)
    if isinstance(value, dict):
        if len(value) > MAX_ROWS:
            raise FactError(f"{what}: more than {MAX_ROWS} keys in a fact object")
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise FactError(f"{what}: fact object keys must be strings")
            out[k] = _freeze(v, budget, depth + 1, what)
        return MappingProxyType(out)
    raise FactError(f"{what}: unsupported value type {type(value).__name__} in fact data")


def _freeze_data(data: dict, budget: list[int], what: str) -> Mapping[str, Any]:
    local = [MAX_FACT_ELEMENTS]
    frozen = _freeze(data, local, 0, what)
    budget[0] -= MAX_FACT_ELEMENTS - local[0]
    if budget[0] < 0:
        raise FactError(f"{what}: graph document carries too much fact data")
    return frozen


def _conflict(raw: Mapping[str, Any], what: str) -> bool:
    """Absent / false / null / [] = no conflict; true / a non-empty object / a non-empty list =
    conflict. Anything else (a string, a number, ``{}``) is refused: a conflict marker that cannot
    be read must not be read as "no conflict"."""
    if "conflict" not in raw:
        return False
    v = raw["conflict"]
    if v is None or v is False:
        return False
    if v is True:
        return True
    if isinstance(v, dict):
        if not v:
            raise FactError(f"{what}: 'conflict' must be a boolean, a non-empty object or a list")
        return True
    if isinstance(v, list):
        if not all(isinstance(x, dict) and x for x in v):
            raise FactError(f"{what}: 'conflict' list entries must be non-empty objects")
        return bool(v)
    raise FactError(f"{what}: 'conflict' must be a boolean, a non-empty object or a list")


def parse_fact(collector: str, raw: Any, nid: str, budget: list[int]) -> Fact:
    what = f"node {nid!r} facts.{collector}"
    if not isinstance(raw, dict):
        raise FactError(f"{what}: a fact must be an object")
    for k in raw:
        # Unknown keys are tolerated (a newer builder may add informational ones) except a
        # misspelled conflict marker, which would silently read as "no conflict".
        if isinstance(k, str) and "conflict" in k.lower() and k != "conflict":
            raise FactError(f"{what}: unknown key {k!r} (the conflict marker is 'conflict')")
    status = raw.get("status")
    if not isinstance(status, str) or status not in STATUSES:
        raise FactError(f"{what}: status must be one of {STATUSES}")
    tier_raw = raw.get("tier")
    if not isinstance(tier_raw, str):
        raise FactError(f"{what}: bad tier {tier_raw!r}")
    try:
        tier = Tier(tier_raw)
    except ValueError as exc:
        raise FactError(f"{what}: bad tier {tier_raw!r}") from exc
    signed = raw.get("signed")
    if not isinstance(signed, bool):
        raise FactError(f"{what}: 'signed' must be a boolean")
    seq = raw.get("seq", 0)
    if seq is None:
        seq = 0
    if type(seq) is not int or seq < 0 or seq > 2**63 - 1:
        raise FactError(f"{what}: 'seq' must be a non-negative integer")
    conf = raw.get("conf", "approximate")
    if conf is None:
        conf = "approximate"
    if not isinstance(conf, str) or conf not in CONFS:
        raise FactError(f"{what}: 'conf' must be exact or approximate")
    partial = raw.get("partial", True)
    if partial is None:
        partial = True
    if not isinstance(partial, bool):
        raise FactError(f"{what}: 'partial' must be a boolean")
    data = raw.get("data", {})
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise FactError(f"{what}: 'data' must be an object")
    return Fact(
        collector=collector, status=status, tier=tier,
        observed_at=_ts(raw.get("observed_at"), f"{what} observed_at"),
        signed=signed, source=_str(raw, "source", what), key_id=_str(raw, "key_id", what),
        seq=seq, evidence_ref=_str(raw, "evidence_ref", what), conflict=_conflict(raw, what),
        conf=conf, partial=partial, reason=_str(raw, "reason", what, 64),
        data=_freeze_data(data, budget, what))


def parse_facts(raw: Any, nid: str, budget: list[int]) -> HostFacts:
    """``nodes[].facts``: ``{collector: fact}``."""
    if not isinstance(raw, dict):
        raise FactError(f"node {nid!r}: 'facts' must be an object keyed by collector")
    if len(raw) > MAX_COLLECTORS_PER_NODE:
        raise FactError(f"node {nid!r}: too many collectors (max {MAX_COLLECTORS_PER_NODE})")
    out: dict[str, Fact] = {}
    for name in sorted(raw):
        if not isinstance(name, str) or not COLLECTOR_RE.fullmatch(name):
            raise FactError(f"node {nid!r}: bad collector name {name!r}")
        out[name] = parse_fact(name, raw[name], nid, budget)
    return HostFacts(MappingProxyType(out))


def new_budget() -> list[int]:
    return [MAX_TOTAL_ELEMENTS]
