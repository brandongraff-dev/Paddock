"""Evaluating one host-config assertion on one host: Kleene three-valued, with provenance.

Pure functions over the canonical tree (``hostexpr``) and a node's ``HostFacts``. Nothing here
decides a verdict for the estate (``evaluate._eval_hostconfig`` aggregates the hosts); it answers,
for one host, *true / false / unknown*, *which facts the answer rests on*, *which clauses are to
blame* when it is false, and *why* when it is unknown.

Soundness rules, each pinned by a test:

* A leaf is unknown (``None``) unless its collector fact is usable and the accessor produced a
  value (``hostfields.resolve``). An unusable fact is never false.
* ``all`` / ``any`` / ``not`` are Kleene strong, through ``kleene`` only.
* A repeated leaf is unknown wherever it is unknown (``A or not A`` is unknown, never true): the
  logic is conservative, not clever.
* The facts a TRUE answer rests on are returned (``Ev.rel``) so a HOLDS can state its weakest tier
  and its earliest expiry.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from . import hostexpr as X
from . import hostfields as HF
from . import kleene as K
from .hostfacts import Fact, HostFacts
from .kleene import Tri
from .tier import Tier

Rel = tuple[tuple[Fact, Tier], ...]      # the (fact, effective tier) pairs an answer rests on


@dataclass(frozen=True)
class LeafEval:
    leaf: X.Leaf
    spec: HF.FieldSpec
    res: HF.Resolved


@dataclass(frozen=True)
class Ev:
    """The evaluation of one tree node on one host."""

    node: X.Node
    tv: Tri
    kids: tuple["Ev", ...] = ()
    leaf: Optional[LeafEval] = None
    rel: Rel = ()


def _cidrs(values: Iterable[str]) -> list[Any]:
    return [ipaddress.ip_network(v, strict=True) for v in values]


def _cmp(op: str, a: Any, b: Any) -> bool:
    if op == "==":
        return bool(a == b)
    if op == "!=":
        return bool(a != b)
    if op == "<":
        return bool(a < b)
    if op == "<=":
        return bool(a <= b)
    if op == ">":
        return bool(a > b)
    if op == ">=":
        return bool(a >= b)
    raise ValueError(op)


def compare(leaf: X.Leaf, spec: HF.FieldSpec, value: Any) -> bool:
    """Does the observed ``value`` satisfy the leaf? ``value`` is known and of the field's type."""
    if leaf.count:
        return _cmp(leaf.op, len(value), leaf.value)
    typ = spec.type
    if typ == "str":
        v = value.lower()
        if leaf.op == "in":
            return v in leaf.value
        return _cmp(leaf.op, v, leaf.value)
    if typ == "int":
        if leaf.op == "in":
            return value in leaf.value
        return _cmp(leaf.op, value, leaf.value)
    if typ == "bool":
        return _cmp(leaf.op, value, leaf.value)
    if typ == "set<str>":
        lit = frozenset(leaf.value)
        if leaf.op == "subset_of":
            return value <= lit
        return _cmp(leaf.op, frozenset(value), lit)
    # set<cidr>
    nets = _cidrs(leaf.value)
    if leaf.op == "subset_of":
        return all(any(n.version == m.version and n.subnet_of(m) for m in nets) for n in value)
    return _cmp(leaf.op, frozenset(value), frozenset(nets))


def _score(rel: Rel) -> tuple:
    """How good a reason a branch is to rely on: later expiry first, then stronger tier."""
    if not rel:
        return (dt.datetime.max.replace(tzinfo=dt.timezone.utc), 99)
    return (min(f.observed_at for f, _ in rel), min(t.rank for _, t in rel))


def _best(kids: list[Ev]) -> Rel:
    best = max(range(len(kids)), key=lambda i: (_score(kids[i].rel), -i))
    return kids[best].rel


def union_rel(rels: Iterable[Rel]) -> Rel:
    seen: dict[int, tuple[Fact, Tier]] = {}
    for rel in rels:
        for f, t in rel:
            seen.setdefault(id(f), (f, t))
    return tuple(seen.values())


class HostEvaluator:
    """Evaluates the canonical tree on one host. Leaf resolution is cached per (field, params)."""

    def __init__(self, host: Optional[HostFacts], now: dt.datetime, min_tier: Tier,
                 max_age: dt.timedelta) -> None:
        self.host, self.now, self.min_tier, self.max_age = host, now, min_tier, max_age
        self._cache: dict[tuple[str, tuple], HF.Resolved] = {}

    def resolve(self, leaf: X.Leaf) -> HF.Resolved:
        key = (leaf.field, leaf.params)
        got = self._cache.get(key)
        if got is None:
            got = HF.resolve(HF.REGISTRY[leaf.field], leaf.params, self.host, self.now,
                             self.min_tier, self.max_age)
            self._cache[key] = got
        return got

    def evaluate(self, node: X.Node) -> Ev:
        if isinstance(node, X.Leaf):
            spec = HF.REGISTRY[node.field]
            res = self.resolve(node)
            if not res.known:
                return Ev(node, None, leaf=LeafEval(node, spec, res))
            try:
                tv: Tri = compare(node, spec, res.value)
            except Exception:                    # noqa: BLE001 - a comparison that cannot run is unknown
                return Ev(node, None, leaf=LeafEval(node, spec, HF.Resolved(
                    False, reason="no_value", fact=res.fact, tier=res.tier)))
            assert res.fact is not None and res.tier is not None
            rel: Rel = ((res.fact, res.tier),) + tuple(
                (f, f.tier if f.tier.rank <= HF.CFG.rank else HF.CFG) for f in res.also)
            return Ev(node, tv, leaf=LeafEval(node, spec, res), rel=rel)
        if isinstance(node, X.Not):
            c = self.evaluate(node.child)
            return Ev(node, K.k_not(c.tv), (c,), rel=c.rel if c.tv is not None else ())
        kids = [self.evaluate(c) for c in node.children]
        tvs = [k.tv for k in kids]
        tv = K.k_all(tvs) if node.kind == "all" else K.k_any(tvs)
        if tv is None:
            return Ev(node, None, tuple(kids))
        # all+True, any+False: every child took part. all+False, any+True: one child is enough, so
        # rely on the best one (latest expiry, then strongest tier), deterministically.
        every = (node.kind == "all") == (tv is True)
        if every:
            rel = union_rel(k.rel for k in kids)
        else:
            rel = _best([k for k in kids if k.tv is tv])
        return Ev(node, tv, tuple(kids), rel=rel)


# --------------------------------------------------------------------------------------------
# provenance

def unknown_leaves(ev: Ev) -> list[LeafEval]:
    """Every leaf under an unknown node that is itself unknown (what to fix to decide the host)."""
    if ev.tv is not None:
        return []
    if ev.leaf is not None:
        return [ev.leaf]
    out: list[LeafEval] = []
    for k in ev.kids:
        out.extend(unknown_leaves(k))
    return out


def blame(ev: Ev, want: bool, path: tuple[int, ...] = (0,), negations: int = 0) \
        -> list[tuple[tuple[int, ...], int, LeafEval]]:
    """The leaves that make ``ev`` evaluate to ``want`` (True or False), as ``(clause path,
    negations passed through, leaf)``. For a false ``all`` that is every false child; for a false
    ``any`` every child; a true ``any`` is explained by its first true child."""
    if ev.leaf is not None:
        return [(path, negations, ev.leaf)]
    node = ev.node
    if isinstance(node, X.Not):
        return blame(ev.kids[0], not want, path + (0,), negations + 1)
    out: list[tuple[tuple[int, ...], int, LeafEval]] = []
    first_only = isinstance(node, X.Group) and node.kind == "any" and want
    for i, k in enumerate(ev.kids):
        if k.tv is want:
            out.extend(blame(k, want, path + (i,), negations))
            if first_only:
                break
    return out


def clause_id(path: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in path)


def predicate_text(leaf: X.Leaf, negations: int) -> str:
    t = X.leaf_text(leaf)
    for _ in range(negations):
        t = f"not({t})"
    return t


def clean_text(s: str) -> str:
    """Printable ASCII only: a value a host reported ends up in witnesses, findings and terminals."""
    return "".join(c if " " <= c <= "~" else "?" for c in s)


def fmt_observed(value: Any, limit: int = 200) -> str:
    if isinstance(value, bool):
        s = "true" if value else "false"
    elif isinstance(value, frozenset):
        s = ",".join(sorted(str(v) for v in value))
    else:
        s = str(value)
    s = clean_text(s)
    return s if len(s) <= limit else s[:limit - 3] + "..."


def fmt_expected(leaf: X.Leaf) -> str:
    v = leaf.value
    if isinstance(v, bool):
        s = "true" if v else "false"
    elif isinstance(v, tuple):
        s = ",".join(str(x) for x in v)
    else:
        s = str(v)
    return s if len(s) <= 200 else s[:197] + "..."


def op_text(leaf: X.Leaf) -> str:
    return ("count" + leaf.op) if leaf.count else leaf.op


def observed_value(le: LeafEval) -> Any:
    """What the host's fact said for this leaf (the count, for a ``count()`` leaf)."""
    v = le.res.value
    return len(v) if le.leaf.count else v
