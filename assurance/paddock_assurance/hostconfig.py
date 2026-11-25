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
  and its earliest expiry, and the limits of that evidence (``Ev.notes``) so it can say so.
* A key a Match block changes has no single value. A leaf over such a key is decided per variant
  (the base config and every probed user/address): True only if every variant satisfies it, False as
  soon as one definitely does not (a weakened variant is a violation), else unknown. Only outside
  ``not``: ``not(x == "yes")`` over a key that varies is not read as "no variant has yes".
* A False that rests on "some variant fails this leaf" is *witnessed* (``Ev.wit``): it is only a
  False of the whole expression in THAT variant. ``any`` is False only if every child is False in one
  and the same variant, so an ``any`` with two witnessed False children is unknown (``A`` fails for
  one user and ``B`` for another proves nothing); one witnessed child beside children that are False
  for every variant (a leaf that does not vary) is False. ``all`` is False as soon as one child is,
  witnessed or not. A True never needs this: every variant satisfied the leaf.
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
    # per-variant leaves only: the value of the first variant that decided it False (what to show)
    shown: Any = None
    has_shown: bool = False


@dataclass(frozen=True)
class Ev:
    """The evaluation of one tree node on one host."""

    node: X.Node
    tv: Tri
    kids: tuple["Ev", ...] = ()
    leaf: Optional[LeafEval] = None
    rel: Rel = ()
    notes: tuple[str, ...] = ()        # limits of the evidence the TRUE/FALSE answer rests on
    wit: bool = False                  # a False that holds in some variant, not in every one


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


def _best(kids: list[Ev]) -> Ev:
    best = max(range(len(kids)), key=lambda i: (_score(kids[i].rel), -i))
    return kids[best]


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

    def _per_variant(self, node: X.Leaf, spec: HF.FieldSpec, res: HF.Resolved) -> Ev:
        """A leaf over a key Match blocks change: every variant must satisfy it. One that does not
        (definitely) makes it False; one that cannot be read leaves it unknown unless another already
        failed; all satisfied is True."""
        tvs: list[Tri] = []
        shown: Any = None
        has_shown = False
        for v in res.variants:
            if v is None:
                tvs.append(None)
                continue
            try:
                t: Tri = compare(node, spec, v)
            except Exception:                    # noqa: BLE001 - a comparison that cannot run is unknown
                t = None
            tvs.append(t)
            if t is False and not has_shown:
                shown, has_shown = v, True
        tv = K.k_all(tvs)
        if tv is None or res.fact is None or res.tier is None:
            return Ev(node, None, leaf=LeafEval(node, spec, res))
        return Ev(node, tv, leaf=LeafEval(node, spec, res, shown, has_shown),
                  rel=((res.fact, res.tier),), wit=tv is False)

    def evaluate(self, node: X.Node, under_not: bool = False) -> Ev:
        if isinstance(node, X.Leaf):
            spec = HF.REGISTRY[node.field]
            res = self.resolve(node)
            if not res.known:
                if res.variants and not under_not:
                    return self._per_variant(node, spec, res)
                return Ev(node, None, leaf=LeafEval(node, spec, res))
            try:
                tv: Tri = compare(node, spec, res.value)
            except Exception:                    # noqa: BLE001 - a comparison that cannot run is unknown
                return Ev(node, None, leaf=LeafEval(node, spec, HF.Resolved(
                    False, reason="no_value", fact=res.fact, tier=res.tier)))
            assert res.fact is not None and res.tier is not None
            rel: Rel = ((res.fact, res.tier),) + tuple(
                (f, f.tier if f.tier.rank <= HF.CFG.rank else HF.CFG) for f in res.also)
            return Ev(node, tv, leaf=LeafEval(node, spec, res), rel=rel, notes=res.notes)
        if isinstance(node, X.Not):
            c = self.evaluate(node.child, True)
            known = c.tv is not None
            return Ev(node, K.k_not(c.tv), (c,), rel=c.rel if known else (),
                      notes=c.notes if known else ())
        kids = [self.evaluate(c, under_not) for c in node.children]
        tvs = [k.tv for k in kids]
        tv = K.k_all(tvs) if node.kind == "all" else K.k_any(tvs)
        if tv is None:
            return Ev(node, None, tuple(kids))
        wit = False
        if tv is False:
            if node.kind == "all":
                wit = all(k.wit for k in kids if k.tv is False)     # one uniform False is enough
            else:
                n = sum(1 for k in kids if k.wit)
                if n > 1:                    # False in different variants: no variant fails them all
                    return Ev(node, None, tuple(kids))
                wit = n == 1
        # all+True, any+False: every child took part. all+False, any+True: one child is enough, so
        # rely on the best one (latest expiry, then strongest tier), deterministically.
        every = (node.kind == "all") == (tv is True)
        if every:
            rel = union_rel(k.rel for k in kids)
            notes = tuple(sorted({n for k in kids for n in k.notes}))
        else:
            one = _best([k for k in kids if k.tv is tv])
            rel, notes = one.rel, one.notes
        return Ev(node, tv, tuple(kids), rel=rel, notes=notes, wit=wit)


# --------------------------------------------------------------------------------------------
# provenance

def _variant_leaves(ev: Ev) -> list[LeafEval]:
    """Leaves under ``ev`` that were decided by looking at the variants of a key Match blocks change."""
    if ev.leaf is not None:
        return [ev.leaf] if ev.leaf.res.variants else []
    out: list[LeafEval] = []
    for k in ev.kids:
        out.extend(_variant_leaves(k))
    return out


def unknown_leaves(ev: Ev) -> list[LeafEval]:
    """Every leaf under an unknown node that is itself unknown (what to fix to decide the host). An
    ``any`` that is unknown only because two of its children fail in different variants has no
    unknown leaf: its variant-dependent leaves (``match_override``) are what keep it open."""
    if ev.tv is not None:
        return []
    if ev.leaf is not None:
        return [ev.leaf]
    out: list[LeafEval] = []
    for k in ev.kids:
        out.extend(unknown_leaves(k))
    return out or _variant_leaves(ev)


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


#: What a host-controlled value may show in a witness (and so in a finding, a ticket, a terminal).
#: Everything else, markup, spaces, quotes, brackets and non-ASCII included, is shown as ``?``.
SAFE_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@,-")
OBSERVED_LIMIT = 120


def clean_text(s: str) -> str:
    """Restricted alphabet ``[A-Za-z0-9._:/@,-]``, ``?`` for any other character: a value a host
    reported must not carry markup, links or instructions into witnesses, findings and terminals."""
    return "".join(c if c in SAFE_CHARS else "?" for c in s)


def fmt_observed(value: Any, limit: int = OBSERVED_LIMIT) -> str:
    if isinstance(value, bool):
        s = "true" if value else "false"
    elif isinstance(value, frozenset):
        s = ",".join(sorted(str(v) for v in value))
    else:
        s = str(value)
    cut = len(s) > limit
    s = clean_text(s[:limit])           # cut first: a set of thousands of names is never scanned whole
    return s[:limit - 3] + "..." if cut else s


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
    if le.has_shown:
        return le.shown
    v = le.res.value
    return len(v) if le.leaf.count else v
