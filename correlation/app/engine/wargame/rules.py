"""Vendor-neutral rule solver for Wargame (config-only reachability).

This module answers one narrow, defensive question over a boundary's
:class:`~app.engine.wargame.model.RuleSet`: *does the configuration permit
a given flow?* It sends no packets and emits no exploit — it reduces a set
of first-match rules to an allow/deny :class:`Decision`, the way Batfish or
AWS Tiros reason about config (see ``docs/WARGAME.md`` §2.2). The backward
search in :mod:`.reachability` builds on it.

Determinism. Rules are evaluated first-match over a stable sort by
``(order, id)`` — lower ``order`` wins, ties broken by ``id`` — so the same
ruleset and flow always produce the same verdict.

Scope / honesty. A rule marked ``conditional`` depends on runtime state the
config cannot prove (App-ID, FQDN objects, dynamic groups, service mesh,
NetworkPolicy). When such a rule decides a flow, the verdict is labelled
``conditional`` and can never be presented as a proved-closed boundary;
only as "needs a probe or observation to settle". At boundary level a
conditional rule never *contributes* to a closed proof: traffic it may match
is reported closed only if it is closed whether or not the rule matches
(e.g. a conditional deny whose fall-through reaches only denies).

Boundary questions (:func:`boundary_permits`) are answered *exactly*, not by
sampling: the query (every src address × every dst address × every
protocol/port in the port class) is a set of header-space boxes, and the
rules are walked in first-match order subtracting what each one matches
(see that function). The one-sided guarantee the product rests on: the
solver never reports a boundary closed unless the configuration proves it.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

from .model import Action, Decision, PortRange, Proto, Rule, RuleSet


# ---------------------------------------------------------------------------
# Single-flow evaluation
# ---------------------------------------------------------------------------

def evaluate(
    ruleset: RuleSet,
    src_ip: str,
    dst_ip: str,
    proto: Proto,
    port: int,
) -> Decision:
    """First-match evaluation of ``ruleset`` for one concrete flow.

    Rules are considered in ascending ``order`` (lower wins), ties broken by
    ``id`` for a stable, deterministic order. The first rule whose
    :meth:`Rule.matches` is True decides the flow:

    * ``allowed`` = the rule's action is :attr:`Action.ALLOW`
    * ``matched_rule`` = that rule's ``id``
    * ``conditional`` = that rule's ``conditional`` flag

    If no rule matches, the ruleset's ``default_action`` applies and
    ``matched_rule`` is ``None`` (``conditional`` is ``False``).
    """
    for rule in sorted(ruleset.rules, key=lambda r: (r.order, r.id)):
        if rule.matches(src_ip, dst_ip, proto, port):
            return Decision(
                allowed=rule.action == Action.ALLOW,
                matched_rule=rule.id,
                conditional=rule.conditional,
            )
    return Decision(
        allowed=ruleset.default_action == Action.ALLOW,
        matched_rule=None,
        conditional=False,
    )


def permits(
    ruleset: RuleSet,
    src_ip: str,
    dst_ip: str,
    proto: Proto,
    port: int,
) -> bool:
    """Convenience wrapper: just the ``allowed`` bit of :func:`evaluate`."""
    return evaluate(ruleset, src_ip, dst_ip, proto, port).allowed


# ---------------------------------------------------------------------------
# Boundary evaluation (CIDR-to-CIDR, exact header-space decision)
# ---------------------------------------------------------------------------
#
# A *box* is a product of intervals over the flow header:
#
#     (src_version, dst_version, proto_class,
#      src_lo, src_hi, dst_lo, dst_hi, port_lo, port_hi)
#
# Addresses are integers (``int(ipaddress)``); the address family of each
# side is part of the box key, so an IPv4 box never intersects an IPv6 rule
# ("0.0.0.0/0" covers IPv4 only, "::/0" IPv6 only), exactly as
# ``model._ip_in_cidr`` behaves. ``proto_class`` is one of the four concrete
# classes below; ``Proto.ANY`` (in a rule or a query) expands to all four.
#
# Ports. ``PortRange.contains`` compares the port literally for every
# protocol, ICMP included, and ``Rule.matches`` / :func:`evaluate` (and
# ``impossible.flow_crosses``) inherit that. The box algebra keeps the same
# literal semantics on every protocol class so it agrees with
# :func:`evaluate` flow-for-flow. Parsers model ICMP as ``icmp/0-65535``
# (type/code are not ports) and ingest records an ICMP flow at port 0, so
# every real ICMP flow inside a query's port class is covered.

_P_TCP, _P_UDP, _P_ICMP, _P_OTHER = 0, 1, 2, 3
_PROTO_CLASSES: dict[Proto, tuple[int, ...]] = {
    Proto.TCP: (_P_TCP,),
    Proto.UDP: (_P_UDP,),
    Proto.ICMP: (_P_ICMP,),
    # ANY covers tcp, udp, icmp and every other IP protocol (gre, esp, ...),
    # which only an ANY rule can match.
    Proto.ANY: (_P_TCP, _P_UDP, _P_ICMP, _P_OTHER),
}

_V4_ALL: tuple[int, int, int] = (4, 0, (1 << 32) - 1)
_V6_ALL: tuple[int, int, int] = (6, 0, (1 << 128) - 1)
_PORT_ALL: tuple[int, int] = (0, 65535)

#: Upper bound on the number of disjoint boxes kept in the "remaining" set.
#: Pathological rule sets (many interleaved partial overlaps) can fragment
#: the space; past this cap the walk stops and returns the SOUND fallback
#: (possibly open, conditional), never "closed".
MAX_BOXES = 50_000
#: Upper bound on box/rule-box intersection tests for one boundary question,
#: with the same sound fallback. Keeps a single verdict bounded in time.
MAX_WORK = 5_000_000

Box = tuple[int, int, int, int, int, int, int, int, int]
Interval = tuple[int, int, int]  # (ip version, lo, hi)


class _BudgetExceeded(Exception):
    """Internal: the box set grew past :data:`MAX_BOXES` / :data:`MAX_WORK`."""


def _parse_cidr(cidr: object) -> Optional[Interval]:
    """``cidr`` as an inclusive integer interval ``(version, lo, hi)``.

    Accepts exactly what ``model._ip_in_cidr`` accepts: a network (host bits
    ignored, ``strict=False``) or a bare address (a /32 or /128). Returns
    ``None`` for anything that does not parse.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)  # type: ignore[arg-type]
        return (net.version, int(net.network_address), int(net.broadcast_address))
    except (ValueError, TypeError):
        pass
    try:
        addr = ipaddress.ip_address(cidr)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None
    return (addr.version, int(addr), int(addr))


def _merge(intervals: Iterable[Interval]) -> list[Interval]:
    """Sort and coalesce overlapping/adjacent intervals per version, so the
    result is disjoint (and the boxes built from it are too)."""
    out: list[Interval] = []
    for v, lo, hi in sorted(intervals):
        if out and out[-1][0] == v and lo <= out[-1][2] + 1:
            if hi > out[-1][2]:
                out[-1] = (v, out[-1][1], hi)
        else:
            out.append((v, lo, hi))
    return out


def _addr_side(cidrs: Iterable[object]) -> tuple[list[Interval], bool]:
    """Parse one side's CIDRs → (merged intervals, all_parsed)."""
    parsed: list[Interval] = []
    ok = True
    for c in cidrs:
        iv = _parse_cidr(c)
        if iv is None:
            ok = False
        else:
            parsed.append(iv)
    return _merge(parsed), ok


def _port_boxes(ranges: Iterable[PortRange]) -> list[tuple[int, int, int]]:
    """Port ranges → merged, disjoint ``(proto_class, lo, hi)`` triples."""
    triples = [
        (p, pr.low, pr.high)
        for pr in ranges
        for p in _PROTO_CLASSES.get(pr.proto, _PROTO_CLASSES[Proto.ANY])
    ]
    # Same coalescing as addresses, with the proto class in the version slot.
    return _merge(triples)


def _product(
    srcs: list[Interval], dsts: list[Interval], ports: list[tuple[int, int, int]]
) -> list[Box]:
    return [
        (sv, dv, p, slo, shi, dlo, dhi, plo, phi)
        for sv, slo, shi in srcs
        for dv, dlo, dhi in dsts
        for p, plo, phi in ports
    ]


def _index(boxes: list[Box]) -> dict[tuple[int, int, int], list[Box]]:
    idx: dict[tuple[int, int, int], list[Box]] = {}
    for b in boxes:
        idx.setdefault(b[:3], []).append(b)
    return idx


def _compile_rule(
    rule: Rule,
) -> tuple[dict[tuple[int, int, int], list[Box]], dict[tuple[int, int, int], list[Box]]]:
    """A rule's match space as (certain boxes, uncertain boxes), keyed by
    ``(src_version, dst_version, proto_class)``.

    * ``certain``: the rule definitely matches every flow in these boxes.
    * ``uncertain``: the rule *may* match. Everything for a ``conditional``
      rule. An unparsable CIDR on either side is widened to "any" (IPv4 and
      IPv6) and marks that part uncertain, matching the parsers' honesty
      rule (``parsers/base.py``: unknown → any + conditional). Under
      :func:`evaluate` such a CIDR simply never matches, which for an ALLOW
      would silently drop a possibly-open path.
    """
    src, src_ok = _addr_side(rule.src_cidrs)
    dst, dst_ok = _addr_side(rule.dst_cidrs)
    ports = _port_boxes(rule.ports)
    certain: list[Box] = [] if rule.conditional else _product(src, dst, ports)
    uncertain: list[Box] = []
    if rule.conditional or not (src_ok and dst_ok):
        src_u = src if src_ok else [_V4_ALL, _V6_ALL]
        dst_u = dst if dst_ok else [_V4_ALL, _V6_ALL]
        uncertain = _product(src_u, dst_u, ports)
    return _index(certain), _index(uncertain)


def _subtract(a: Box, b: Box) -> list[Box]:
    """``a`` minus ``b`` as ≤ 6 disjoint boxes. Requires ``a`` and ``b`` to
    intersect (same key, overlapping on every interval)."""
    sv, dv, p, slo, shi, dlo, dhi, plo, phi = a
    _, _, _, bslo, bshi, bdlo, bdhi, bplo, bphi = b
    out: list[Box] = []
    if slo < bslo:
        out.append((sv, dv, p, slo, bslo - 1, dlo, dhi, plo, phi))
    if shi > bshi:
        out.append((sv, dv, p, bshi + 1, shi, dlo, dhi, plo, phi))
    s1, s2 = max(slo, bslo), min(shi, bshi)
    if dlo < bdlo:
        out.append((sv, dv, p, s1, s2, dlo, bdlo - 1, plo, phi))
    if dhi > bdhi:
        out.append((sv, dv, p, s1, s2, bdhi + 1, dhi, plo, phi))
    d1, d2 = max(dlo, bdlo), min(dhi, bdhi)
    if plo < bplo:
        out.append((sv, dv, p, s1, s2, d1, d2, plo, bplo - 1))
    if phi > bphi:
        out.append((sv, dv, p, s1, s2, d1, d2, bphi + 1, phi))
    return out


def _overlaps(a: Box, b: Box) -> bool:
    return (
        a[3] <= b[4] and b[3] <= a[4]
        and a[5] <= b[6] and b[5] <= a[6]
        and a[7] <= b[8] and b[7] <= a[8]
    )


class _Walk:
    """Mutable state of one exact boundary walk (budget accounting)."""

    def __init__(self) -> None:
        self.work = 0

    def split(
        self, box: Box, rule_boxes: list[Box]
    ) -> tuple[list[Box], list[Box]]:
        """Split ``box`` into (matched by any of ``rule_boxes``, unmatched),
        both as disjoint boxes."""
        matched: list[Box] = []
        rest = [box]
        for rb in rule_boxes:
            nxt: list[Box] = []
            for piece in rest:
                self.work += 1
                if _overlaps(piece, rb):
                    matched.append((
                        piece[0], piece[1], piece[2],
                        max(piece[3], rb[3]), min(piece[4], rb[4]),
                        max(piece[5], rb[5]), min(piece[6], rb[6]),
                        max(piece[7], rb[7]), min(piece[8], rb[8]),
                    ))
                    nxt.extend(_subtract(piece, rb))
                else:
                    nxt.append(piece)
            rest = nxt
            if not rest:
                break
        if self.work > MAX_WORK:
            raise _BudgetExceeded
        return matched, rest


#: The sound answer when the solver cannot decide: possibly open, and
#: labelled conditional so it can never back a closed certificate.
_UNKNOWN = Decision(allowed=True, matched_rule=None, conditional=True)


def boundary_permits(
    ruleset: RuleSet,
    src_cidrs: "tuple[str, ...] | list[str]",
    dst_cidrs: "tuple[str, ...] | list[str]",
    port: Optional[PortRange],
) -> Decision:
    """Decide whether *any* flow from any ``src_cidr`` to any ``dst_cidr`` on
    the given port class is permitted by ``ruleset``, **exactly**.

    Query space. The union of header-space boxes ``src_cidrs × dst_cidrs ×
    port class``: every address of every CIDR, and for the port class
    ``port.proto`` (``Proto.ANY`` = tcp, udp, icmp and any other protocol)
    over ``port.low..port.high``; ``port=None`` means all traffic (all four
    protocol classes, all ports). IPv4 and IPv6 are separate dimensions.

    Walk. Rules are taken in first-match order ``(order, id)`` while a set of
    disjoint "remaining" boxes is maintained, each tagged *certain* (it has
    not passed any rule that only *might* have matched it). For each rule,
    the remaining boxes are intersected with the rule's match space and the
    matched part is subtracted (box subtraction yields ≤ 6 pieces):

    * matched by a definite ALLOW: a certain box is **proved open**, and the
      walk returns immediately with that rule; an uncertain box is
      *possibly open*. Either way the matched part is decided.
    * matched by a definite DENY: that part is closed on that path.
    * matched by a *conditional* rule (``rule.conditional``, or an unparsable
      rule CIDR widened to "any"): the match is uncertain. A conditional
      ALLOW makes the part *possibly open*; a conditional DENY only
      *possibly* denies. In both cases the part also falls through to later
      rules, now uncertain. A conditional deny whose fall-through reaches
      only denies (or the default deny) is closed either way.

    What remains after the last rule gets ``ruleset.default_action``.

    Verdict:

    * some certain box reaches an allow → ``Decision(allowed=True,
      conditional=False, matched_rule=<that rule, or None for the default>)``;
    * else some uncertain path reaches an allow → ``allowed=True,
      conditional=True`` (``matched_rule`` = the first allow it reached);
    * else → ``allowed=False, conditional=False``, ``matched_rule`` = the
      first DENY rule that matched part of the query (``None`` if it all
      fell to the default).

    Unknown inputs are never closed. If a side has no CIDRs, or a CIDR that
    does not parse, that part of the query cannot be evaluated, so unless
    the rest is proved open the verdict is ``allowed=True,
    conditional=True``. The same sound fallback is returned if the box set
    outgrows :data:`MAX_BOXES` (or the walk :data:`MAX_WORK`).
    """
    src, src_ok = _addr_side(src_cidrs)
    dst, dst_ok = _addr_side(dst_cidrs)
    # A side with no CIDR at all is as unknown as one that does not parse.
    unknown = not (src_ok and dst_ok and src and dst)

    if port is None:
        ports = _port_boxes((PortRange.any(),))
    else:
        ports = _port_boxes((port,))

    # remaining: (box, certain)
    remaining: list[tuple[Box, bool]] = [(b, True) for b in _product(src, dst, ports)]
    possibly_open_rule: Optional[str] = None
    possibly_open = False
    first_deny: Optional[str] = None
    walk = _Walk()

    if len(remaining) > MAX_BOXES:
        return _UNKNOWN  # sound fallback: too many CIDR/port combinations
    try:
        for rule in sorted(ruleset.rules, key=lambda r: (r.order, r.id)):
            if not remaining:
                break
            certain_idx, uncertain_idx = _compile_rule(rule)
            if not certain_idx and not uncertain_idx:
                continue
            is_allow = rule.action == Action.ALLOW
            nxt: list[tuple[Box, bool]] = []
            for box, sure in remaining:
                key = box[:3]
                matched, rest = walk.split(box, certain_idx.get(key, []))
                if matched:
                    if is_allow:
                        if sure:
                            # Proved: a definite allow on a path no
                            # conditional rule could have diverted.
                            return Decision(
                                allowed=True, matched_rule=rule.id, conditional=False
                            )
                        if not possibly_open:
                            possibly_open, possibly_open_rule = True, rule.id
                    elif first_deny is None:
                        first_deny = rule.id
                    # Definitely matched: decided, does not fall through.
                ukeys = uncertain_idx.get(key)
                if ukeys:
                    for piece in rest:
                        maybe, untouched = walk.split(piece, ukeys)
                        if maybe and is_allow and not possibly_open:
                            possibly_open, possibly_open_rule = True, rule.id
                        # Uncertain match: falls through, no longer certain.
                        nxt.extend((m, False) for m in maybe)
                        nxt.extend((u, sure) for u in untouched)
                else:
                    nxt.extend((r, sure) for r in rest)
            if possibly_open:
                # Uncertain boxes can now only re-derive "possibly open";
                # only a certain box can still change the verdict.
                nxt = [(b, s) for b, s in nxt if s]
            if len(nxt) > MAX_BOXES:
                raise _BudgetExceeded
            remaining = nxt
    except _BudgetExceeded:
        # Too fragmented to decide within budget. Sound fallback: possibly
        # open (conditional), NEVER closed.
        return _UNKNOWN

    if ruleset.default_action == Action.ALLOW and remaining:
        if any(sure for _, sure in remaining):
            return Decision(allowed=True, matched_rule=None, conditional=False)
        if not possibly_open:
            possibly_open, possibly_open_rule = True, None

    if possibly_open:
        return Decision(allowed=True, matched_rule=possibly_open_rule, conditional=True)
    if unknown:
        # Part of the query could not be evaluated (address-less node or an
        # unparsable CIDR): we cannot prove it closed.
        return _UNKNOWN
    return Decision(allowed=False, matched_rule=first_deny, conditional=False)
