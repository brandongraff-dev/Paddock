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
only as "needs a probe or observation to settle".
"""
from __future__ import annotations

import ipaddress
import itertools
from typing import Optional

from .model import Action, Decision, PortRange, Proto, RuleSet


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
# Boundary evaluation (CIDR-to-CIDR, representative-flow approximation)
# ---------------------------------------------------------------------------

def _first_host(cidr: str) -> Optional[str]:
    """A representative host address for ``cidr`` (its first usable host).

    Handles a plain CIDR, a bare IP (treated as a /32 or /128), a /31 or /32
    (RFC 3021 point-to-point and single host, both usable), and IPv6. Returns
    ``None`` for input that does not parse as a network or an address, so the
    caller can simply skip it.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        # Not a network; maybe a bare address with no prefix after all.
        try:
            return str(ipaddress.ip_address(cidr))
        except ValueError:
            return None
    # ``hosts()`` already special-cases /31 and /32 (both/one usable) and
    # drops the network + broadcast address for a wider IPv4 block.
    first = next(iter(net.hosts()), None)
    if first is not None:
        return str(first)
    # Degenerate (shouldn't happen for valid nets) — fall back to the base.
    return str(net.network_address)


def boundary_permits(
    ruleset: RuleSet,
    src_cidrs: "tuple[str, ...] | list[str]",
    dst_cidrs: "tuple[str, ...] | list[str]",
    port: Optional[PortRange],
) -> Decision:
    """Decide whether *any* flow from any ``src_cidr`` to any ``dst_cidr`` on
    the given port class is permitted by ``ruleset``.

    Approach. One representative flow is evaluated per (src_cidr, dst_cidr)
    pair, using the first usable host of each CIDR (see :func:`_first_host`)
    and a representative port — ``port.low`` on ``port.proto`` when a
    :class:`PortRange` is given, else port ``0`` on :attr:`Proto.ANY`. The
    verdict is reduced over all representative flows:

    * if any representative flow is **allowed**, return an allowed
      :class:`Decision` (a non-conditional allow is preferred over a
      conditional one, so a proved-open boundary is reported as such);
    * else if some representative flow was decided by a **conditional** rule,
      return a conditional, allowed Decision — the config cannot prove the
      boundary closed, so it is treated as possibly-open and labelled
      ``conditional``, never closed;
    * else return a denied Decision.

    If either side carries no CIDR there are no representative flows and the
    result is a denied Decision; model address-less adjacencies (identities,
    third parties) as *ungoverned* edges rather than governed ones.

    LIMITATION — representative-IP approximation. Only the first usable host
    of each CIDR is tested, so a sub-CIDR deny carve-out (a rule that denies
    a slice of an otherwise-allowed block, or allows a slice of an otherwise
    denied one) can be over- or under-counted: a boundary may read as open
    when only part of the range is, or as closed when a narrow allow exists
    off the representative host. This is a deliberate trade for a bounded,
    deterministic per-boundary verdict; exhaustive per-host evaluation is out
    of scope for the solver.
    """
    if port is not None:
        rep_proto = port.proto
        rep_port = port.low
    else:
        rep_proto = Proto.ANY
        rep_port = 0

    src_hosts = [h for h in (_first_host(c) for c in src_cidrs) if h is not None]
    dst_hosts = [h for h in (_first_host(c) for c in dst_cidrs) if h is not None]

    allowed_decision: Optional[Decision] = None
    conditional_decision: Optional[Decision] = None
    denied_decision: Optional[Decision] = None

    for s, d in itertools.product(src_hosts, dst_hosts):
        dec = evaluate(ruleset, s, d, rep_proto, rep_port)
        if dec.allowed:
            if not dec.conditional:
                # Strongest open signal — return immediately, it is proved.
                return dec
            if allowed_decision is None:
                allowed_decision = dec
        elif dec.conditional:
            if conditional_decision is None:
                conditional_decision = dec
        elif denied_decision is None:
            denied_decision = dec

    if allowed_decision is not None:
        return allowed_decision
    if conditional_decision is not None:
        # A conditional rule decided it (e.g. a conditional deny). Config
        # cannot prove the boundary closed, so treat it as possibly-open and
        # labelled conditional — never as a closed proof.
        return Decision(
            allowed=True,
            matched_rule=conditional_decision.matched_rule,
            conditional=True,
        )
    if denied_decision is not None:
        return denied_decision
    # No representative flows at all (both sides address-less, or unparsable).
    return Decision(allowed=False, matched_rule=None, conditional=False)
