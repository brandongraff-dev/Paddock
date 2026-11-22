"""Terraform plan parser: ``terraform show -json`` → a Wargame ProposedChange.

DEFENSIVE. This reads the JSON of a *proposed* plan and turns the AWS network
changes in it into a :class:`~app.engine.wargame.environment.ProposedChange`
the change gate can evaluate (``docs/WARGAME.md`` §2.3). It never runs
terraform, applies anything, or sends a packet.

Handled resource types (everything else is collected in ``skipped``, never
raised on):

* ``aws_security_group_rule`` — ``type`` ingress/egress, CIDR / SG sources.
* ``aws_vpc_security_group_ingress_rule`` / ``..._egress_rule`` — the newer
  single-rule resources (``cidr_ipv4`` / ``cidr_ipv6``, ``ip_protocol``).
* ``aws_network_acl_rule`` — ordered, allow/deny, ``rule_number``.

Modelling matches :mod:`.aws` so a change composes with a parsed AWS
environment: SG ingress is src=CIDRs, dst=ANY in the RuleSet keyed by the
group id; SG egress is src=ANY, dst=CIDRs in ``f"{sg}:egress"``; NACL rules
live in ``f"{acl}:ingress"`` / ``f"{acl}:egress"`` with ``order`` =
``rule_number``.

Plan actions map to ops: ``create`` → ADD_RULE, ``delete`` → REMOVE_RULE,
``update`` → MODIFY_RULE, replace (``create`` + ``delete`` in either order) →
MODIFY_RULE using ``after``. ``no-op`` / ``read`` are ignored.

The honesty rule: a value that is null and flagged in ``after_unknown``
("known after apply"), or a reference we cannot resolve (SG-to-SG, prefix
list, ``self``), is over-approximated toward *reachable* (unknown CIDR → any,
unknown port/protocol → any) and the rule is marked ``conditional``
(:attr:`ConditionalFeature.UNRESOLVED`), so it can never prove a boundary
closed. Output is deterministic (ops sorted by address).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from ..environment import ChangeKind, ChangeOp, ProposedChange
from ..model import Action, PortRange, Proto, Rule
from .base import (
    ANY_CIDRS,
    CONDITIONAL_REASON,
    ConditionalFeature,
    normalize_cidrs,
    port_range,
    proto_from,
)

SOURCE = "terraform-plan"
_COST_CLASS = "cloud_policy"
_UNRESOLVED_NOTE = (
    f"conditional ({ConditionalFeature.UNRESOLVED.value}): "
    f"{CONDITIONAL_REASON[ConditionalFeature.UNRESOLVED]}"
)

_SG_RULE = "aws_security_group_rule"
_VPC_INGRESS = "aws_vpc_security_group_ingress_rule"
_VPC_EGRESS = "aws_vpc_security_group_egress_rule"
_NACL_RULE = "aws_network_acl_rule"
HANDLED_TYPES = frozenset({_SG_RULE, _VPC_INGRESS, _VPC_EGRESS, _NACL_RULE})

_ADD, _REMOVE, _MODIFY = "add", "remove", "modify"


@dataclass
class PlanParse:
    """A parsed plan: the change plus what we deliberately did not model."""

    change: ProposedChange
    #: ``(address, reason)`` for every resource change we skipped.
    skipped: list[tuple[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def parse_plan(raw: "dict | str") -> ProposedChange:
    """Turn a ``terraform show -json`` plan into a :class:`ProposedChange`."""
    return parse_plan_detailed(raw).change


def parse_plan_detailed(raw: "dict | str") -> PlanParse:
    """Like :func:`parse_plan` but also returns the skipped resources.

    A string is ``json.loads``-ed (invalid JSON / a non-object top level
    raises ``ValueError``). Anything wrong *inside* the plan is skipped, not
    raised.
    """
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, dict):
        raise ValueError(f"expected a terraform plan object, got {type(raw).__name__}")

    skipped: list[tuple[str, str]] = []
    built: list[tuple[str, ChangeOp, bool]] = []   # (address, op, conditional)

    changes = raw.get("resource_changes")
    if not isinstance(changes, list):
        changes = []
    for rc in changes:
        if not isinstance(rc, dict):
            skipped.append(("?", "resource change is not an object"))
            continue
        address = str(rc.get("address") or "")
        rtype = rc.get("type")
        if rtype not in HANDLED_TYPES:
            if _actions(rc) - {"no-op", "read"}:
                skipped.append((address or "?", f"unhandled resource type {rtype!r}"))
            continue
        try:
            got = _build_op(rc, address, str(rtype))
        except (TypeError, ValueError, KeyError, AttributeError) as e:
            skipped.append((address or "?", f"unparseable {rtype}: {e}"))
            continue
        if got is None:
            continue                      # no-op / read: nothing proposed
        op, conditional = got
        built.append((address, op, conditional))

    built.sort(key=lambda t: t[0])
    ops = [op for _, op, _ in built]
    adds = sum(1 for o in ops if o.kind is ChangeKind.ADD_RULE)
    removes = sum(1 for o in ops if o.kind is ChangeKind.REMOVE_RULE)
    mods = sum(1 for o in ops if o.kind is ChangeKind.MODIFY_RULE)
    cond = sum(1 for _, _, c in built if c)
    title = (
        f"Terraform plan: {len(ops)} network rule change(s) "
        f"({adds} add, {removes} remove, {mods} modify), "
        f"{cond} conditional, {len(skipped)} skipped"
    )
    return PlanParse(
        change=ProposedChange(ops=ops, title=title, source=SOURCE),
        skipped=skipped,
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _actions(rc: dict) -> set[str]:
    change = rc.get("change")
    acts = change.get("actions") if isinstance(change, dict) else None
    return {str(a) for a in acts} if isinstance(acts, list) else set()


def _classify(actions: set[str]) -> Optional[str]:
    if "create" in actions and "delete" in actions:
        return _MODIFY                    # replace: model as modify using `after`
    if "create" in actions:
        return _ADD
    if "delete" in actions:
        return _REMOVE
    if "update" in actions:
        return _MODIFY
    return None                           # no-op / read / empty


def _flagged(unknown: Any) -> bool:
    """True if an ``after_unknown`` entry marks anything as unknown."""
    if unknown is True:
        return True
    if isinstance(unknown, list):
        return any(_flagged(u) for u in unknown)
    if isinstance(unknown, dict):
        return any(_flagged(u) for u in unknown.values())
    return False


class _Attrs:
    """Attribute access over ``after`` + ``after_unknown`` that tracks
    whether any value used was unknown or unresolvable."""

    def __init__(self, values: dict, unknown: Any) -> None:
        self.values = values
        self.unknown = unknown if isinstance(unknown, dict) else {}
        self.conditional = False

    def is_unknown(self, key: str) -> bool:
        return self.values.get(key) is None and _flagged(self.unknown.get(key))

    def get(self, key: str) -> Any:
        """The value, or ``None`` if absent *or* unknown (unknown also
        flips ``conditional``)."""
        if self.is_unknown(key):
            self.conditional = True
            return None
        return self.values.get(key)


def _cidrs(attrs: _Attrs, keys: tuple[str, ...], ref_keys: tuple[str, ...]) -> tuple[str, ...]:
    """Resolve the address side. Unknown/unresolvable pieces widen to ANY
    and flag the rule conditional."""
    out: list[str] = []
    widen = False
    for key in keys:
        if attrs.is_unknown(key):
            attrs.conditional = True
            widen = True
            continue
        val = attrs.values.get(key)
        items = val if isinstance(val, list) else ([val] if val else [])
        for item in items:
            got = normalize_cidrs(str(item))
            if got is None:
                attrs.conditional = True
                widen = True
            else:
                out.extend(got)
    for key in ref_keys:
        v = attrs.values.get(key)
        if attrs.is_unknown(key) or (v not in (None, False, "", [])):
            # SG-to-SG / prefix list / self: membership isn't in the plan.
            attrs.conditional = True
            widen = True
    if widen or not out:
        if not out and not widen:
            attrs.conditional = True      # no address at all: can't prove narrow
        return ANY_CIDRS
    return tuple(dict.fromkeys(out))


def _ports(attrs: _Attrs, proto: Proto, frm_key: str, to_key: str) -> tuple[PortRange, ...]:
    if proto is Proto.ANY:
        return (PortRange.any(),)
    if proto is Proto.ICMP:
        return (port_range(Proto.ICMP, 0, 65535),)
    frm, to = attrs.get(frm_key), attrs.get(to_key)
    lo = 0 if frm is None else int(frm)
    hi = 65535 if to is None else int(to)
    if lo < 0:
        lo = 0
    if hi < 0:
        hi = 65535
    return (port_range(proto, lo, hi),)


def _proto(attrs: _Attrs, key: str) -> Proto:
    if attrs.is_unknown(key):
        attrs.conditional = True
        return Proto.ANY
    return proto_from(attrs.values.get(key))


def _ruleset_id(attrs: _Attrs, key: str, address: str, suffix: str = "") -> str:
    val = attrs.values.get(key)
    if attrs.is_unknown(key) or not val:
        attrs.conditional = True
        return address
    return f"{val}{suffix}"


def _build_op(rc: dict, address: str, rtype: str) -> Optional[tuple[ChangeOp, bool]]:
    change = rc.get("change")
    if not isinstance(change, dict):
        raise ValueError("no change block")
    kind = _classify(_actions(rc))
    if kind is None:
        return None
    if not address:
        raise ValueError("no address")

    # delete reads the old object; everything else the planned one
    src_key = "before" if kind == _REMOVE else "after"
    values = change.get(src_key)
    if not isinstance(values, dict):
        raise ValueError(f"no {src_key} object")
    unknown = change.get("after_unknown") if kind != _REMOVE else {}
    attrs = _Attrs(values, unknown)

    if rtype == _NACL_RULE:
        ruleset_id, rule = _nacl(attrs, address)
    else:
        ruleset_id, rule = _sg(attrs, address, rtype)

    note = f"{address}: {_UNRESOLVED_NOTE}" if attrs.conditional else address
    if kind == _REMOVE:
        op = ChangeOp(ChangeKind.REMOVE_RULE, ruleset_id=ruleset_id,
                      rule_id=address, description=f"remove {address}")
        return op, False
    ck = ChangeKind.ADD_RULE if kind == _ADD else ChangeKind.MODIFY_RULE
    verb = "add" if kind == _ADD else "modify"
    op = ChangeOp(ck, ruleset_id=ruleset_id, rule=rule,
                  rule_id=address if kind == _MODIFY else "",
                  description=f"{verb} {note}")
    return op, rule.conditional


def _sg(attrs: _Attrs, address: str, rtype: str) -> tuple[str, Rule]:
    if rtype == _VPC_INGRESS:
        direction = "ingress"
    elif rtype == _VPC_EGRESS:
        direction = "egress"
    else:
        t = attrs.get("type")
        if t is None:
            attrs.conditional = True
            direction = "ingress"         # unknown direction: assume the exposed one
        elif str(t).lower() in ("ingress", "egress"):
            direction = str(t).lower()
        else:
            raise ValueError(f"bad rule type {t!r}")

    if rtype == _SG_RULE:
        proto = _proto(attrs, "protocol")
        ports = _ports(attrs, proto, "from_port", "to_port")
        addr = _cidrs(attrs, ("cidr_blocks", "ipv6_cidr_blocks"),
                      ("source_security_group_id", "prefix_list_ids", "self"))
    else:
        proto = _proto(attrs, "ip_protocol")
        ports = _ports(attrs, proto, "from_port", "to_port")
        addr = _cidrs(attrs, ("cidr_ipv4", "cidr_ipv6"),
                      ("referenced_security_group_id", "prefix_list_id"))

    suffix = ":egress" if direction == "egress" else ""
    ruleset_id = _ruleset_id(attrs, "security_group_id", address, suffix)
    any_side = ANY_CIDRS
    src, dst = (any_side, addr) if direction == "egress" else (addr, any_side)
    rule = Rule(
        id=address,
        action=Action.ALLOW,              # SG rules are allow-only
        order=0,
        src_cidrs=src,
        dst_cidrs=dst,
        ports=ports,
        vendor="aws",
        conditional=attrs.conditional,
        raw_ref=address,
        cost_class=_COST_CLASS,
    )
    return ruleset_id, rule


def _nacl(attrs: _Attrs, address: str) -> tuple[str, Rule]:
    egress_unknown = attrs.is_unknown("egress")
    egress = False if egress_unknown else bool(attrs.values.get("egress", False))
    if egress_unknown:
        attrs.conditional = True
    direction = "egress" if egress else "ingress"

    act = attrs.get("rule_action")
    # unknown action: over-approximate toward reachable (allow)
    action = Action.DENY if str(act).lower() == "deny" else Action.ALLOW

    num = attrs.get("rule_number")
    if num is None:
        # unknown position: an allow is worst-case first, a deny worst-case last
        order = 0 if action is Action.ALLOW else 32767
        attrs.conditional = True
    else:
        order = int(num)

    proto = _proto(attrs, "protocol")
    ports = _ports(attrs, proto, "from_port", "to_port")
    addr = _cidrs(attrs, ("cidr_block", "ipv6_cidr_block"), ())
    ruleset_id = _ruleset_id(attrs, "network_acl_id", address, f":{direction}")
    src, dst = (ANY_CIDRS, addr) if egress else (addr, ANY_CIDRS)
    rule = Rule(
        id=address,
        action=action,
        order=order,
        src_cidrs=src,
        dst_cidrs=dst,
        ports=ports,
        vendor="aws",
        conditional=attrs.conditional,
        raw_ref=address,
        cost_class=_COST_CLASS,
    )
    return ruleset_id, rule
