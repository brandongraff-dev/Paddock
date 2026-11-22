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

Rule ids and the live AWS export
--------------------------------
The AWS parser keys SG rules positionally (``sg-x#in0``: one rule per
``IpPermission``, which can bundle several CIDRs) and NACL rules as
``f"{acl}:{ingress|egress}#{RuleNumber}"``. A plan does not know SG indices, so:

* **NACL** rules are emitted *directly* in the AWS scheme, so a plan's
  remove / modify finds the live rule with no extra step (a changed
  ``rule_number`` modifies the old number's rule).
* **SG** rules are matched by *content* in :func:`bind_to_environment` (or
  ``parse_plan(raw, env=env)``): the removed/modified rule's ports and CIDRs
  are located in the live rule set and subtracted from it. A live permission
  that bundles more CIDRs than the plan touches is *split* (the remainder is
  kept), never removed whole. A rule that cannot be matched with certainty
  (SG-to-SG / prefix-list / unresolved) is **retained** with a warning: not
  removing can only over-approximate, never claim a boundary closed.

Inline ``ingress`` / ``egress`` blocks on ``aws_security_group`` are diffed
(before vs after) into the same adds / removes. A deny whose fields are unknown
at plan time is dropped rather than widened (a widened deny would shadow later
allows, a false "closed"); an allow is widened toward reachable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any, Optional

from ..environment import ChangeKind, ChangeOp, Environment, ProposedChange
from ..model import Action, PortRange, Proto, Rule, RuleSet
from .aws import _proto_of
from .base import (
    ANY_CIDRS,
    CONDITIONAL_REASON,
    ConditionalFeature,
    normalize_cidrs,
    port_range,
)

SOURCE = "terraform-plan"
_COST_CLASS = "cloud_policy"
_UNRESOLVED_NOTE = (
    f"conditional ({ConditionalFeature.UNRESOLVED.value}): "
    f"{CONDITIONAL_REASON[ConditionalFeature.UNRESOLVED]}"
)

_SG = "aws_security_group"
_SG_RULE = "aws_security_group_rule"
_VPC_INGRESS = "aws_vpc_security_group_ingress_rule"
_VPC_EGRESS = "aws_vpc_security_group_egress_rule"
_NACL_RULE = "aws_network_acl_rule"
HANDLED_TYPES = frozenset({_SG, _SG_RULE, _VPC_INGRESS, _VPC_EGRESS, _NACL_RULE})

_ADD, _REMOVE, _MODIFY = "add", "remove", "modify"


@dataclass
class PlanParse:
    """A parsed plan: the change plus what we deliberately did not model."""

    change: ProposedChange
    #: ``(address, reason)`` for every resource change we skipped.
    skipped: list[tuple[str, str]] = field(default_factory=list)
    #: ``(address, note)`` for things modelled approximately or retained
    #: conservatively (e.g. a removal that could not be matched).
    warnings: list[tuple[str, str]] = field(default_factory=list)
    #: ``address -> (ruleset_id, before_rule)`` for SG removals/modifications,
    #: used by :func:`bind_to_environment` to find the live rule by content.
    befores: dict[str, tuple[str, Rule]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def parse_plan(raw: "dict | str", env: Optional[Environment] = None) -> ProposedChange:
    """Turn a ``terraform show -json`` plan into a :class:`ProposedChange`.

    With ``env`` the plan is bound to that environment's live rule ids (see
    :func:`bind_to_environment`) so removes/modifies find their targets."""
    return parse_plan_detailed(raw, env).change


def parse_plan_detailed(raw: "dict | str", env: Optional[Environment] = None) -> PlanParse:
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
    notes: list[tuple[str, str]] = []
    befores: dict[str, tuple[str, Rule]] = {}
    built: list[tuple[str, ChangeOp, bool]] = []   # (sort key, op, conditional)

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
            got = _build_ops(rc, address, str(rtype), befores, notes)
        except (TypeError, ValueError, KeyError, AttributeError) as e:
            skipped.append((address or "?", f"unparseable {rtype}: {e}"))
            continue
        built.extend(got)

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
    plan = PlanParse(
        change=ProposedChange(ops=ops, title=title, source=SOURCE),
        skipped=skipped,
        warnings=notes,
        befores=befores,
    )
    if env is not None:
        plan = bind_to_environment(plan, env)
    return plan


# ---------------------------------------------------------------------------
# binding to live (AWS-parsed) rule ids
# ---------------------------------------------------------------------------

def bind_to_environment(plan: PlanParse, env: Environment) -> PlanParse:
    """Rewrite ``plan`` so its removes/modifies address the rules actually
    present in ``env`` (parsed from a live AWS export by :mod:`.aws`).

    SG removals/modifications are located by content (ruleset id, ports,
    CIDR) and *subtracted* from the live rule: a live ``IpPermission`` with
    several CIDRs is split, never removed whole (removing it whole would
    narrow more than the plan does, a false "closed"). A target that cannot be
    matched exactly is retained and noted in ``warnings``. A NACL target is
    looked up by its AWS-scheme id. Never mutates ``env`` or the input plan.
    """
    working: dict[str, list[Rule]] = {}

    def rules_of(rsid: str) -> Optional[list[Rule]]:
        if rsid not in working:
            rs = env.rulesets.get(rsid)
            if rs is None:
                return None
            working[rsid] = list(rs.rules)
        return working[rsid]

    notes = list(plan.warnings)
    out: list[ChangeOp] = []

    def retain(addr: str, why: str) -> None:
        notes.append((addr, f"rule retained (not removed): {why}"))

    def subtract(addr: str, rsid: str, before: Rule) -> None:
        """Remove ``before``'s CIDRs/ports from the live rules in ``rsid``."""
        rules = rules_of(rsid)
        if rules is None:
            retain(addr, f"rule set {rsid!r} is not in the environment")
            return
        egress = rsid.endswith(":egress")
        side = (lambda r: r.dst_cidrs) if egress else (lambda r: r.src_cidrs)
        if before.conditional:
            retain(addr, "the rule uses an unresolved reference; cannot match it "
                         "to a live rule")
            return
        want_ports = set(before.ports)
        for cidr in dict.fromkeys(side(before)):
            idx = next(
                (i for i, r in enumerate(rules)
                 if r.action is Action.ALLOW and not r.conditional
                 and set(r.ports) == want_ports and cidr in side(r)),
                None,
            )
            if idx is None:
                retain(addr, f"no live rule in {rsid!r} allows {cidr} on "
                             f"{sorted(map(str, want_ports))}")
                continue
            live = rules[idx]
            left = tuple(c for c in side(live) if c != cidr)
            if not left:
                rules.pop(idx)
                out.append(ChangeOp(ChangeKind.REMOVE_RULE, ruleset_id=rsid,
                                    rule_id=live.id, description=f"remove {addr}"))
            else:
                new = (replace(live, dst_cidrs=left) if egress
                       else replace(live, src_cidrs=left))
                rules[idx] = new
                out.append(ChangeOp(ChangeKind.MODIFY_RULE, ruleset_id=rsid,
                                    rule=new, rule_id=live.id,
                                    description=f"remove {cidr} from {live.id} ({addr})"))

    for op in plan.change.ops:
        addr = op.rule_id or (op.rule.id if op.rule else "")
        if addr in plan.befores and op.kind in (ChangeKind.REMOVE_RULE,
                                                ChangeKind.MODIFY_RULE):
            b_rsid, b_rule = plan.befores[addr]
            subtract(addr, b_rsid, b_rule)
            if op.kind is ChangeKind.MODIFY_RULE and op.rule is not None:
                out.append(ChangeOp(ChangeKind.ADD_RULE, ruleset_id=op.ruleset_id,
                                    rule=op.rule,
                                    description=op.description or f"add {addr}"))
            continue
        if op.kind in (ChangeKind.REMOVE_RULE, ChangeKind.MODIFY_RULE):
            rules = rules_of(op.ruleset_id)
            target = op.rule_id or (op.rule.id if op.rule else "")
            live_id = _find_live_id(rules, target)
            if rules is None or live_id is None:
                if op.kind is ChangeKind.REMOVE_RULE:
                    retain(target, f"{target!r} not found in {op.ruleset_id!r}")
                elif op.rule is not None:
                    notes.append((target, "modify target not found; added the new "
                                          "rule instead (widens, never narrows)"))
                    out.append(ChangeOp(ChangeKind.ADD_RULE, ruleset_id=op.ruleset_id,
                                        rule=op.rule, description=op.description))
                continue
            op = replace(op, rule_id=live_id)
        out.append(op)

    change = ProposedChange(ops=out, title=plan.change.title, source=plan.change.source)
    return PlanParse(change=change, skipped=list(plan.skipped), warnings=notes,
                     befores=dict(plan.befores))


def _find_live_id(rules: Optional[list[Rule]], target: str) -> Optional[str]:
    """The live rule id for ``target``, tolerating the AWS parser's ``:v6`` /
    ``:dupN`` disambiguation suffix when the plain id is absent."""
    if rules is None or not target:
        return None
    ids = [r.id for r in rules]
    if target in ids:
        return target
    alts = [i for i in ids if i.startswith(target + ":")]
    return alts[0] if len(alts) == 1 else None


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
    try:
        lo = 0 if frm is None else int(frm)
        hi = 65535 if to is None else int(to)
    except (TypeError, ValueError):
        attrs.conditional = True
        return (port_range(proto, 0, 65535),)
    if lo < 0:
        lo = 0
    if hi < 0:
        hi = 65535
    return (port_range(proto, lo, hi),)


def _proto(attrs: _Attrs, key: str) -> tuple[Proto, bool]:
    """(proto, modelled). Unknown / unmodelled protocols widen to ANY and flag
    the rule conditional; ``modelled`` is False in that case."""
    if attrs.is_unknown(key):
        attrs.conditional = True
        return Proto.ANY, False
    proto, ok = _proto_of(attrs.values.get(key))
    if not ok:
        attrs.conditional = True
    return proto, ok


def _ruleset_id(attrs: _Attrs, key: str, address: str, suffix: str = "") -> str:
    val = attrs.values.get(key)
    if attrs.is_unknown(key) or not val:
        attrs.conditional = True
        return address
    return f"{val}{suffix}"


def _as_bool(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def _build_ops(
    rc: dict,
    address: str,
    rtype: str,
    befores: dict[str, tuple[str, Rule]],
    notes: list[tuple[str, str]],
) -> list[tuple[str, ChangeOp, bool]]:
    change = rc.get("change")
    if not isinstance(change, dict):
        raise ValueError("no change block")
    kind = _classify(_actions(rc))
    if kind is None:
        return []
    if not address:
        raise ValueError("no address")

    before_vals = change.get("before")
    after_vals = change.get("after")
    unknown = change.get("after_unknown")

    if rtype == _SG:
        return _build_inline_sg(address, kind, before_vals, after_vals, unknown,
                                befores, notes)

    results: list[tuple[str, ChangeOp, bool]] = []
    # 1. the old rule (delete / update / replace)
    before_rule: Optional[Rule] = None
    before_rsid = ""
    if kind in (_REMOVE, _MODIFY):
        if not isinstance(before_vals, dict):
            if kind == _REMOVE:
                raise ValueError("no before object")
        else:
            b_attrs = _Attrs(before_vals, {})
            built = _nacl(b_attrs, address) if rtype == _NACL_RULE \
                else _sg(b_attrs, address, rtype)
            if built is not None:
                before_rsid, before_rule = built
    if kind == _REMOVE:
        if before_rule is None:
            raise ValueError("cannot read the removed rule")
        if rtype == _NACL_RULE:
            rule_id = before_rule.id
        else:
            rule_id = address
            befores[address] = (before_rsid, before_rule)
        results.append((address, ChangeOp(
            ChangeKind.REMOVE_RULE, ruleset_id=before_rsid, rule_id=rule_id,
            description=f"remove {address}"), False))
        return results

    # 2. the new rule (create / update / replace)
    if not isinstance(after_vals, dict):
        raise ValueError("no after object")
    attrs = _Attrs(after_vals, unknown)
    built = _nacl(attrs, address) if rtype == _NACL_RULE else _sg(attrs, address, rtype)
    if built is None:
        # an unknown / unrepresentable DENY: dropped, never widened
        notes.append((address, "deny rule not modelled (unknown or unsupported "
                               "fields); omitted rather than widened"))
        if kind == _MODIFY and before_rule is not None:
            rule_id = before_rule.id if rtype == _NACL_RULE else address
            if rtype != _NACL_RULE:
                befores[address] = (before_rsid, before_rule)
            results.append((address, ChangeOp(
                ChangeKind.REMOVE_RULE, ruleset_id=before_rsid, rule_id=rule_id,
                description=f"remove {address}"), False))
        return results
    ruleset_id, rule = built

    note = f"{address}: {_UNRESOLVED_NOTE}" if attrs.conditional else address
    if kind == _ADD:
        results.append((address, ChangeOp(
            ChangeKind.ADD_RULE, ruleset_id=ruleset_id, rule=rule,
            description=f"add {note}"), rule.conditional))
        return results

    # modify / replace
    if rtype == _NACL_RULE:
        old_id = before_rule.id if before_rule is not None else rule.id
        old_rsid = before_rsid or ruleset_id
        if old_rsid != ruleset_id:
            # moved to another ACL/direction: remove there, add here
            results.append((address, ChangeOp(
                ChangeKind.REMOVE_RULE, ruleset_id=old_rsid, rule_id=old_id,
                description=f"remove {address}"), False))
            results.append((address, ChangeOp(
                ChangeKind.ADD_RULE, ruleset_id=ruleset_id, rule=rule,
                description=f"add {note}"), rule.conditional))
        else:
            results.append((address, ChangeOp(
                ChangeKind.MODIFY_RULE, ruleset_id=ruleset_id, rule=rule,
                rule_id=old_id, description=f"modify {note}"), rule.conditional))
    else:
        if before_rule is not None:
            befores[address] = (before_rsid, before_rule)
        results.append((address, ChangeOp(
            ChangeKind.MODIFY_RULE, ruleset_id=ruleset_id, rule=rule,
            rule_id=address, description=f"modify {note}"), rule.conditional))
    return results


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
        proto, _ = _proto(attrs, "protocol")
        ports = _ports(attrs, proto, "from_port", "to_port")
        addr = _cidrs(attrs, ("cidr_blocks", "ipv6_cidr_blocks"),
                      ("source_security_group_id", "prefix_list_ids", "self"))
    else:
        proto, _ = _proto(attrs, "ip_protocol")
        ports = _ports(attrs, proto, "from_port", "to_port")
        addr = _cidrs(attrs, ("cidr_ipv4", "cidr_ipv6"),
                      ("referenced_security_group_id", "prefix_list_id"))

    suffix = ":egress" if direction == "egress" else ""
    ruleset_id = _ruleset_id(attrs, "security_group_id", address, suffix)
    return ruleset_id, _sg_rule(address, direction, addr, ports, attrs.conditional)


def _sg_rule(address: str, direction: str, addr: tuple[str, ...],
             ports: tuple[PortRange, ...], conditional: bool) -> Rule:
    src, dst = (ANY_CIDRS, addr) if direction == "egress" else (addr, ANY_CIDRS)
    return Rule(
        id=address,
        action=Action.ALLOW,              # SG rules are allow-only
        order=0,
        src_cidrs=src,
        dst_cidrs=dst,
        ports=ports,
        vendor="aws",
        conditional=conditional,
        raw_ref=address,
        cost_class=_COST_CLASS,
    )


def _nacl(attrs: _Attrs, address: str) -> Optional[tuple[str, Rule]]:
    """The NACL rule, id'd in the AWS parser's scheme
    (``f"{acl}:{direction}#{rule_number}"``) when the acl and number are known.
    ``None`` for a deny that cannot be represented exactly (never widened)."""
    egress_unknown = attrs.is_unknown("egress")
    egress = False if egress_unknown else _as_bool(attrs.values.get("egress", False))
    if egress_unknown:
        attrs.conditional = True
    direction = "egress" if egress else "ingress"

    act = attrs.get("rule_action")
    action = Action.DENY if str(act).lower() == "deny" else Action.ALLOW

    num = attrs.get("rule_number")
    order_known = num is not None
    if num is None:
        # unknown position: an allow is worst-case first
        order = 0 if action is Action.ALLOW else 32767
        attrs.conditional = True
    else:
        order = int(num)

    proto, proto_ok = _proto(attrs, "protocol")
    ports = _ports(attrs, proto, "from_port", "to_port")
    addr = _cidrs(attrs, ("cidr_block", "ipv6_cidr_block"), ())
    ruleset_id = _ruleset_id(attrs, "network_acl_id", address, f":{direction}")
    acl_known = ruleset_id.endswith(f":{direction}") and ruleset_id != address
    if action is Action.DENY and (attrs.conditional or not proto_ok):
        return None
    if action is Action.DENY and proto is Proto.ICMP and attrs.values.get("icmp_type") \
            not in (None, -1, "-1"):
        return None
    src, dst = (ANY_CIDRS, addr) if egress else (addr, ANY_CIDRS)
    rule_id = (f"{ruleset_id.rsplit(':', 1)[0]}:{direction}#{order}"
               if acl_known and order_known else address)
    rule = Rule(
        id=rule_id,
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


# ---------------------------------------------------------------------------
# inline aws_security_group ingress/egress blocks
# ---------------------------------------------------------------------------

def _block_key(blk: dict) -> str:
    def norm(v: Any) -> Any:
        return sorted(str(x) for x in v) if isinstance(v, list) else v
    keys = ("protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
            "security_groups", "prefix_list_ids", "self")
    return json.dumps({k: norm(blk.get(k)) for k in keys}, sort_keys=True, default=str)


def _inline_rule(blk: dict, unk: Any, address: str, direction: str
                 ) -> tuple[Rule, bool]:
    attrs = _Attrs(blk, unk)
    proto, _ = _proto(attrs, "protocol")
    ports = _ports(attrs, proto, "from_port", "to_port")
    addr = _cidrs(attrs, ("cidr_blocks", "ipv6_cidr_blocks"),
                  ("security_groups", "prefix_list_ids", "self"))
    rule = _sg_rule(address, direction, addr, ports, attrs.conditional)
    return rule, attrs.conditional


def _build_inline_sg(
    address: str,
    kind: str,
    before_vals: Any,
    after_vals: Any,
    unknown: Any,
    befores: dict[str, tuple[str, Rule]],
    notes: list[tuple[str, str]],
) -> list[tuple[str, ChangeOp, bool]]:
    """Diff the inline ``ingress`` / ``egress`` blocks of an
    ``aws_security_group`` into rule adds and removes."""
    out: list[tuple[str, ChangeOp, bool]] = []
    if kind == _REMOVE:
        notes.append((address, "security group deletion not modelled; its rules "
                               "are retained (cannot narrow)"))
        return out
    if not isinstance(after_vals, dict):
        raise ValueError("no after object")
    unknown = unknown if isinstance(unknown, dict) else {}
    old = before_vals if isinstance(before_vals, dict) else {}
    sg_id = old.get("id") or after_vals.get("id")
    new_group = kind == _ADD or not sg_id
    if kind == _MODIFY and _flagged(unknown.get("id")) and not old.get("id"):
        new_group = True

    for direction in ("ingress", "egress"):
        suffix = ":egress" if direction == "egress" else ""
        rsid = address + suffix if new_group else f"{sg_id}{suffix}"
        a_list = after_vals.get(direction)
        a_unknown = unknown.get(direction)
        b_list = old.get(direction)
        a_blocks = [b for b in a_list if isinstance(b, dict)] if isinstance(a_list, list) else []
        b_blocks = [b for b in b_list if isinstance(b, dict)] if isinstance(b_list, list) else []
        whole_unknown = a_unknown is True or (a_list is None and _flagged(a_unknown))

        new_rules: list[tuple[str, Rule, bool]] = []
        a_keys = set()
        for i, blk in enumerate(a_blocks):
            unk = a_unknown[i] if isinstance(a_unknown, list) and i < len(a_unknown) else {}
            a_keys.add(_block_key(blk))
            if kind != _ADD and _block_key(blk) in {_block_key(b) for b in b_blocks} \
                    and not _flagged(unk):
                continue                      # unchanged block
            addr_i = f"{address}.{direction}[{i}]"
            rule, cond = _inline_rule(blk, unk, addr_i, direction)
            new_rules.append((addr_i, rule, cond))
        if whole_unknown:
            addr_i = f"{address}.{direction}[?]"
            rule = _sg_rule(addr_i, direction, ANY_CIDRS, (PortRange.any(),), True)
            new_rules.append((addr_i, rule, True))
            notes.append((address, f"{direction} blocks unknown at plan time; "
                                   "over-approximated to allow-any (conditional)"))

        if new_group:
            if new_rules or direction == "ingress":
                rs = RuleSet(id=rsid, rules=[r for _, r, _ in new_rules],
                             default_action=Action.DENY, vendor="aws")
                out.append((f"{address}{suffix}", ChangeOp(
                    ChangeKind.ADD_RULESET, ruleset=rs,
                    description=f"add security group {address}"),
                    any(c for _, _, c in new_rules)))
            continue

        # removed blocks (only when the new list is fully known)
        if not whole_unknown:
            for i, blk in enumerate(b_blocks):
                if _block_key(blk) in a_keys:
                    continue
                addr_i = f"{address}.{direction}.before[{i}]"
                rule, _ = _inline_rule(blk, {}, addr_i, direction)
                befores[addr_i] = (rsid, rule)
                out.append((addr_i, ChangeOp(
                    ChangeKind.REMOVE_RULE, ruleset_id=rsid, rule_id=addr_i,
                    description=f"remove {addr_i}"), False))
        for addr_i, rule, cond in new_rules:
            out.append((addr_i, ChangeOp(
                ChangeKind.ADD_RULE, ruleset_id=rsid, rule=rule,
                description=f"add {addr_i}"), cond))
    if new_group:
        notes.append((address, "new security group: its attachment to instances is "
                               "not in the plan, so no edge is opened by it here"))
    return out
