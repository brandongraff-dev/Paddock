"""AWS parser: VPC Security Groups and Network ACLs → vendor-neutral RuleSets.

DEFENSIVE. This turns a static AWS network export into the solver's
:class:`~app.engine.wargame.model.RuleSet` model. It sends no packets and
represents no exploit — it only reasons about what the configuration permits,
the way Batfish / AWS Tiros do (see ``docs/WARGAME.md`` §2.2).

It consumes the JSON that ``aws ec2 describe-security-groups`` and
``aws ec2 describe-network-acls`` emit (boto3 shapes), in one combined dict
(``{"SecurityGroups": [...], "NetworkAcls": [...]}``) or whichever key is
present. ``raw`` may be a dict or a JSON string.

Modelling choices, made explicit (the honesty rule, ``docs/WARGAME.md`` §2.2):

**Security groups are stateful and allow-only.** Each SG's *ingress* rules
(``IpPermissions``) become one RuleSet keyed by ``GroupId`` with
``default_action=DENY`` — anything not explicitly admitted is denied. Order
inside an SG RuleSet is irrelevant (every rule is an allow and the group is a
union), so we assign ``order`` by appearance for stability only.

*Direction.* An SG is attached to the host it protects, so the group itself
carries the *destination* identity (via its :class:`RuleSetBinding`, which
names the ENIs/instances it is attached to). Therefore an **ingress** rule's
``dst_cidrs`` is ANY — the destination is the bound host, not something the
rule enumerates — and its ``src_cidrs`` is what the permission lists. We record
*egress* (``IpPermissionsEgress``) as a **separate** RuleSet keyed
``f"{GroupId}:egress"``: egress is destination-scoped, so there ``src_cidrs``
is ANY and ``dst_cidrs`` is what the permission lists.

*SG-to-SG references* (``UserIdGroupPairs``) are not a CIDR — the real source
is "every instance that carries the referenced SG". When the caller supplies
``sg_members`` (``{group_id: [cidr, ...]}``) we resolve the reference to those
member CIDRs, and the rule stays a hard, provable allow (NOT conditional).
When it is not supplied we cannot know the members from config alone, so we
over-approximate the source to ANY and mark the rule ``conditional``
(:attr:`ConditionalFeature.UNRESOLVED`) with a warning naming the SG — a
defensive tool must never claim a door is shut because it failed to read it.

*Prefix lists* (``PrefixListIds``) have contents that are not in the SG export,
so they are always ``conditional`` / UNRESOLVED here (a prefix-list resolver is
future work).

**Network ACLs are stateless and ordered.** Each NACL yields TWO RuleSets —
``f"{NetworkAclId}:ingress"`` and ``f"{NetworkAclId}:egress"`` — split on the
entry's ``Egress`` flag. Entries are first-match by ``RuleNumber`` ascending
(lower wins), so we set ``Rule.order = RuleNumber``. ``RuleAction`` gives
allow/deny. For ingress ``src_cidrs`` is the entry's CIDR and ``dst_cidrs`` is
ANY; for egress it is the mirror. ``default_action`` is DENY (the implicit
``RuleNumber 32767`` "*" deny); we emit that explicit entry too when the export
contains it. Bindings name the subnets the NACL is associated with.

Never raises on missing/odd keys: the offending SG / NACL / entry is skipped
with an UNSUPPORTED/INFO warning. Output is deterministic for a fixed input
(SGs sorted by ``GroupId``, NACLs by ``NetworkAclId``, rules in a stable order).
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from ..model import Action, PortRange, Proto, RuleSet
from .base import (
    ANY_CIDRS,
    ConditionalFeature,
    Parser,
    ParseResult,
    ResolvedAddresses,
    ResolvedService,
    RuleSetBinding,
    WarningLevel,
    build_rule,
    normalize_cidrs,
    port_range,
    proto_from,
    register,
)

_COST_CLASS = "cloud_policy"


@register("aws")
class AwsParser(Parser):
    """Parse AWS Security Groups and Network ACLs into RuleSets."""

    def parse(
        self,
        raw: Any,
        *,
        sg_members: Optional[dict[str, list[str]]] = None,
        **opts: Any,
    ) -> ParseResult:
        result = ParseResult(vendor="aws")
        data = self._load(raw, result)
        if data is None:
            return result

        sgs = data.get("SecurityGroups")
        nacls = data.get("NetworkAcls")
        if sgs is None and nacls is None:
            result.add_warning(
                WarningLevel.INFO,
                "no SecurityGroups or NetworkAcls key in input; nothing to parse",
            )
            return result

        if isinstance(sgs, list):
            for sg in sorted(
                sgs, key=lambda g: str(g.get("GroupId", "")) if isinstance(g, dict) else ""
            ):
                self._parse_security_group(sg, sg_members or {}, result)
        if isinstance(nacls, list):
            for nacl in sorted(
                nacls,
                key=lambda n: str(n.get("NetworkAclId", "")) if isinstance(n, dict) else "",
            ):
                self._parse_network_acl(nacl, result)
        return result

    # -- input -------------------------------------------------------------
    @staticmethod
    def _load(raw: Any, result: ParseResult) -> Optional[dict]:
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (ValueError, TypeError) as e:
                result.add_warning(
                    WarningLevel.UNSUPPORTED, f"input is not valid JSON: {e}"
                )
                return None
        if not isinstance(raw, dict):
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"expected a dict of describe-* output, got {type(raw).__name__}",
            )
            return None
        return raw

    # -- security groups ---------------------------------------------------
    def _parse_security_group(
        self, sg: Any, sg_members: dict[str, list[str]], result: ParseResult
    ) -> None:
        if not isinstance(sg, dict):
            result.add_warning(WarningLevel.UNSUPPORTED, "security group is not an object")
            return
        gid = sg.get("GroupId")
        if not gid:
            result.add_warning(
                WarningLevel.UNSUPPORTED, "security group has no GroupId; skipped"
            )
            return

        attached = tuple(str(a) for a in (sg.get("AttachedTo") or []) if a)

        owner = str(sg.get("OwnerId") or "")

        # Ingress: the SG is attached to the destination host, so src is the
        # permission's ranges and dst is ANY (the bound host carries identity).
        ingress = sg.get("IpPermissions")
        rs_in = RuleSet(id=str(gid), rules=[], default_action=Action.DENY, vendor="aws")
        if isinstance(ingress, list):
            for i, perm in enumerate(ingress):
                self._add_sg_rule(
                    rs_in, perm, i, side="src", gid=str(gid), owner=owner,
                    sg_members=sg_members, result=result, direction="ingress",
                )
        else:
            # A missing key is NOT "no rules": reading it as an empty allow-list
            # would call every port closed (a false "closed"). Over-approximate.
            self._unknown_permissions(rs_in, str(gid), "ingress", "src", result)
        result.rulesets[rs_in.id] = rs_in
        result.bindings.append(
            RuleSetBinding(ruleset_id=rs_in.id, direction="in", attached_to=attached)
        )

        # Egress: destination-scoped. Separate RuleSet; src ANY, dst = ranges.
        # A *present but empty* list is real (all egress revoked => deny all);
        # a missing key is unknown and emits no egress filter at all.
        egress = sg.get("IpPermissionsEgress")
        if isinstance(egress, list):
            rs_out = RuleSet(
                id=f"{gid}:egress", rules=[], default_action=Action.DENY, vendor="aws"
            )
            for i, perm in enumerate(egress):
                self._add_sg_rule(
                    rs_out, perm, i, side="dst", gid=str(gid), owner=owner,
                    sg_members=sg_members, result=result, direction="egress",
                )
            result.rulesets[rs_out.id] = rs_out
            result.bindings.append(
                RuleSetBinding(
                    ruleset_id=rs_out.id, direction="out", attached_to=attached
                )
            )
        else:
            result.add_warning(
                WarningLevel.INFO,
                f"{gid} has no IpPermissionsEgress; egress is not modelled "
                "(treated as unfiltered)",
                str(gid),
            )

    @staticmethod
    def _unknown_permissions(
        ruleset: RuleSet, gid: str, direction: str, side: str, result: ParseResult
    ) -> None:
        """Add a conditional allow-any rule for a permission list we could not
        read, so the group can never prove a boundary closed."""
        tag = "in" if side == "src" else "out"
        rule, warnings = build_rule(
            rule_id=f"{gid}#{tag}unknown",
            action=Action.ALLOW,
            order=0,
            src=ResolvedAddresses(cidrs=ANY_CIDRS),
            dst=ResolvedAddresses(cidrs=ANY_CIDRS),
            service=ResolvedService(ports=(PortRange.any(),)),
            vendor="aws",
            raw_ref=f"{gid} {direction} (unreadable)",
            cost_class=_COST_CLASS,
            extra_conditional=True,
            extra_feature=ConditionalFeature.UNRESOLVED,
        )
        ruleset.rules.append(rule)
        result.warnings.extend(warnings)
        result.add_warning(
            WarningLevel.UNSUPPORTED,
            f"{gid} has no readable {direction} permission list; "
            "over-approximated to allow-any (conditional)",
            gid,
        )

    def _add_sg_rule(
        self,
        ruleset: RuleSet,
        perm: Any,
        index: int,
        *,
        side: str,
        gid: str,
        owner: str = "",
        sg_members: dict[str, list[str]],
        result: ParseResult,
        direction: str,
    ) -> None:
        if not isinstance(perm, dict):
            # An unreadable permission must not silently vanish (that narrows
            # the group): over-approximate it to allow-any, conditional.
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"{gid} {direction} permission #{index} is not an object; "
                "over-approximated to allow-any (conditional)",
            )
            perm = {"_unreadable": True}
        proto, proto_ok = _proto_of(perm.get("IpProtocol"))
        ports, ports_ok = self._ports_checked(
            proto, perm.get("FromPort"), perm.get("ToPort")
        )
        service = ResolvedService(
            ports=ports,
            conditional=not (proto_ok and ports_ok),
            features=(
                () if (proto_ok and ports_ok) else (ConditionalFeature.UNRESOLVED,)
            ),
        )
        raw_ref = f"{gid} {direction} #{index}"
        if not (proto_ok and ports_ok):
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"unmodelled protocol/port {perm.get('IpProtocol')!r} "
                f"{perm.get('FromPort')!r}-{perm.get('ToPort')!r}; "
                "over-approximated to any (conditional)",
                raw_ref,
            )
        ranged = self._sg_ranges(perm, sg_members, owner=owner, ref=raw_ref, result=result)
        any_side = ResolvedAddresses(cidrs=ANY_CIDRS)
        src, dst = (ranged, any_side) if side == "src" else (any_side, ranged)
        tag = "in" if side == "src" else "out"
        rule, warnings = build_rule(
            rule_id=f"{gid}#{tag}{index}",
            action=Action.ALLOW,          # SG rules are allow-only
            order=index,                  # order is irrelevant within an SG
            src=src,
            dst=dst,
            service=service,
            vendor="aws",
            raw_ref=raw_ref,
            cost_class=_COST_CLASS,
        )
        ruleset.rules.append(rule)
        result.warnings.extend(warnings)

    @staticmethod
    def _sg_ranges(
        perm: dict,
        sg_members: dict[str, list[str]],
        *,
        owner: str = "",
        ref: str = "",
        result: Optional[ParseResult] = None,
    ) -> ResolvedAddresses:
        """The address side of an SG permission: literal CIDRs, SG-to-SG
        references resolved via ``sg_members``, and prefix lists.

        If any reference can't be resolved from config (an SG ref with no
        members supplied, a prefix list, an unparseable CIDR, a permission with
        no source at all), over-approximate to ANY and mark the whole side
        conditional/UNRESOLVED so no boundary reads as closed.

        A reference to a group in *another account* is never provable from
        this account's export: even when members are supplied the rule is
        flagged conditional.
        """
        cidrs: list[str] = []
        unresolved: list[str] = []
        widen = False
        flag_only = False         # conditional, but members known (narrow ok)

        def lit(token: Any) -> None:
            nonlocal widen
            got = normalize_cidrs(str(token))
            if got is None:
                unresolved.append(f"bad-cidr:{token}")
                widen = True
            else:
                cidrs.extend(got)

        for r in perm.get("IpRanges") or []:
            if isinstance(r, dict) and r.get("CidrIp"):
                lit(r["CidrIp"])
        for r in perm.get("Ipv6Ranges") or []:
            if isinstance(r, dict) and r.get("CidrIpv6"):
                lit(r["CidrIpv6"])

        for pair in perm.get("UserIdGroupPairs") or []:
            if not isinstance(pair, dict):
                continue
            gref = pair.get("GroupId")
            if not gref:
                # GroupName-only / peering-only reference: membership unknown.
                name = pair.get("GroupName") or pair.get("VpcPeeringConnectionId") or "?"
                unresolved.append(str(name))
                widen = True
                continue
            gref = str(gref)
            foreign = bool(
                owner and pair.get("UserId") and str(pair.get("UserId")) != owner
            ) or bool(pair.get("VpcPeeringConnectionId"))
            members = sg_members.get(gref)
            ok = (
                isinstance(members, (list, tuple, set))
                and len(members) > 0
                and all(normalize_cidrs(str(m)) is not None for m in members)
            )
            if ok:
                for m in members:  # type: ignore[union-attr]
                    cidrs.extend(normalize_cidrs(str(m)) or [])
                if foreign:
                    flag_only = True
                    unresolved.append(f"cross-account:{gref}")
            else:
                unresolved.append(gref)
                widen = True
        for pl in perm.get("PrefixListIds") or []:
            if isinstance(pl, dict) and pl.get("PrefixListId"):
                unresolved.append(str(pl["PrefixListId"]))
                widen = True
        if perm.get("_unreadable"):
            unresolved.append("unreadable-permission")
            widen = True

        canon = _canon_cidrs(cidrs)
        if not canon and not widen:
            unresolved.append("no-source-or-destination")
            widen = True
        if widen:
            # Can't prove the real source set — over-approximate to reachable.
            return ResolvedAddresses(
                cidrs=ANY_CIDRS,
                conditional=True,
                features=(ConditionalFeature.UNRESOLVED,),
                unresolved=tuple(dict.fromkeys(unresolved)),
            )
        if flag_only:
            return ResolvedAddresses(
                cidrs=canon,
                conditional=True,
                features=(ConditionalFeature.UNRESOLVED,),
                unresolved=tuple(dict.fromkeys(unresolved)),
            )
        return ResolvedAddresses(cidrs=canon)

    # -- network ACLs ------------------------------------------------------
    def _parse_network_acl(self, nacl: Any, result: ParseResult) -> None:
        if not isinstance(nacl, dict):
            result.add_warning(WarningLevel.UNSUPPORTED, "network ACL is not an object")
            return
        nid = nacl.get("NetworkAclId")
        if not nid:
            result.add_warning(
                WarningLevel.UNSUPPORTED, "network ACL has no NetworkAclId; skipped"
            )
            return

        subnets = tuple(
            str(a.get("SubnetId"))
            for a in (nacl.get("Associations") or [])
            if isinstance(a, dict) and a.get("SubnetId")
        )

        rs_in = RuleSet(
            id=f"{nid}:ingress", rules=[], default_action=Action.DENY, vendor="aws"
        )
        rs_out = RuleSet(
            id=f"{nid}:egress", rules=[], default_action=Action.DENY, vendor="aws"
        )
        entries = nacl.get("Entries")
        if not isinstance(entries, list):
            # No Entries key is not "deny everything": that would be a false
            # closed. Over-approximate both directions to a conditional allow.
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"{nid} has no Entries list; over-approximated to allow-any "
                "(conditional)",
                str(nid),
            )
            for rs, direction in ((rs_in, "ingress"), (rs_out, "egress")):
                rule, warnings = build_rule(
                    rule_id=f"{nid}:{direction}#unknown",
                    action=Action.ALLOW,
                    order=0,
                    src=ResolvedAddresses(cidrs=ANY_CIDRS),
                    dst=ResolvedAddresses(cidrs=ANY_CIDRS),
                    service=ResolvedService(ports=(PortRange.any(),)),
                    vendor="aws",
                    raw_ref=f"{nid} {direction} (unreadable)",
                    cost_class=_COST_CLASS,
                    extra_conditional=True,
                    extra_feature=ConditionalFeature.UNRESOLVED,
                )
                rs.rules.append(rule)
                result.warnings.extend(warnings)
            entries = []

        # First match by RuleNumber ascending, independent of export order.
        def _key(e: Any) -> tuple:
            n = e.get("RuleNumber") if isinstance(e, dict) else None
            try:
                return (0, int(n))
            except (TypeError, ValueError):
                return (1, 0)

        for entry in sorted(entries, key=_key):
            self._add_nacl_rule(entry, str(nid), rs_in, rs_out, result)

        self._warn_stateless(str(nid), rs_in, rs_out, result)

        for rs, direction in ((rs_in, "in"), (rs_out, "out")):
            result.rulesets[rs.id] = rs
            result.bindings.append(
                RuleSetBinding(
                    ruleset_id=rs.id, direction=direction, attached_to=subnets
                )
            )

    @staticmethod
    def _warn_stateless(
        nid: str, rs_in: RuleSet, rs_out: RuleSet, result: ParseResult
    ) -> None:
        """NACLs are stateless: a reply needs its own egress allow on the
        ephemeral ports. The model reasons about the forward path only (which
        over-approximates), so flag it when the return path looks blocked."""

        def _admits_ephemeral(rs: RuleSet) -> bool:
            for r in sorted(rs.rules, key=lambda r: (r.order, r.id)):
                covers = any(
                    p.proto.matches(Proto.TCP) and p.low <= 1024 and p.high >= 65535
                    for p in r.ports
                )
                if covers:
                    return r.action is Action.ALLOW
            return False

        allows_in = any(
            r.action is Action.ALLOW and r.ports and r.ports[0].proto is not Proto.ICMP
            for r in rs_in.rules
        )
        if allows_in and not _admits_ephemeral(rs_out):
            result.add_warning(
                WarningLevel.INFO,
                f"{nid} is stateless: ingress allows traffic but egress has no "
                "allow covering ephemeral ports 1024-65535, so replies may be "
                "dropped in practice; the model reports the forward path only "
                "(over-approximation, never a false closed)",
                str(nid),
            )

    def _add_nacl_rule(
        self,
        entry: Any,
        nid: str,
        rs_in: RuleSet,
        rs_out: RuleSet,
        result: ParseResult,
    ) -> None:
        if not isinstance(entry, dict):
            result.add_warning(WarningLevel.UNSUPPORTED, f"{nid} NACL entry is not an object")
            return
        number = entry.get("RuleNumber")
        if number is None:
            result.add_warning(
                WarningLevel.UNSUPPORTED, f"{nid} NACL entry has no RuleNumber; skipped"
            )
            return
        try:
            order = int(number)
        except (TypeError, ValueError):
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"{nid} NACL entry RuleNumber not an int; skipped",
                str(number),
            )
            return

        egress = _as_bool(entry.get("Egress", False))
        direction = "egress" if egress else "ingress"
        target = rs_out if egress else rs_in
        rule_id = f"{nid}:{direction}#{order}"
        if any(r.id == rule_id for r in target.rules):
            # IPv4 and IPv6 entries may reuse a number: keep ids unique.
            rule_id = f"{rule_id}:v6"
            n = 2
            while any(r.id == rule_id for r in target.rules):
                rule_id = f"{nid}:{direction}#{order}:dup{n}"
                n += 1
        raw_ref = f"{nid} {direction} rule {order}"

        action_tok = str(entry.get("RuleAction", "")).strip().lower()
        action_known = action_tok in ("allow", "deny")
        action = Action.DENY if action_tok == "deny" else Action.ALLOW
        conditional = False
        if not action_known:
            # Unknown action: an allow over-approximates (never narrows).
            conditional = True
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"unrecognised RuleAction {entry.get('RuleAction')!r}; treated as "
                "allow (conditional)",
                raw_ref,
            )

        proto, proto_ok = _proto_of(entry.get("Protocol"))
        pr = entry.get("PortRange")
        pr = pr if isinstance(pr, dict) else {}
        ports, ports_ok = self._ports_checked(proto, pr.get("From"), pr.get("To"))

        block = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
        got = normalize_cidrs(str(block)) if block else None
        addr_ok = got is not None

        if action is Action.DENY:
            # A deny that is wider than the real one would shadow later allows
            # (a false "closed"). If we cannot express it exactly, drop it
            # (narrowing a deny only ever makes the model more open).
            reason = ""
            if not proto_ok:
                reason = f"protocol {entry.get('Protocol')!r} is not modelled"
            elif not ports_ok:
                reason = "port range is unreadable"
            elif not addr_ok:
                reason = "CIDR is missing or unreadable"
            elif proto is Proto.ICMP and _icmp_is_specific(entry.get("IcmpTypeCode")):
                reason = "ICMP type/code deny cannot be expressed (model has no types)"
            if reason:
                result.add_warning(
                    WarningLevel.UNSUPPORTED,
                    f"deny entry skipped (never widened): {reason}",
                    raw_ref,
                )
                return
        else:
            if not (proto_ok and ports_ok):
                conditional = True
                result.add_warning(
                    WarningLevel.UNSUPPORTED,
                    f"unmodelled protocol/port {entry.get('Protocol')!r}; allow "
                    "over-approximated to any (conditional)",
                    raw_ref,
                )
            if not addr_ok:
                conditional = True

        addr = (
            ResolvedAddresses(cidrs=tuple(got)) if got else ResolvedAddresses(cidrs=ANY_CIDRS)
        )
        any_side = ResolvedAddresses(cidrs=ANY_CIDRS)
        # Ingress: src = the entry's CIDR, dst = ANY. Egress: the mirror.
        src, dst = (any_side, addr) if egress else (addr, any_side)

        rule, warnings = build_rule(
            rule_id=rule_id,
            action=action,
            order=order,                  # RuleNumber: lower wins (first-match)
            src=src,
            dst=dst,
            service=ResolvedService(ports=ports),
            vendor="aws",
            raw_ref=raw_ref,
            cost_class=_COST_CLASS,
            extra_conditional=conditional,
            extra_feature=ConditionalFeature.UNRESOLVED if conditional else None,
        )
        target.rules.append(rule)
        result.warnings.extend(warnings)

    # -- ports -------------------------------------------------------------
    @staticmethod
    def _ports(proto: Proto, from_port: Any, to_port: Any) -> tuple[PortRange, ...]:
        return AwsParser._ports_checked(proto, from_port, to_port)[0]

    @staticmethod
    def _ports_checked(
        proto: Proto, from_port: Any, to_port: Any
    ) -> tuple[tuple[PortRange, ...], bool]:
        """Port range for a permission/entry, plus whether it was readable.

        ``-1`` protocol (ANY) and ICMP carry no L4 port (ICMP From/To are
        type/code, and ``-1`` means all types); both model "any port". For
        TCP/UDP, a missing or ``-1`` bound means unbounded on that end. An
        unreadable bound (non-integer) widens to the full range and reports
        ``False`` so the caller can mark the rule conditional.
        """
        if proto is Proto.ANY:
            return (PortRange.any(),), True
        if proto is Proto.ICMP:
            return (port_range(Proto.ICMP, 0, 65535),), True
        ok = True
        try:
            lo = 0 if from_port is None else int(from_port)
        except (TypeError, ValueError):
            lo, ok = 0, False
        try:
            hi = 65535 if to_port is None else int(to_port)
        except (TypeError, ValueError):
            hi, ok = 65535, False
        if lo < 0:
            lo = 0
        if hi < 0:
            hi = 65535
        if not ok:
            lo, hi = 0, 65535
        return (port_range(proto, lo, hi),), ok


_KNOWN_PROTOS = frozenset(
    {"tcp", "6", "udp", "17", "icmp", "1", "icmpv6", "58", "-1", "all"}
)


def _proto_of(token: Any) -> tuple[Proto, bool]:
    """Map an AWS protocol token to (Proto, modelled?).

    ``-1`` is "all". Any other protocol (GRE 47, ESP 50, ...) is not
    representable: it maps to ANY (over-approximation) with ``modelled=False``
    so callers can flag it conditional (allow) or refuse to widen it (deny).
    A missing protocol is unreadable, not "all".
    """
    if token is None:
        return Proto.ANY, False
    t = str(token).strip().lower()
    if t == "all":
        return Proto.ANY, True
    if t not in _KNOWN_PROTOS:
        return Proto.ANY, False
    return proto_from(t), True


def _as_bool(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def _icmp_is_specific(code: Any) -> bool:
    """True if an ``IcmpTypeCode`` narrows to a specific type (not all)."""
    if not isinstance(code, dict):
        return False
    t = code.get("Type")
    return t is not None and str(t) != "-1"


def combine_security_groups(
    result: ParseResult, group_ids: list[str], merged_id: str, *, direction: str = "in"
) -> Optional[RuleSet]:
    """Union of several security groups attached to one ENI.

    AWS evaluates multiple SGs as a *union*: traffic is allowed if ANY group
    allows it. Because each group is its own default-DENY :class:`RuleSet`, an
    edge governed by only one of them would read closed for traffic another
    group admits. This returns (and registers under ``merged_id``) one
    RuleSet whose rules are every member's allow rules, with the same
    default DENY. Unknown ids are skipped with a warning; ``None`` if none
    resolve. Rules are renumbered for stable ordering.
    """
    suffix = "" if direction == "in" else ":egress"
    rules = []
    for gid in sorted(group_ids):
        rs = result.rulesets.get(f"{gid}{suffix}")
        if rs is None:
            result.add_warning(
                WarningLevel.UNRESOLVED,
                f"cannot combine unknown security group {gid}{suffix}",
                merged_id,
            )
            continue
        rules.extend(rs.rules)
    if not rules and not any(f"{g}{suffix}" in result.rulesets for g in group_ids):
        return None
    from dataclasses import replace

    merged = RuleSet(
        id=merged_id,
        rules=[replace(r, order=i) for i, r in enumerate(rules)],
        default_action=Action.DENY,
        vendor="aws",
    )
    result.rulesets[merged_id] = merged
    return merged


def _canon_cidrs(cidrs: list[str]) -> tuple[str, ...]:
    """De-duplicate already-normalised literals, keeping first-seen order."""
    out: list[str] = []
    for c in cidrs:
        if c not in out:
            out.append(c)
    return tuple(out)
