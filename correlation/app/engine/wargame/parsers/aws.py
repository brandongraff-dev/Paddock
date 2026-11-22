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

        # Ingress: the SG is attached to the destination host, so src is the
        # permission's ranges and dst is ANY (the bound host carries identity).
        ingress = sg.get("IpPermissions") or []
        rs_in = RuleSet(id=str(gid), rules=[], default_action=Action.DENY, vendor="aws")
        for i, perm in enumerate(ingress):
            self._add_sg_rule(
                rs_in, perm, i, side="src", gid=str(gid),
                sg_members=sg_members, result=result, direction="ingress",
            )
        result.rulesets[rs_in.id] = rs_in
        result.bindings.append(
            RuleSetBinding(ruleset_id=rs_in.id, direction="in", attached_to=attached)
        )

        # Egress: destination-scoped. Separate RuleSet; src ANY, dst = ranges.
        egress = sg.get("IpPermissionsEgress") or []
        if egress:
            rs_out = RuleSet(
                id=f"{gid}:egress", rules=[], default_action=Action.DENY, vendor="aws"
            )
            for i, perm in enumerate(egress):
                self._add_sg_rule(
                    rs_out, perm, i, side="dst", gid=str(gid),
                    sg_members=sg_members, result=result, direction="egress",
                )
            result.rulesets[rs_out.id] = rs_out
            result.bindings.append(
                RuleSetBinding(
                    ruleset_id=rs_out.id, direction="out", attached_to=attached
                )
            )

    def _add_sg_rule(
        self,
        ruleset: RuleSet,
        perm: Any,
        index: int,
        *,
        side: str,
        gid: str,
        sg_members: dict[str, list[str]],
        result: ParseResult,
        direction: str,
    ) -> None:
        if not isinstance(perm, dict):
            result.add_warning(
                WarningLevel.UNSUPPORTED, f"{gid} {direction} permission is not an object"
            )
            return
        proto = proto_from(perm.get("IpProtocol"))
        service = ResolvedService(
            ports=self._ports(proto, perm.get("FromPort"), perm.get("ToPort"))
        )
        ranged = self._sg_ranges(perm, sg_members)
        any_side = ResolvedAddresses(cidrs=ANY_CIDRS)
        src, dst = (ranged, any_side) if side == "src" else (any_side, ranged)
        tag = "in" if side == "src" else "out"
        raw_ref = f"{gid} {direction} #{index}"
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
        perm: dict, sg_members: dict[str, list[str]]
    ) -> ResolvedAddresses:
        """The address side of an SG permission: literal CIDRs, SG-to-SG
        references resolved via ``sg_members``, and prefix lists.

        If any reference can't be resolved from config (an SG ref with no
        members supplied, or a prefix list), over-approximate to ANY and mark
        the whole side conditional/UNRESOLVED so no boundary reads as closed.
        """
        cidrs: list[str] = []
        for r in perm.get("IpRanges") or []:
            if isinstance(r, dict) and r.get("CidrIp"):
                cidrs.append(str(r["CidrIp"]))
        for r in perm.get("Ipv6Ranges") or []:
            if isinstance(r, dict) and r.get("CidrIpv6"):
                cidrs.append(str(r["CidrIpv6"]))

        unresolved: list[str] = []
        for pair in perm.get("UserIdGroupPairs") or []:
            if not isinstance(pair, dict):
                continue
            ref = pair.get("GroupId")
            if not ref:
                continue
            members = sg_members.get(str(ref))
            if members:
                cidrs.extend(str(m) for m in members)
            else:
                unresolved.append(str(ref))
        for pl in perm.get("PrefixListIds") or []:
            if isinstance(pl, dict) and pl.get("PrefixListId"):
                unresolved.append(str(pl["PrefixListId"]))

        if unresolved:
            # Can't prove the real source set — over-approximate to reachable.
            return ResolvedAddresses(
                cidrs=ANY_CIDRS,
                conditional=True,
                features=(ConditionalFeature.UNRESOLVED,),
                unresolved=tuple(dict.fromkeys(unresolved)),
            )

        canon = _canon_cidrs(cidrs)
        return ResolvedAddresses(cidrs=canon if canon else ANY_CIDRS)

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
        for entry in nacl.get("Entries") or []:
            self._add_nacl_rule(entry, str(nid), rs_in, rs_out, result)

        for rs, direction in ((rs_in, "in"), (rs_out, "out")):
            result.rulesets[rs.id] = rs
            result.bindings.append(
                RuleSetBinding(
                    ruleset_id=rs.id, direction=direction, attached_to=subnets
                )
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

        egress = bool(entry.get("Egress", False))
        action = (
            Action.ALLOW
            if str(entry.get("RuleAction", "deny")).lower() == "allow"
            else Action.DENY
        )
        proto = proto_from(entry.get("Protocol"))
        pr = entry.get("PortRange") or {}
        service = ResolvedService(
            ports=self._ports(proto, pr.get("From"), pr.get("To"))
        )

        block = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
        got = normalize_cidrs(str(block)) if block else None
        addr = ResolvedAddresses(cidrs=tuple(got)) if got else ResolvedAddresses(cidrs=ANY_CIDRS)
        any_side = ResolvedAddresses(cidrs=ANY_CIDRS)
        # Ingress: src = the entry's CIDR, dst = ANY. Egress: the mirror.
        src, dst = (any_side, addr) if egress else (addr, any_side)

        direction = "egress" if egress else "ingress"
        target = rs_out if egress else rs_in
        rule, warnings = build_rule(
            rule_id=f"{nid}:{direction}#{order}",
            action=action,
            order=order,                  # RuleNumber: lower wins (first-match)
            src=src,
            dst=dst,
            service=service,
            vendor="aws",
            raw_ref=f"{nid} {direction} rule {order}",
            cost_class=_COST_CLASS,
        )
        target.rules.append(rule)
        result.warnings.extend(warnings)

    # -- ports -------------------------------------------------------------
    @staticmethod
    def _ports(
        proto: Proto, from_port: Any, to_port: Any
    ) -> tuple[PortRange, ...]:
        """Port range for a permission/entry.

        ``-1`` protocol (ANY) and ICMP carry no L4 port; both model "any
        port". For TCP/UDP, a missing or ``-1`` bound means unbounded on that
        end, so an absent ``From``/``To`` yields the full port range.
        """
        if proto is Proto.ANY:
            return (PortRange.any(),)
        if proto is Proto.ICMP:
            # ICMP From/To are type/code, not L4 ports — model the whole space.
            return (port_range(Proto.ICMP, 0, 65535),)
        lo = 0 if from_port is None else int(from_port)
        hi = 65535 if to_port is None else int(to_port)
        if lo < 0:
            lo = 0
        if hi < 0:
            hi = 65535
        return (port_range(proto, lo, hi),)


def _canon_cidrs(cidrs: list[str]) -> tuple[str, ...]:
    """Normalise each literal and de-duplicate, keeping first-seen order."""
    out: list[str] = []
    for c in cidrs:
        got = normalize_cidrs(c)
        for norm in (got if got is not None else [c]):
            if norm not in out:
                out.append(norm)
    return tuple(out)
