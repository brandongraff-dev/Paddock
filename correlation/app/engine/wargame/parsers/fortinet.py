"""Fortinet FortiGate (FortiOS CLI) parser.

Turns the nested ``config ... edit ... set ... next ... end`` text of a
FortiOS backup into vendor-neutral :class:`~app.engine.wargame.model.RuleSet`
objects. Defensive only: it reads config, nothing is sent anywhere.

Modelling choices
-----------------
* **Rule sets are keyed by zone pair**: ``f"{srcintf}>{dstintf}"``. Several
  interfaces on one policy are joined with ``+`` (in config order); an unset
  list is ``any``. In a multi-VDOM backup the key is prefixed ``<vdom>:``.
  Each rule set carries ``default_action=DENY`` (FortiOS implicit deny) and
  gets a :class:`RuleSetBinding` with ``src_zone``/``dst_zone``.
* **Order is appearance order.** FortiOS evaluates policies top to bottom as
  *listed*, not by policy id, so ``Rule.order`` is the policy's global
  appearance index; the policy id lives in ``raw_ref`` / the rule id.
* **Multiple srcaddr/dstaddr/service tokens** are each resolved through the
  :class:`ObjectTable` and UNIONed (cidrs / ports de-duplicated in order;
  conditional flags, features and unresolved names merged).
* A missing ``set action`` means DENY (FortiOS default). ``set status
  disable`` skips the policy entirely (INFO warning).
* The honesty rule: FQDN / geography / dynamic address objects, user or
  group match, application match and Internet-Service objects make a rule
  ``conditional``. Negated matches (``*-negate enable``) cannot be modelled
  as a CIDR set, so that side widens to "any" and the rule is conditional.
* Predefined FortiGate services whose real definition differs from base's
  named-service table (DNS, SNMP, PING, ALL_*) are seeded as ``FGT:<name>``
  objects and policy tokens are remapped, unless the config redefines them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..model import Action, PortRange, Proto
from .base import (
    ANY_CIDRS,
    AddressObject,
    ConditionalFeature,
    ObjectTable,
    ParseResult,
    Parser,
    ResolvedAddresses,
    ResolvedService,
    RuleSetBinding,
    ServiceObject,
    WarningLevel,
    build_rule,
    normalize_cidrs,
    port_range,
    proto_from,
    register,
)
from ..model import RuleSet

_VENDOR = "fortinet"

#: Predefined services where base.service_from_name would be wrong/missing.
_BUILTIN_SERVICES: dict[str, tuple[PortRange, ...]] = {
    "DNS": (port_range(Proto.TCP, 53), port_range(Proto.UDP, 53)),
    "SNMP": (port_range(Proto.TCP, 161, 162), port_range(Proto.UDP, 161, 162)),
    "PING": (PortRange(Proto.ICMP, 0, 65535),),
    "ALL_ICMP": (PortRange(Proto.ICMP, 0, 65535),),
    "ALL_TCP": (PortRange(Proto.TCP, 0, 65535),),
    "ALL_UDP": (PortRange(Proto.UDP, 0, 65535),),
}
_BUILTIN_PREFIX = "FGT:"


# ---------------------------------------------------------------------------
# Block tokenizer
# ---------------------------------------------------------------------------

@dataclass
class _Node:
    kind: str                      # "root" | "config" | "edit"
    name: str = ""                 # config path ("firewall policy") or edit key
    settings: dict[str, list[str]] = field(default_factory=dict)
    children: list["_Node"] = field(default_factory=list)


def _split_tokens(line: str) -> list[str]:
    """Split a CLI line on whitespace, honouring double/single quotes and
    backslash escapes. Unterminated quotes consume to end of line."""
    out: list[str] = []
    buf: list[str] = []
    quote = ""
    have = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                buf.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            else:
                buf.append(ch)
        elif ch in ('"', "'"):
            quote = ch
            have = True
        elif ch == "\\" and i + 1 < n:
            buf.append(line[i + 1])
            have = True
            i += 2
            continue
        elif ch.isspace():
            if buf or have:
                out.append("".join(buf))
                buf, have = [], False
        else:
            buf.append(ch)
            have = True
        i += 1
    if buf or have:
        out.append("".join(buf))
    return out


def _tokenize(raw: str) -> _Node:
    """Build a tree of config/edit blocks. Never raises; unbalanced input is
    closed at EOF and stray ``next``/``end`` are ignored."""
    root = _Node("root")
    stack: list[_Node] = [root]
    for line in (raw or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        toks = _split_tokens(s)
        if not toks:
            continue
        cmd = toks[0].lower()
        top = stack[-1]
        if cmd == "config" and len(toks) > 1:
            node = _Node("config", " ".join(toks[1:]))
            top.children.append(node)
            stack.append(node)
        elif cmd == "edit" and len(toks) > 1:
            if top.kind == "edit":          # missing `next`: close it
                stack.pop()
                top = stack[-1]
            node = _Node("edit", toks[1])
            top.children.append(node)
            stack.append(node)
        elif cmd == "set" and len(toks) > 1 and top.kind != "root":
            top.settings[toks[1]] = toks[2:]
        elif cmd == "append" and len(toks) > 1 and top.kind != "root":
            top.settings.setdefault(toks[1], []).extend(toks[2:])
        elif cmd == "unset" and len(toks) > 1:
            top.settings.pop(toks[1], None)
        elif cmd == "next":
            if top.kind == "edit":
                stack.pop()
        elif cmd == "end":
            if top.kind == "edit" and len(stack) > 1:
                stack.pop()
            if stack[-1].kind == "config" and len(stack) > 1:
                stack.pop()
        # anything else (banners, `show` output, ...) is ignored
    return root


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first(node: _Node, key: str, default: str = "") -> str:
    v = node.settings.get(key)
    return v[0] if v else default


def _parse_ports(proto: Proto, tokens: list[str]) -> list[PortRange]:
    """``443`` / ``80-90`` / ``443:1024-65535`` (dst[:src]) → PortRanges."""
    out: list[PortRange] = []
    for tok in tokens:
        dst = tok.split(":", 1)[0].strip()
        if not dst:
            continue
        lo_s, _, hi_s = dst.partition("-")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else lo
        except ValueError:
            continue
        out.append(port_range(proto, lo, hi))
    return out


def _union_addr(parts: list[ResolvedAddresses]) -> ResolvedAddresses:
    cidrs: list[str] = []
    feats: list[ConditionalFeature] = []
    unres: list[str] = []
    for p in parts:
        cidrs.extend(p.cidrs)
        feats.extend(p.features)
        unres.extend(p.unresolved)
    f = tuple(sorted(set(feats), key=lambda x: x.value))
    return ResolvedAddresses(
        cidrs=tuple(dict.fromkeys(cidrs)) or ANY_CIDRS,
        conditional=any(p.conditional for p in parts),
        features=f,
        unresolved=tuple(dict.fromkeys(unres)),
    )


def _union_svc(parts: list[ResolvedService]) -> ResolvedService:
    ports: list[PortRange] = []
    feats: list[ConditionalFeature] = []
    unres: list[str] = []
    for p in parts:
        ports.extend(p.ports)
        feats.extend(p.features)
        unres.extend(p.unresolved)
    return ResolvedService(
        ports=tuple(dict.fromkeys(ports)) or (PortRange.any(),),
        conditional=any(p.conditional for p in parts),
        features=tuple(sorted(set(feats), key=lambda x: x.value)),
        unresolved=tuple(dict.fromkeys(unres)),
    )


def _any_addr() -> ResolvedAddresses:
    return ResolvedAddresses(cidrs=ANY_CIDRS)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register("fortinet")
class FortinetParser(Parser):
    vendor = "fortinet"

    def parse(self, raw: str, **opts: Any) -> ParseResult:
        result = ParseResult(vendor=_VENDOR)
        try:
            tree = _tokenize(raw if isinstance(raw, str) else str(raw or ""))
            # (vdom, config node) pairs in file order; descend into wrappers.
            blocks: list[tuple[str, _Node]] = []
            self._collect(tree, "", blocks, result, multi_vdom=[False])
            self._build(blocks, result)
        except Exception as exc:  # pragma: no cover - defensive, never raise
            result.add_warning(WarningLevel.UNSUPPORTED, f"fortinet parse aborted: {exc}")
        return result

    # -- block discovery ----------------------------------------------------
    def _collect(
        self,
        node: _Node,
        vdom: str,
        out: list[tuple[str, _Node]],
        result: ParseResult,
        multi_vdom: list[bool],
    ) -> None:
        for child in node.children:
            if child.kind != "config":
                continue
            if child.name == "global":
                self._collect(child, vdom, out, result, multi_vdom)
            elif child.name == "vdom":
                multi_vdom[0] = True
                for ed in child.children:
                    if ed.kind == "edit":
                        self._collect(ed, ed.name, out, result, multi_vdom)
            else:
                out.append((vdom, child))

    # -- objects + policies -------------------------------------------------
    def _build(self, blocks: list[tuple[str, _Node]], result: ParseResult) -> None:
        tables: dict[str, ObjectTable] = {}
        defined_svc: dict[str, set[str]] = {}
        seen_unsupported: set[str] = set()

        def table(v: str) -> ObjectTable:
            if v not in tables:
                tables[v] = ObjectTable()
                defined_svc[v] = set()
            return tables[v]

        # Pass 1: objects (so policy order in the file doesn't matter).
        for vdom, blk in blocks:
            t = table(vdom)
            if blk.name == "firewall address":
                for e in blk.children:
                    self._address(t, e, result)
            elif blk.name == "firewall addrgrp":
                for e in blk.children:
                    if e.kind == "edit":
                        t.add_address(AddressObject(e.name, members=tuple(e.settings.get("member", []))))
            elif blk.name == "firewall service custom":
                for e in blk.children:
                    self._service(t, e, result)
                    defined_svc[vdom].add(e.name)
            elif blk.name == "firewall service group":
                for e in blk.children:
                    if e.kind == "edit":
                        t.add_service(ServiceObject(e.name, members=tuple(e.settings.get("member", []))))
                        defined_svc[vdom].add(e.name)

        # Seed predefined services the config did not redefine, then remap
        # group members that point at them.
        for vdom, t in tables.items():
            for name, ports in _BUILTIN_SERVICES.items():
                if name not in defined_svc[vdom]:
                    t.add_service(ServiceObject(_BUILTIN_PREFIX + name, ports=ports))
            for obj in t.services.values():
                if obj.members:
                    obj.members = tuple(self._svc_token(m, defined_svc[vdom]) for m in obj.members)

        # Pass 2: policies, in file order.
        index = 0
        for vdom, blk in blocks:
            if blk.name == "firewall policy":
                t = table(vdom)
                for e in blk.children:
                    if e.kind != "edit":
                        continue
                    self._policy(e, index, vdom, t, defined_svc[vdom], result)
                    index += 1
            elif blk.name not in (
                "firewall address", "firewall addrgrp",
                "firewall service custom", "firewall service group",
            ):
                key = f"{vdom}|{blk.name}"
                if key not in seen_unsupported:
                    seen_unsupported.add(key)
                    result.add_warning(
                        WarningLevel.UNSUPPORTED,
                        f"skipped unsupported config block: {blk.name}",
                        blk.name,
                    )

    @staticmethod
    def _svc_token(tok: str, defined: set[str]) -> str:
        if tok in _BUILTIN_SERVICES and tok not in defined:
            return _BUILTIN_PREFIX + tok
        return tok

    def _address(self, t: ObjectTable, e: _Node, result: ParseResult) -> None:
        if e.kind != "edit" or e.name.lower() == "all":
            return  # built-in "all" means any; base resolves it as a literal
        typ = _first(e, "type", "ipmask").lower()
        name = e.name
        if typ == "fqdn":
            t.add_address(AddressObject(name, conditional=True, feature=ConditionalFeature.FQDN))
        elif typ == "wildcard-fqdn":
            t.add_address(AddressObject(name, conditional=True, feature=ConditionalFeature.FQDN))
        elif typ == "geography":
            t.add_address(AddressObject(name, conditional=True, feature=ConditionalFeature.GEO))
        elif typ == "iprange":
            lo, hi = _first(e, "start-ip"), _first(e, "end-ip")
            cidrs = normalize_cidrs(f"{lo}-{hi}") if lo and hi else None
            self._addr_or_unresolved(t, name, cidrs, f"iprange {lo}-{hi}", result)
        elif typ == "ipmask":
            sub = e.settings.get("subnet", [])
            cidrs = normalize_cidrs(" ".join(sub)) if sub else None
            self._addr_or_unresolved(t, name, cidrs, f"subnet {' '.join(sub)}", result)
        elif typ == "dynamic":
            t.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.DYNAMIC_ADDRESS_GROUP))
        else:  # mac, interface-subnet, route-tag, ...
            t.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
            result.add_warning(
                WarningLevel.UNSUPPORTED, f"address type {typ!r} not modelled", name)

    @staticmethod
    def _addr_or_unresolved(
        t: ObjectTable, name: str, cidrs: Optional[list[str]], what: str, result: ParseResult
    ) -> None:
        if cidrs is None:
            t.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
            result.add_warning(WarningLevel.UNRESOLVED, f"unparseable address ({what})", name)
        else:
            t.add_address(AddressObject(name, cidrs=tuple(cidrs)))

    def _service(self, t: ObjectTable, e: _Node, result: ParseResult) -> None:
        if e.kind != "edit":
            return
        protocol = _first(e, "protocol", "TCP/UDP/SCTP").upper()
        ports: list[PortRange] = []
        if protocol in ("ICMP", "ICMP6"):
            ports.append(PortRange(Proto.ICMP, 0, 65535))
        elif protocol == "IP":
            num = _first(e, "protocol-number")
            ports.append(PortRange(proto_from(num) if num else Proto.ANY, 0, 65535))
        else:
            ports += _parse_ports(Proto.TCP, e.settings.get("tcp-portrange", []))
            ports += _parse_ports(Proto.UDP, e.settings.get("udp-portrange", []))
            if "sctp-portrange" in e.settings:
                result.add_warning(WarningLevel.INFO, "SCTP ports widened to any protocol", e.name)
                ports.append(PortRange(Proto.ANY, 0, 65535))
            if not ports:
                result.add_warning(
                    WarningLevel.INFO, "service has no port ranges; treated as any", e.name)
                ports.append(PortRange.any())
        t.add_service(ServiceObject(e.name, ports=tuple(dict.fromkeys(ports))))

    # -- policies -------------------------------------------------------------
    def _policy(
        self,
        e: _Node,
        index: int,
        vdom: str,
        t: ObjectTable,
        defined_svc: set[str],
        result: ParseResult,
    ) -> None:
        pid = e.name
        prefix = f"{vdom}:" if vdom else ""
        if _first(e, "status", "enable").lower() == "disable":
            result.add_warning(WarningLevel.INFO, "disabled policy skipped", f"policy {pid}")
            return

        srcintf = e.settings.get("srcintf") or ["any"]
        dstintf = e.settings.get("dstintf") or ["any"]
        src_zone, dst_zone = "+".join(srcintf), "+".join(dstintf)
        rsid = f"{prefix}{src_zone}>{dst_zone}"
        ref = f"policy {pid}" + (f" ({_first(e, 'name')})" if _first(e, "name") else "")

        action_s = _first(e, "action", "deny").lower()
        action = Action.ALLOW if action_s in ("accept", "ipsec") else Action.DENY
        if action_s == "ipsec":
            result.add_warning(WarningLevel.INFO, "ipsec action modelled as accept", ref)

        extra_feat: Optional[ConditionalFeature] = None

        def flag(f: ConditionalFeature) -> None:
            nonlocal extra_feat
            if extra_feat is None:
                extra_feat = f

        s = e.settings
        internet_svc_dst = _first(e, "internet-service", "disable").lower() == "enable"
        internet_svc_src = _first(e, "internet-service-src", "disable").lower() == "enable"
        if internet_svc_dst or internet_svc_src:
            flag(ConditionalFeature.EXTERNAL_DYNAMIC_LIST)
        if s.get("users") or s.get("groups") or s.get("fsso-groups"):
            flag(ConditionalFeature.USER_ID)
        if s.get("application") or s.get("app-category") or s.get("application-list"):
            flag(ConditionalFeature.APP_ID)

        def side(key: str, neg_key: str) -> ResolvedAddresses:
            toks = s.get(key, [])
            if _first(e, neg_key, "disable").lower() == "enable":
                flag(ConditionalFeature.UNRESOLVED)
                result.add_warning(
                    WarningLevel.INFO, f"{neg_key} enabled; side widened to any", ref)
                return _any_addr()
            if not toks:
                return _any_addr()
            return _union_addr([t.resolve_addresses(tok) for tok in toks])

        src = side("srcaddr", "srcaddr-negate")
        dst = side("dstaddr", "dstaddr-negate")

        svc_toks = s.get("service", [])
        if _first(e, "service-negate", "disable").lower() == "enable":
            flag(ConditionalFeature.UNRESOLVED)
            result.add_warning(WarningLevel.INFO, "service-negate enabled; widened to any", ref)
            svc = ResolvedService(ports=(PortRange.any(),))
        elif not svc_toks:
            svc = ResolvedService(ports=(PortRange.any(),))
        else:
            svc = _union_svc([
                t.resolve_service(self._svc_token(tok, defined_svc)) for tok in svc_toks
            ])

        sched = _first(e, "schedule")
        if sched and sched.lower() != "always":
            result.add_warning(
                WarningLevel.INFO, f"schedule {sched!r} not evaluated; rule treated as always on", ref)

        rule, warns = build_rule(
            rule_id=f"{_VENDOR}:{rsid}:{pid}",
            action=action,
            order=index,
            src=src,
            dst=dst,
            service=svc,
            vendor=_VENDOR,
            raw_ref=ref,
            extra_conditional=extra_feat is not None,
            extra_feature=extra_feat,
        )
        result.warnings.extend(warns)

        rs = result.rulesets.get(rsid)
        if rs is None:
            rs = RuleSet(id=rsid, rules=[], default_action=Action.DENY, vendor=_VENDOR)
            result.rulesets[rsid] = rs
            result.bindings.append(
                RuleSetBinding(ruleset_id=rsid, src_zone=src_zone, dst_zone=dst_zone))
        rs.rules.append(rule)


def _build_table_for_tests(raw: str) -> ObjectTable:  # pragma: no cover - test aid
    """Object table (addresses + services) built from ``raw``; exposed so tests
    can check object resolution independent of policies."""
    p = FortinetParser()
    blocks: list[tuple[str, _Node]] = []
    res = ParseResult(vendor=_VENDOR)
    p._collect(_tokenize(raw), "", blocks, res, [False])
    t = ObjectTable()
    for _v, blk in blocks:
        if blk.name == "firewall address":
            for e in blk.children:
                p._address(t, e, res)
        elif blk.name == "firewall addrgrp":
            for e in blk.children:
                t.add_address(AddressObject(e.name, members=tuple(e.settings.get("member", []))))
        elif blk.name == "firewall service custom":
            for e in blk.children:
                p._service(t, e, res)
        elif blk.name == "firewall service group":
            for e in blk.children:
                t.add_service(ServiceObject(e.name, members=tuple(e.settings.get("member", []))))
    return t
