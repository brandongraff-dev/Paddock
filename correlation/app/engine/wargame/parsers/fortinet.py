"""Fortinet FortiGate (FortiOS CLI) parser.

Turns the nested ``config ... edit ... set ... next ... end`` text of a
FortiOS backup into vendor-neutral :class:`~app.engine.wargame.model.RuleSet`
objects. Defensive only: it reads config, nothing is sent anywhere.

Modelling choices
-----------------
* **Rule sets are keyed by interface pair**: ``f"{srcintf}>{dstintf}"``. A
  policy naming several interfaces is placed in *each* single-interface
  pair set (cartesian product), and a policy on ``any`` is also placed in
  every concrete pair set it covers, in sequence position, because on the
  box it governs those flows too. In a multi-VDOM backup the key is prefixed
  ``<vdom>:``. Each rule set carries ``default_action=DENY`` (FortiOS
  implicit deny) and a :class:`RuleSetBinding` with ``src_zone``/``dst_zone``.
* **Order is sequence order.** FortiOS evaluates policies top to bottom as
  *listed*, not by policy id, so ``Rule.order`` is the policy's appearance
  index; the policy id lives in ``raw_ref`` / the rule id.
* **Address families.** ``srcaddr``/``dstaddr`` are IPv4 fields (``all`` is
  ``0.0.0.0/0``); ``srcaddr6``/``dstaddr6`` and ``config firewall policy6``
  are IPv6 (``all`` is ``::/0``). A rule's sides are the union of both.
* **Multiple srcaddr/dstaddr/service tokens** are each resolved through the
  :class:`ObjectTable` and UNIONed.
* A missing ``set action`` means DENY (FortiOS default). ``set status
  disable`` skips the policy entirely (INFO warning).
* **Negation** (``srcaddr-negate`` / ``dstaddr-negate``) is modelled exactly
  as the complement within the field's family when the side resolves
  cleanly; otherwise it widens to any and the rule is conditional.
  ``service-negate`` likewise (complement of the port set) when exact.
* The honesty rule: FQDN / geography / dynamic / wildcard address objects,
  user or group match, application match, Internet-Service objects,
  non-``always`` schedules, VIPs (destination NAT), source-port / ICMP-type /
  protocol-number services and deny policies that might not apply to VIP
  traffic (``match-vip``) make a rule ``conditional``.
* Predefined FortiGate services whose real definition differs from base's
  named-service table (DNS, NTP, SIP, SNMP, PING, ALL_*, ...) are seeded as
  ``FGT:<name>`` objects and policy tokens are remapped, unless the config
  redefines them.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Optional

from ..model import Action, PortRange, Proto, Rule, RuleSet
from .base import (
    ANY4_CIDRS,
    ANY6_CIDRS,
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
    complement_cidrs,
    exclude_cidrs,
    filter_family,
    normalize_cidrs,
    port_range,
    proto_from,
    proto_is_exact,
    register,
)

_VENDOR = "fortinet"


def _tcp(*rngs: tuple[int, int]) -> tuple[PortRange, ...]:
    return tuple(port_range(Proto.TCP, a, b) for a, b in rngs)


def _udp(*rngs: tuple[int, int]) -> tuple[PortRange, ...]:
    return tuple(port_range(Proto.UDP, a, b) for a, b in rngs)


def _both(*rngs: tuple[int, int]) -> tuple[PortRange, ...]:
    return _tcp(*rngs) + _udp(*rngs)


_ICMP_ALL = (PortRange(Proto.ICMP, 0, 65535),)

#: Predefined services where base.service_from_name would be wrong/missing.
#: (FortiOS 6.x/7.x defaults.)
_BUILTIN_SERVICES: dict[str, tuple[PortRange, ...]] = {
    "DNS": _both((53, 53)),
    "NTP": _both((123, 123)),
    "SIP": _both((5060, 5060)),
    "SNMP": _both((161, 162)),
    "KERBEROS": _both((88, 88)),
    "SAMBA": _tcp((139, 139)),
    "MS-SQL": _tcp((1433, 1434)),
    "IKE": _udp((500, 500), (4500, 4500)),
    "DHCP": _udp((67, 68)),
    "NFS": _both((111, 111), (2049, 2049)),
    "ONC-RPC": _both((111, 111)),
    "DCE-RPC": _both((135, 135)),
    "RADIUS": _udp((1812, 1813)),
    "TRACEROUTE": _udp((33434, 33535)),
    "IMAPS": _tcp((993, 993)),
    "POP3S": _tcp((995, 995)),
    "SMTPS": _tcp((465, 465)),
    "L2TP": _both((1701, 1701)),
    "BGP": _tcp((179, 179)),
    "SYSLOG": _udp((514, 514)),
    "PING": _ICMP_ALL,
    "ALL_ICMP": _ICMP_ALL,
    "ALL_ICMP6": _ICMP_ALL,
    "ALL_TCP": _tcp((0, 65535)),
    "ALL_UDP": _udp((0, 65535)),
}
#: Predefined protocol-only services the model can only widen to ANY.
_BUILTIN_PROTO_ONLY = ("GRE", "ESP", "AH", "OSPF")
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


def _enabled(node: _Node, key: str) -> bool:
    return _first(node, key, "disable").lower() == "enable"


def _int_range(spec: str) -> Optional[tuple[int, int]]:
    lo_s, sep, hi_s = spec.strip().partition("-")
    try:
        lo = int(lo_s)
        hi = int(hi_s) if sep else lo
    except ValueError:
        return None
    if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
        return None
    return lo, hi


def _parse_ports(
    proto: Proto, tokens: list[str]
) -> tuple[list[PortRange], bool, list[str]]:
    """``443`` / ``80-90`` / ``443:1024-65535`` (``dst[:src]``) and several
    ranges per line → (dst PortRanges, source-port-restricted?, bad tokens).

    A malformed token widens to the whole protocol (never silently dropped:
    that would narrow an accept). A source-port restriction is not modelled;
    the caller flags the service conditional when one is present."""
    out: list[PortRange] = []
    src_restricted = False
    bad: list[str] = []
    for tok in tokens:
        dst, sep, src = tok.partition(":")
        if not dst.strip():
            bad.append(tok)
            out.append(port_range(proto, 0, 65535))
            continue
        rng = _int_range(dst)
        if rng is None:
            bad.append(tok)
            out.append(port_range(proto, 0, 65535))
            continue
        out.append(port_range(proto, rng[0], rng[1]))
        if sep:
            srng = _int_range(src)
            if srng is None or not (min(srng) <= 1 and max(srng) == 65535):
                src_restricted = True
    return out, src_restricted, bad


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
        cidrs=tuple(dict.fromkeys(cidrs)),
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


_ADDR_BLOCKS = {
    "firewall address": 4, "firewall address6": 6,
    "firewall addrgrp": 4, "firewall addrgrp6": 6,
    "firewall vip": 4, "firewall vip6": 6,
    "firewall vipgrp": 4, "firewall vipgrp6": 6,
}
_POLICY_BLOCKS = ("firewall policy", "firewall policy6", "firewall security-policy")
_HANDLED_BLOCKS = frozenset(
    list(_ADDR_BLOCKS) + list(_POLICY_BLOCKS)
    + ["firewall service custom", "firewall service group"]
)
#: Blocks that can *permit* traffic the parser does not model.
_PERMITTING_BLOCKS = frozenset({
    "firewall proxy-policy", "firewall multicast-policy",
    "firewall multicast-policy6", "firewall policy46", "firewall policy64",
    "firewall interface-policy", "firewall consolidated policy",
})


@dataclass
class _Entry:
    vdom: str
    kind: str                     # "" | "security-policy:"
    rule: Rule
    pairs: list[tuple[str, str]] = field(default_factory=list)


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
        self._t4: dict[str, ObjectTable] = {}
        self._t6: dict[str, ObjectTable] = {}
        self._defined_svc: dict[str, set[str]] = {}
        self._has_vip: dict[str, bool] = {}
        excludes: list[tuple[ObjectTable, str, tuple[str, ...], tuple[str, ...]]] = []
        seen_unsupported: set[str] = set()

        # Pass 1: objects (so policy order in the file doesn't matter).
        for vdom, blk in blocks:
            t4, t6 = self._tables(vdom)
            fam = _ADDR_BLOCKS.get(blk.name)
            t = t4 if fam != 6 else t6
            edits = [e for e in blk.children if e.kind == "edit"]
            if blk.name in ("firewall address", "firewall address6"):
                for e in edits:
                    self._address(t, e, result, fam or 4)
            elif blk.name in ("firewall addrgrp", "firewall addrgrp6",
                              "firewall vipgrp", "firewall vipgrp6"):
                for e in edits:
                    members = tuple(e.settings.get("member", []))
                    t.add_address(AddressObject(e.name, members=members))
                    if _enabled(e, "exclude") and e.settings.get("exclude-member"):
                        excludes.append((t, e.name, members,
                                         tuple(e.settings["exclude-member"])))
            elif blk.name in ("firewall vip", "firewall vip6"):
                for e in edits:
                    self._vip(t, e, result, fam or 4)
                    self._has_vip[vdom] = True
            elif blk.name == "firewall service custom":
                for e in edits:
                    self._service(t4, e, result)
                    self._defined_svc[vdom].add(e.name)
            elif blk.name == "firewall service group":
                for e in edits:
                    t4.add_service(ServiceObject(e.name, members=tuple(e.settings.get("member", []))))
                    self._defined_svc[vdom].add(e.name)

        # Seed predefined services the config did not redefine, then remap
        # group members that point at them.
        for vdom, t in self._t4.items():
            defined = self._defined_svc[vdom]
            for name, ports in _BUILTIN_SERVICES.items():
                if name not in defined:
                    t.add_service(ServiceObject(_BUILTIN_PREFIX + name, ports=ports))
            for name in _BUILTIN_PROTO_ONLY:
                if name not in defined:
                    t.add_service(ServiceObject(
                        _BUILTIN_PREFIX + name, ports=(PortRange.any(),),
                        conditional=True, feature=ConditionalFeature.PARTIAL_MATCH))
            for obj in t.services.values():
                if obj.members:
                    obj.members = tuple(self._svc_token(m, defined) for m in obj.members)

        self._apply_excludes(excludes, result)

        # Pass 2: policies, in file (sequence) order.
        entries: list[_Entry] = []
        index = 0
        for vdom, blk in blocks:
            if blk.name in _POLICY_BLOCKS:
                for e in blk.children:
                    if e.kind != "edit":
                        continue
                    entries.extend(self._policy_guarded(e, index, vdom, blk.name, result))
                    index += 1
            elif blk.name not in _HANDLED_BLOCKS:
                key = f"{vdom}|{blk.name}"
                if key not in seen_unsupported:
                    seen_unsupported.add(key)
                    msg = f"skipped unsupported config block: {blk.name}"
                    if blk.name in _PERMITTING_BLOCKS:
                        msg += ("; it can permit traffic this model does not "
                                "contain, so a closed verdict here is not proof")
                    result.add_warning(WarningLevel.UNSUPPORTED, msg, blk.name)

        self._emit(entries, result)

    def _tables(self, vdom: str) -> tuple[ObjectTable, ObjectTable]:
        if vdom not in self._t4:
            self._t4[vdom] = ObjectTable()
            self._t6[vdom] = ObjectTable()
            self._defined_svc[vdom] = set()
        return self._t4[vdom], self._t6[vdom]

    @staticmethod
    def _svc_token(tok: str, defined: set[str]) -> str:
        if (tok in _BUILTIN_SERVICES or tok in _BUILTIN_PROTO_ONLY) and tok not in defined:
            return _BUILTIN_PREFIX + tok
        return tok

    # -- address objects ------------------------------------------------------
    def _address(self, t: ObjectTable, e: _Node, result: ParseResult, fam: int) -> None:
        if e.name.lower() == "all" and not e.settings.get("subnet") \
                and not e.settings.get("ip6"):
            return  # built-in "all" means any; resolved as a literal per family
        default_type = "ipmask" if fam == 4 else "ipprefix"
        typ = _first(e, "type", default_type).lower()
        name = e.name
        if typ in ("fqdn", "wildcard-fqdn"):
            t.add_address(AddressObject(name, conditional=True, feature=ConditionalFeature.FQDN))
        elif typ == "geography":
            t.add_address(AddressObject(name, conditional=True, feature=ConditionalFeature.GEO))
        elif typ == "iprange":
            lo, hi = _first(e, "start-ip"), _first(e, "end-ip")
            cidrs = normalize_cidrs(f"{lo}-{hi}") if lo and hi else None
            self._addr_or_unresolved(t, name, cidrs, f"iprange {lo}-{hi}", result)
        elif typ == "ipmask":
            sub = e.settings.get("subnet", [])
            # FortiOS default subnet is 0.0.0.0 0.0.0.0 (i.e. all)
            spec = " ".join(sub) if sub else "0.0.0.0 0.0.0.0"
            cidrs = normalize_cidrs(spec, mask_style="netmask")
            self._addr_or_unresolved(t, name, cidrs, f"subnet {spec}", result)
        elif typ == "ipprefix":
            ip6 = _first(e, "ip6", "::/0")
            cidrs = normalize_cidrs(ip6)
            self._addr_or_unresolved(t, name, cidrs, f"ip6 {ip6}", result)
        elif typ == "dynamic":
            t.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.DYNAMIC_ADDRESS_GROUP))
        else:  # wildcard, mac, interface-subnet, route-tag, template, ...
            t.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"address type {typ!r} not modelled; treated as conditional any", name)

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

    def _vip(self, t: ObjectTable, e: _Node, result: ParseResult, fam: int) -> None:
        """A VIP is destination NAT: a policy naming it matches traffic to the
        external address that is delivered to the mapped one. Both are kept
        and the object is conditional (NAT)."""
        cidrs: list[str] = []
        ok = True
        specs = list(e.settings.get("extip", [])) + list(e.settings.get("mappedip", []))
        for child in e.children:                     # config realservers
            for rs in child.children:
                specs.extend(rs.settings.get("ip", []))
        for spec in specs:
            got = normalize_cidrs(spec)
            if got is None:
                ok = False
            else:
                cidrs.extend(got)
        if not ok or not cidrs:
            result.add_warning(
                WarningLevel.UNRESOLVED,
                "VIP addresses not fully readable; treated as conditional any", e.name)
            t.add_address(AddressObject(
                e.name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
            return
        t.add_address(AddressObject(
            e.name, cidrs=tuple(dict.fromkeys(cidrs)), conditional=True,
            feature=ConditionalFeature.NAT))

    def _apply_excludes(
        self,
        excludes: list[tuple[ObjectTable, str, tuple[str, ...], tuple[str, ...]]],
        result: ParseResult,
    ) -> None:
        """``set exclude enable`` groups are members MINUS exclude-members.
        Exact when both sides resolve cleanly; otherwise the group stays the
        (superset) member list and is conditional, so it can never narrow an
        accept or wrongly broaden a deny."""
        originals = {(id(t), n): m for t, n, m, _x in excludes}
        for _ in range(len(excludes) + 1):           # settle nested excludes
            for t, name, members, minus in excludes:
                tmp = ObjectTable()
                tmp.addresses = dict(t.addresses)
                tmp.addresses[name] = AddressObject(name, members=originals[(id(t), name)])
                inc = tmp.resolve_addresses(name)
                exc = _union_addr([tmp.resolve_addresses(x) for x in minus])
                if inc.conditional or exc.conditional:
                    t.add_address(AddressObject(
                        name, members=members, conditional=True,
                        feature=ConditionalFeature.UNRESOLVED))
                    continue
                try:
                    diff = exclude_cidrs(inc.cidrs, exc.cidrs)
                except ValueError:
                    t.add_address(AddressObject(
                        name, members=members, conditional=True,
                        feature=ConditionalFeature.UNRESOLVED))
                    continue
                t.add_address(AddressObject(name, cidrs=tuple(diff)))
        for t, name, _m, _x in excludes:
            if t.addresses[name].conditional:
                result.add_warning(
                    WarningLevel.UNRESOLVED,
                    "address group exclusion could not be computed exactly; "
                    "group treated as conditional", name)

    # -- services -------------------------------------------------------------
    def _service(self, t: ObjectTable, e: _Node, result: ParseResult) -> None:
        protocol = _first(e, "protocol", "TCP/UDP/SCTP").upper()
        ports: list[PortRange] = []
        partial = False
        if protocol in ("ICMP", "ICMP6"):
            ports.append(PortRange(Proto.ICMP, 0, 65535))
            if e.settings.get("icmptype") or e.settings.get("icmpcode"):
                partial = True
                result.add_warning(
                    WarningLevel.INFO, "ICMP type/code not modelled; widened (conditional)", e.name)
        elif protocol == "IP":
            num = _first(e, "protocol-number", "0")
            if num == "0":
                ports.append(PortRange.any())        # protocol-number 0 = all
            else:
                ports.append(PortRange(proto_from(num), 0, 65535))
                if not proto_is_exact(num):
                    partial = True
                    result.add_warning(
                        WarningLevel.INFO,
                        f"IP protocol {num} not modelled; widened to any (conditional)", e.name)
        elif protocol == "ALL":
            ports.append(PortRange.any())
        else:
            bad: list[str] = []
            for key, proto in (("tcp-portrange", Proto.TCP), ("udp-portrange", Proto.UDP)):
                got, src_r, b = _parse_ports(proto, e.settings.get(key, []))
                ports += got
                partial = partial or src_r
                bad += b
            if "sctp-portrange" in e.settings:
                result.add_warning(
                    WarningLevel.INFO, "SCTP ports widened to any protocol (conditional)", e.name)
                ports.append(PortRange(Proto.ANY, 0, 65535))
                partial = True
            if bad:
                partial = True
                result.add_warning(
                    WarningLevel.UNRESOLVED,
                    f"unparseable port range(s) {bad}; widened (conditional)", e.name)
            elif any(":" in tok for k in ("tcp-portrange", "udp-portrange")
                     for tok in e.settings.get(k, [])) and partial:
                result.add_warning(
                    WarningLevel.INFO, "source-port range not modelled; widened (conditional)",
                    e.name)
            if not ports:
                result.add_warning(
                    WarningLevel.INFO,
                    "service has no port ranges; treated as any (conditional)", e.name)
                ports.append(PortRange.any())
                partial = True
        if e.settings.get("iprange") or e.settings.get("fqdn"):
            partial = True
            result.add_warning(
                WarningLevel.INFO,
                "service destination address restriction not modelled; widened (conditional)",
                e.name)
        t.add_service(ServiceObject(
            e.name, ports=tuple(dict.fromkeys(ports)), conditional=partial,
            feature=ConditionalFeature.PARTIAL_MATCH if partial else None))

    # -- policies -------------------------------------------------------------
    def _policy_guarded(
        self, e: _Node, index: int, vdom: str, block: str, result: ParseResult,
    ) -> list[_Entry]:
        try:
            return self._policy(e, index, vdom, block, result)
        except Exception as exc:  # never let one policy sink the parse
            ref = f"policy {e.name}"
            if _first(e, "action", "deny").lower() == "deny":
                result.add_warning(
                    WarningLevel.UNSUPPORTED,
                    f"deny policy could not be parsed ({exc!r}); skipped", ref)
                return []
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"policy could not be parsed ({exc!r}); kept as a conditional accept-any", ref)
            any_a = ResolvedAddresses(ANY_CIDRS, True, (ConditionalFeature.UNRESOLVED,))
            rule, warns = build_rule(
                rule_id=f"{_VENDOR}:{vdom + ':' if vdom else ''}{e.name}",
                action=Action.ALLOW, order=index, src=any_a, dst=any_a,
                service=ResolvedService((PortRange.any(),)), vendor=_VENDOR, raw_ref=ref)
            result.warnings.extend(warns)
            src = e.settings.get("srcintf") or ["any"]
            dst = e.settings.get("dstintf") or ["any"]
            return [_Entry(vdom, "", rule, [(a, b) for a in src for b in dst])]

    def _side(
        self,
        e: _Node,
        vdom: str,
        keys4: tuple[str, ...],
        keys6: tuple[str, ...],
        neg_key: str,
        ref: str,
        result: ParseResult,
    ) -> Optional[ResolvedAddresses]:
        """Resolve one side; ``None`` means the side matches nothing."""
        t4, t6 = self._tables(vdom)
        toks4 = next((e.settings[k] for k in keys4 if e.settings.get(k)), [])
        toks6 = next((e.settings[k] for k in keys6 if e.settings.get(k)), [])
        if not toks4 and not toks6:
            result.add_warning(
                WarningLevel.UNRESOLVED, f"no {neg_key.split('-')[0]} set; widened to any", ref)
            return ResolvedAddresses(ANY_CIDRS, True, (ConditionalFeature.UNRESOLVED,))
        parts: list[tuple[int, ResolvedAddresses]] = []
        for fam, toks, t in ((4, toks4, t4), (6, toks6, t6)):
            if not toks:
                continue
            r = _union_addr([t.resolve_addresses(tok) for tok in toks])
            # a v4 field only ever matches IPv4 (and vice versa)
            parts.append((fam, replace(r, cidrs=filter_family(r.cidrs, fam))))
        side = _union_addr([p for _f, p in parts])
        if not _enabled(e, neg_key):
            return side if side.cidrs else None
        if side.conditional:
            result.add_warning(
                WarningLevel.INFO,
                f"{neg_key} over a conditional address; side widened to any", ref)
            fams = tuple(f for f, _p in parts)
            cidrs = tuple(c for f, c in ((4, ANY4_CIDRS[0]), (6, ANY6_CIDRS[0])) if f in fams)
            return ResolvedAddresses(
                cidrs, True, tuple(sorted(set(side.features) | {ConditionalFeature.UNRESOLVED},
                                          key=lambda f: f.value)), side.unresolved)
        comp: list[str] = []
        for fam, p in parts:
            comp.extend(complement_cidrs(p.cidrs, (fam,)))
        result.add_warning(
            WarningLevel.INFO, f"{neg_key} modelled as the exact complement", ref)
        return ResolvedAddresses(tuple(comp)) if comp else None

    def _policy(
        self, e: _Node, index: int, vdom: str, block: str, result: ParseResult,
    ) -> list[_Entry]:
        pid = e.name
        prefix = f"{vdom}:" if vdom else ""
        kind = "security-policy:" if block == "firewall security-policy" else ""
        id_mid = {"firewall policy6": "policy6:", "firewall security-policy":
                  "security-policy:"}.get(block, "")
        ref = f"{id_mid}policy {pid}" + (f" ({_first(e, 'name')})" if _first(e, "name") else "")
        if _first(e, "status", "enable").lower() == "disable":
            result.add_warning(WarningLevel.INFO, "disabled policy skipped", ref)
            return []

        srcintf = e.settings.get("srcintf") or ["any"]
        dstintf = e.settings.get("dstintf") or ["any"]

        feats: list[ConditionalFeature] = []
        action_s = _first(e, "action", "deny").lower()
        if action_s in ("accept", "ipsec"):
            action = Action.ALLOW
            if action_s == "ipsec":
                result.add_warning(WarningLevel.INFO, "ipsec action modelled as accept", ref)
        elif action_s == "deny":
            action = Action.DENY
        else:
            action = Action.ALLOW
            feats.append(ConditionalFeature.UNRESOLVED)
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"unknown action {action_s!r}; modelled as a conditional accept", ref)

        s = e.settings
        if _enabled(e, "internet-service") or _enabled(e, "internet-service-src") \
                or s.get("internet-service-name") or s.get("internet-service-src-name"):
            feats.append(ConditionalFeature.EXTERNAL_DYNAMIC_LIST)
        if s.get("users") or s.get("groups") or s.get("fsso-groups"):
            feats.append(ConditionalFeature.USER_ID)
        if s.get("application") or s.get("app-category") or s.get("application-list") \
                or s.get("app-group"):
            feats.append(ConditionalFeature.APP_ID)
        sched = _first(e, "schedule")
        if sched and sched.lower() != "always":
            feats.append(ConditionalFeature.SCHEDULE)
            result.add_warning(
                WarningLevel.INFO, f"schedule {sched!r} not evaluated; rule is conditional", ref)
        if kind:
            feats.append(ConditionalFeature.PARTIAL_MATCH)
            result.add_warning(
                WarningLevel.INFO,
                "NGFW policy-based security-policy is evaluated together with the "
                "firewall policy; modelled as a separate conditional rule set", ref)
        if action is Action.DENY and self._has_vip.get(vdom) and not _enabled(e, "match-vip"):
            # FortiOS: a deny policy does not match VIP (DNAT) traffic unless
            # match-vip is enabled, so it may not stop flows to a VIP.
            feats.append(ConditionalFeature.NAT)
            result.add_warning(
                WarningLevel.INFO,
                "deny policy without match-vip does not apply to VIP traffic", ref)

        if block == "firewall policy6":       # pre-6.4 IPv6 policy table
            src_k4 = dst_k4 = ()
            src_k6, dst_k6 = ("srcaddr", "srcaddr6"), ("dstaddr", "dstaddr6")
        else:
            src_k4, dst_k4 = ("srcaddr", "srcaddr4"), ("dstaddr", "dstaddr4")
            src_k6, dst_k6 = ("srcaddr6",), ("dstaddr6",)
        src = self._side(e, vdom, src_k4, src_k6, "srcaddr-negate", ref, result)
        dst = self._side(e, vdom, dst_k4, dst_k6, "dstaddr-negate", ref, result)
        if src is None or dst is None:
            result.add_warning(
                WarningLevel.INFO, "negated address matches nothing; policy never matches", ref)
            return []

        t4, _t6 = self._tables(vdom)
        svc_toks = s.get("service", [])
        if _enabled(e, "service-negate"):
            feats.append(ConditionalFeature.PARTIAL_MATCH)
            result.add_warning(
                WarningLevel.INFO, "service-negate enabled; widened to any (conditional)", ref)
            svc = ResolvedService(ports=(PortRange.any(),))
        elif not svc_toks:
            if ConditionalFeature.EXTERNAL_DYNAMIC_LIST not in feats:
                feats.append(ConditionalFeature.UNRESOLVED)
                result.add_warning(
                    WarningLevel.UNRESOLVED, "no service set; widened to any", ref)
            svc = ResolvedService(ports=(PortRange.any(),))
        else:
            defined = self._defined_svc[vdom]
            svc = _union_svc([
                t4.resolve_service(self._svc_token(tok, defined)) for tok in svc_toks
            ])

        rid = f"{_VENDOR}:{prefix}{id_mid}{pid}"
        rule, warns = build_rule(
            rule_id=rid, action=action, order=index, src=src, dst=dst,
            service=svc, vendor=_VENDOR, raw_ref=ref,
            extra_conditional=bool(feats),
            extra_features=tuple(dict.fromkeys(feats)),
        )
        result.warnings.extend(warns)
        pairs = list(dict.fromkeys((a, b) for a in srcintf for b in dstintf))
        out = [_Entry(vdom, kind, rule, pairs)]
        if svc_toks and svc.conditional and not (feats or src.conditional or dst.conditional):
            # Only some services are conditional (e.g. one has a source-port
            # range). Splitting by service is exact under first match (same
            # action, same addresses), and keeps the clean part provable.
            defined = self._defined_svc[vdom]
            parts = [t4.resolve_service(self._svc_token(tok, defined)) for tok in svc_toks]
            clean = [p for p in parts if not p.conditional]
            if clean:
                c_rule, _ = build_rule(
                    rule_id=rid, action=action, order=index, src=src, dst=dst,
                    service=_union_svc(clean), vendor=_VENDOR, raw_ref=ref)
                p_rule, _ = build_rule(
                    rule_id=f"{rid}#conditional", action=action, order=index,
                    src=src, dst=dst,
                    service=_union_svc([p for p in parts if p.conditional]),
                    vendor=_VENDOR, raw_ref=ref)
                out = [_Entry(vdom, kind, c_rule, pairs), _Entry(vdom, kind, p_rule, pairs)]
        return out

    # -- rule sets ------------------------------------------------------------
    def _emit(self, entries: list[_Entry], result: ParseResult) -> None:
        """One rule set per concrete interface pair. A policy on several
        interfaces lands in each pair; a policy on ``any`` also lands in
        every pair it covers, keeping sequence order (first match)."""
        groups: dict[tuple[str, str], list[_Entry]] = {}
        for ent in entries:
            groups.setdefault((ent.vdom, ent.kind), []).append(ent)
        for (vdom, kind), ents in groups.items():
            prefix = f"{vdom}:" if vdom else ""
            keys: list[tuple[str, str]] = []
            for ent in ents:
                for p in ent.pairs:
                    if p not in keys:
                        keys.append(p)
            for kf, kt in keys:
                rules = [
                    ent.rule for ent in sorted(ents, key=lambda x: (x.rule.order, x.rule.id))
                    if any((rf == kf or rf.lower() == "any")
                           and (rt == kt or rt.lower() == "any")
                           for rf, rt in ent.pairs)
                ]
                rsid = f"{prefix}{kind}{kf}>{kt}"
                result.rulesets[rsid] = RuleSet(
                    id=rsid, rules=rules, default_action=Action.DENY, vendor=_VENDOR)
                result.bindings.append(
                    RuleSetBinding(ruleset_id=rsid, src_zone=kf, dst_zone=kt))


def _build_table_for_tests(raw: str) -> ObjectTable:  # pragma: no cover - test aid
    """Object table (addresses + services) built from ``raw``; exposed so tests
    can check object resolution independent of policies."""
    p = FortinetParser()
    blocks: list[tuple[str, _Node]] = []
    res = ParseResult(vendor=_VENDOR)
    p._collect(_tokenize(raw), "", blocks, res, [False])
    p._build(blocks, res)
    return p._t4.get("", ObjectTable())
