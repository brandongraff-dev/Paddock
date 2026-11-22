"""Cisco ASA config -> vendor-neutral RuleSet.

Defensive and static: this reads an ASA running-config and produces the rule
model the solver consumes. Nothing is sent or executed.

Supported constructs
* ``object network`` (host / subnet / range / fqdn)
* ``object-group network`` (network-object, group-object, nested groups)
* ``object service`` and ``object-group service`` (port-object,
  service-object, group-object) and a minimal ``object-group protocol``
* ``access-list NAME [line N] extended permit|deny PROTO SRC DST [SVC]``
* ``access-group NAME in|out interface IFACE`` (and ``global``)

Honesty rule. Anything we cannot model exactly is over-approximated toward
"reachable" and flagged ``conditional`` (unknown objects, unknown protocols,
time-ranges, FQDN objects), never silently dropped. Source-port matches and
ICMP types are not modelled; the rule is widened and an INFO warning is
raised.

Two passes: objects first (so ACLs may reference objects defined later), then
ACLs and bindings. Unknown lines yield a warning and never raise.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..model import Action, PortRange, Proto, RuleSet
from .base import (
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
    port_from_name,
    port_range,
    proto_from,
    register,
)

_VENDOR = "cisco_asa"
_PORT_OPS = ("eq", "neq", "lt", "gt", "range")
_KNOWN_PROTOS = frozenset(
    {"ip", "tcp", "udp", "icmp", "icmp6", "icmpv6", "any"}
)
_ACE_TRAILERS = frozenset(
    {"log", "inactive", "time-range", "disable", "default", "debugging"}
)
# Top-level lines that are ordinary ASA chrome: skipped without a warning.
_BENIGN_PREFIXES = (
    "asa version", "hostname", "domain-name", "enable", "passwd", "password",
    "names", "name ", "interface", "nameif", "security-level", "ip address",
    "ipv6 address", "no ", "service-module", "boot", "banner", "clock",
    "dns", "ftp", "pager", "mtu", "icmp", "arp", "route", "ssh", "telnet",
    "console", "terminal", "same-security", "logging", "aaa", "snmp-server",
    "ntp", "http", "crypto", "username", "class-map", "policy-map",
    "service-policy", "policy", "prompt", "cryptochecksum", "failover",
    "monitor-interface", "timeout", "user-identity", "ssl", "tls-proxy",
    "call-home", "dynamic-access-policy-record", "nat", "global", "vpn",
    "group-policy", "tunnel-group", "webvpn", "end", "ssl",
)
_SILENT_MEMBERS = frozenset({"description", "nat"})


def _is_member_line(raw_line: str, toks: list[str], kind: str) -> bool:
    if raw_line[:1] in (" ", "\t"):
        return True
    return toks[0] in _MEMBER_KEYWORDS.get(kind, ())


_MEMBER_KEYWORDS: dict[str, tuple[str, ...]] = {
    "onet": ("host", "subnet", "range", "fqdn", "description"),
    "gnet": ("network-object", "group-object", "description"),
    "osvc": ("service", "description"),
    "gsvc": ("port-object", "service-object", "group-object", "description"),
    "gproto": ("protocol-object", "group-object", "description"),
    "gother": (),
}


@dataclass
class _Block:
    kind: str
    name: str
    proto: str = ""
    cidrs: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)
    ports: list[PortRange] = field(default_factory=list)
    conditional: bool = False
    feature: Optional[ConditionalFeature] = None


def _port_tok(tok: str) -> Optional[int]:
    return port_from_name(tok)


def _parse_port_op(
    proto: Proto, toks: list[str], i: int
) -> tuple[list[PortRange], int, list[str]]:
    """Parse ``OP ARGS`` at ``toks[i]``. Returns (ranges, next index,
    unresolved port names). An unreadable port widens to the whole protocol."""
    op = toks[i].lower()
    full = [port_range(proto, 0, 65535)]
    if op == "range":
        if i + 2 >= len(toks):
            return full, len(toks), []
        lo, hi = _port_tok(toks[i + 1]), _port_tok(toks[i + 2])
        bad = [t for t, v in ((toks[i + 1], lo), (toks[i + 2], hi)) if v is None]
        if bad:
            return full, i + 3, bad
        return [port_range(proto, lo, hi)], i + 3, []  # type: ignore[arg-type]
    if i + 1 >= len(toks):
        return full, len(toks), []
    val = _port_tok(toks[i + 1])
    if val is None:
        return full, i + 2, [toks[i + 1]]
    if op == "eq":
        return [port_range(proto, val)], i + 2, []
    if op == "lt":
        return ([port_range(proto, 0, val - 1)] if val > 0 else []), i + 2, []
    if op == "gt":
        return (
            [port_range(proto, val + 1, 65535)] if val < 65535 else []
        ), i + 2, []
    # neq
    out: list[PortRange] = []
    if val > 0:
        out.append(port_range(proto, 0, val - 1))
    if val < 65535:
        out.append(port_range(proto, val + 1, 65535))
    return out, i + 2, []


@register(_VENDOR)
class CiscoAsaParser(Parser):
    """Parse a Cisco ASA running-config into a :class:`ParseResult`."""

    def parse(self, raw: str, **opts) -> ParseResult:  # type: ignore[override]
        result = ParseResult(vendor=_VENDOR)
        text = raw if isinstance(raw, str) else str(raw or "")
        lines = text.splitlines()
        table = ObjectTable()
        claimed = self._pass_objects(lines, table, result)
        self._pass_acls(lines, claimed, table, result)
        return result

    # ------------------------------------------------------------------ pass 1
    def _pass_objects(
        self, lines: list[str], table: ObjectTable, result: ParseResult
    ) -> set[int]:
        claimed: set[int] = set()
        block: Optional[_Block] = None

        def flush() -> None:
            nonlocal block
            if block is not None:
                self._finish_block(block, table, result)
                block = None

        for idx, line in enumerate(lines):
            toks = line.split()
            if not toks:
                claimed.add(idx)
                continue
            if toks[0].startswith(("!", ":")):
                claimed.add(idx)
                continue
            head = toks[0].lower()
            toks = [toks[0].lower()] + toks[1:]

            if not line[:1].isspace() and head in ("object", "object-group"):
                flush()
                if len(toks) >= 3:
                    claimed.add(idx)
                    block = self._open_block(head, toks, result, line)
                    continue
                # malformed: fall through to pass 2 as unknown
                continue

            if head in ("access-list", "access-group"):
                flush()
                continue

            if block is not None and _is_member_line(line, toks, block.kind):
                claimed.add(idx)
                self._member(block, toks, line.strip(), result)
                continue

            if block is not None and not line[:1].isspace():
                flush()
        flush()
        return claimed

    def _open_block(
        self, head: str, toks: list[str], result: ParseResult, line: str
    ) -> _Block:
        kind_word = toks[1].lower()
        name = toks[2]
        if head == "object" and kind_word == "network":
            return _Block("onet", name)
        if head == "object" and kind_word == "service":
            return _Block("osvc", name)
        if head == "object-group" and kind_word == "network":
            return _Block("gnet", name)
        if head == "object-group" and kind_word == "service":
            proto = toks[3].lower() if len(toks) > 3 else ""
            return _Block("gsvc", name, proto=proto)
        if head == "object-group" and kind_word == "protocol":
            return _Block("gproto", name)
        result.add_warning(
            WarningLevel.UNSUPPORTED,
            f"unsupported object definition: {head} {kind_word}",
            line.strip(),
        )
        return _Block("gother", name)

    def _member(
        self, b: _Block, toks: list[str], ref: str, result: ParseResult
    ) -> None:
        w = toks[0]
        if w in _SILENT_MEMBERS:
            return
        if b.kind == "onet":
            self._member_onet(b, toks, ref, result)
        elif b.kind == "gnet":
            self._member_gnet(b, toks, ref, result)
        elif b.kind == "osvc":
            if w == "service":
                self._service_spec(b, toks[1:], ref, result)
            else:
                self._unknown_member(b, ref, result)
        elif b.kind == "gsvc":
            self._member_gsvc(b, toks, ref, result)
        elif b.kind == "gproto":
            if w == "protocol-object" and len(toks) >= 2:
                p = proto_from(toks[1])
                if toks[1] not in _KNOWN_PROTOS and not toks[1].isdigit():
                    b.conditional, b.feature = True, ConditionalFeature.UNRESOLVED
                    result.add_warning(
                        WarningLevel.INFO,
                        f"protocol {toks[1]} not modelled; treated as any",
                        ref,
                    )
                b.ports.append(PortRange(p, 0, 65535))
            elif w == "group-object" and len(toks) >= 2:
                b.members.append(toks[1])
            else:
                self._unknown_member(b, ref, result)
        # gother: members consumed silently (one warning at open)

    def _unknown_member(self, b: _Block, ref: str, result: ParseResult) -> None:
        result.add_warning(
            WarningLevel.INFO, f"unsupported line in {b.kind} {b.name}", ref
        )

    def _addr_literal(self, toks: list[str]) -> Optional[list[str]]:
        if not toks:
            return None
        if len(toks) >= 2 and toks[0].lower() != "object":
            got = normalize_cidrs(f"{toks[0]} {toks[1]}")
            if got is not None:
                return got
        return normalize_cidrs(toks[0])

    def _member_onet(
        self, b: _Block, toks: list[str], ref: str, result: ParseResult
    ) -> None:
        w = toks[0]
        got: Optional[list[str]] = None
        if w == "host" and len(toks) >= 2:
            got = normalize_cidrs(toks[1])
        elif w == "subnet" and len(toks) >= 2:
            got = self._addr_literal(toks[1:])
        elif w == "range" and len(toks) >= 3:
            got = normalize_cidrs(f"{toks[1]}-{toks[2]}")
        elif w == "fqdn":
            b.conditional, b.feature = True, ConditionalFeature.FQDN
            return
        else:
            self._unknown_member(b, ref, result)
            return
        if got is None:
            b.conditional, b.feature = True, ConditionalFeature.UNRESOLVED
            result.add_warning(
                WarningLevel.UNRESOLVED,
                f"cannot normalise address in object {b.name}",
                ref,
            )
            return
        b.cidrs.extend(got)

    def _member_gnet(
        self, b: _Block, toks: list[str], ref: str, result: ParseResult
    ) -> None:
        w = toks[0]
        if w == "group-object" and len(toks) >= 2:
            b.members.append(toks[1])
            return
        if w != "network-object" or len(toks) < 2:
            self._unknown_member(b, ref, result)
            return
        if toks[1].lower() == "object" and len(toks) >= 3:
            b.members.append(toks[2])
            return
        if toks[1].lower() == "host" and len(toks) >= 3:
            got = normalize_cidrs(toks[2])
        else:
            got = self._addr_literal(toks[1:])
        if got is None:
            result.add_warning(
                WarningLevel.UNRESOLVED,
                f"cannot normalise network-object in group {b.name}",
                ref,
            )
            b.members.append(" ".join(toks[1:]))  # resolves as unresolved
            return
        b.cidrs.extend(got)

    def _service_spec(
        self, b: _Block, toks: list[str], ref: str, result: ParseResult
    ) -> None:
        """``tcp [source OP..] [destination OP..]`` (object service line or
        service-object body)."""
        if not toks:
            self._unknown_member(b, ref, result)
            return
        if toks[0].lower() == "object" and len(toks) >= 2:
            b.members.append(toks[1])
            return
        ptok = toks[0].lower()
        proto = proto_from(ptok)
        if ptok not in _KNOWN_PROTOS and not ptok.isdigit():
            b.conditional, b.feature = True, ConditionalFeature.UNRESOLVED
            result.add_warning(
                WarningLevel.INFO, f"protocol {ptok} not modelled; treated as any", ref
            )
        if proto not in (Proto.TCP, Proto.UDP):
            b.ports.append(PortRange(proto, 0, 65535))
            return
        i = 1
        dst_ranges: Optional[list[PortRange]] = None
        while i < len(toks):
            kw = toks[i].lower()
            if kw in ("source", "destination") and i + 1 < len(toks) \
                    and toks[i + 1].lower() in _PORT_OPS:
                rngs, i, bad = _parse_port_op(proto, toks, i + 1)
                if bad:
                    b.conditional, b.feature = True, ConditionalFeature.UNRESOLVED
                    result.add_warning(
                        WarningLevel.UNRESOLVED,
                        f"unknown port name(s): {', '.join(bad)}", ref)
                if kw == "destination":
                    dst_ranges = rngs
                else:
                    result.add_warning(
                        WarningLevel.INFO,
                        "source-port match not modelled; widened", ref)
            else:
                i += 1
        b.ports.extend(dst_ranges if dst_ranges is not None
                       else [port_range(proto, 0, 65535)])

    def _member_gsvc(
        self, b: _Block, toks: list[str], ref: str, result: ParseResult
    ) -> None:
        w = toks[0]
        if w == "group-object" and len(toks) >= 2:
            b.members.append(toks[1])
        elif w == "service-object":
            self._service_spec(b, toks[1:], ref, result)
        elif w == "port-object" and len(toks) >= 3 and toks[1].lower() in _PORT_OPS:
            protos = {
                "tcp": [Proto.TCP], "udp": [Proto.UDP],
                "tcp-udp": [Proto.TCP, Proto.UDP],
            }.get(b.proto, [Proto.ANY])
            for p in protos:
                rngs, _, bad = _parse_port_op(p, toks, 1)
                b.ports.extend(rngs)
                if bad:
                    b.conditional, b.feature = True, ConditionalFeature.UNRESOLVED
                    result.add_warning(
                        WarningLevel.UNRESOLVED,
                        f"unknown port name(s): {', '.join(bad)}", ref)
        else:
            self._unknown_member(b, ref, result)

    def _finish_block(
        self, b: _Block, table: ObjectTable, result: ParseResult
    ) -> None:
        if b.kind in ("onet", "gnet"):
            table.add_address(AddressObject(
                b.name, cidrs=tuple(dict.fromkeys(b.cidrs)),
                members=tuple(b.members),
                conditional=b.conditional, feature=b.feature))
        elif b.kind in ("osvc", "gsvc", "gproto"):
            table.add_service(ServiceObject(
                b.name, ports=tuple(dict.fromkeys(b.ports)),
                members=tuple(b.members),
                conditional=b.conditional, feature=b.feature))

    # ------------------------------------------------------------------ pass 2
    def _pass_acls(
        self,
        lines: list[str],
        claimed: set[int],
        table: ObjectTable,
        result: ParseResult,
    ) -> None:
        orders: dict[str, int] = {}
        bound: list[RuleSetBinding] = []
        for idx, line in enumerate(lines):
            if idx in claimed:
                continue
            s = line.strip()
            if not s:
                continue
            toks = s.split()
            head = toks[0].lower()
            if head == "access-list":
                self._acl_line(toks, s, orders, table, result)
            elif head == "access-group":
                self._access_group(toks, s, bound, result)
            elif line[:1].isspace():
                continue  # child of a benign / already-reported parent
            elif s.lower().startswith(_BENIGN_PREFIXES):
                continue
            else:
                result.add_warning(
                    WarningLevel.UNSUPPORTED, "unsupported line skipped", s)
        for b in bound:
            result.bindings.append(b)
            if b.ruleset_id not in result.rulesets:
                result.add_warning(
                    WarningLevel.UNRESOLVED,
                    f"access-group references unknown access-list {b.ruleset_id}",
                    b.ruleset_id,
                )

    def _access_group(
        self, toks: list[str], s: str, bound: list[RuleSetBinding],
        result: ParseResult,
    ) -> None:
        low = [t.lower() for t in toks]
        if len(toks) >= 3 and low[2] == "global":
            bound.append(RuleSetBinding(toks[1], interface="global", direction="in"))
        elif len(toks) >= 5 and low[2] in ("in", "out") and low[3] == "interface":
            bound.append(RuleSetBinding(toks[1], interface=toks[4], direction=low[2]))
        else:
            result.add_warning(
                WarningLevel.UNSUPPORTED, "unsupported access-group form", s)

    def _addr(
        self, toks: list[str], i: int, table: ObjectTable
    ) -> tuple[Optional[ResolvedAddresses], int]:
        """Parse one address spec at ``toks[i]``. ``None`` if malformed."""
        if i >= len(toks):
            return None, i
        t = toks[i].lower()
        if t in ("any", "any4", "any6"):
            return table.resolve_addresses("any"), i + 1
        if t == "host" and i + 1 < len(toks):
            return table.resolve_addresses(toks[i + 1]), i + 2
        if t in ("object", "object-group") and i + 1 < len(toks):
            return table.resolve_addresses(toks[i + 1]), i + 2
        if t == "interface" and i + 1 < len(toks):
            name = f"interface {toks[i + 1]}"
            return ResolvedAddresses(
                ("0.0.0.0/0", "::/0"), True,
                (ConditionalFeature.UNRESOLVED,), (name,)), i + 2
        if i + 1 < len(toks) and normalize_cidrs(f"{toks[i]} {toks[i + 1]}"):
            return table.resolve_addresses(f"{toks[i]} {toks[i + 1]}"), i + 2
        if normalize_cidrs(toks[i]) is not None:
            return table.resolve_addresses(toks[i]), i + 1
        if i + 1 < len(toks) and normalize_cidrs(toks[i]) is None \
                and _looks_like_ip(toks[i]):
            # address + a mask we cannot express as one CIDR
            tok = f"{toks[i]} {toks[i + 1]}"
            return ResolvedAddresses(
                ("0.0.0.0/0", "::/0"), True,
                (ConditionalFeature.UNRESOLVED,), (tok,)), i + 2
        return None, i

    def _acl_line(
        self,
        toks: list[str],
        s: str,
        orders: dict[str, int],
        table: ObjectTable,
        result: ParseResult,
    ) -> None:
        if len(toks) < 4:
            result.add_warning(WarningLevel.UNSUPPORTED, "malformed access-list", s)
            return
        acl = toks[1]
        i = 2
        if toks[i].lower() == "line" and i + 1 < len(toks):
            i += 2
        if i >= len(toks):
            result.add_warning(WarningLevel.UNSUPPORTED, "malformed access-list", s)
            return
        kind = toks[i].lower()
        if kind == "remark":
            return
        if kind != "extended":
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"access-list type '{kind}' not modelled; skipped", s)
            return
        i += 1
        if i >= len(toks) or toks[i].lower() not in ("permit", "deny"):
            result.add_warning(WarningLevel.UNSUPPORTED, "unsupported ACE action", s)
            return
        action = Action.ALLOW if toks[i].lower() == "permit" else Action.DENY
        i += 1
        low = [t.lower() for t in toks]
        if "inactive" in low[i:]:
            result.add_warning(WarningLevel.INFO, "inactive ACE skipped", s)
            return
        if i >= len(toks):
            result.add_warning(WarningLevel.UNSUPPORTED, "truncated ACE", s)
            return

        extra_cond = False
        # --- protocol (or a protocol/service object in its place)
        svc_from_proto: Optional[ResolvedService] = None
        ptok = low[i]
        proto = Proto.ANY
        if ptok in ("object", "object-group") and i + 1 < len(toks):
            svc_from_proto = table.resolve_service(toks[i + 1])
            i += 2
        else:
            proto = proto_from(ptok)
            if ptok not in _KNOWN_PROTOS and not ptok.isdigit():
                extra_cond = True
                result.add_warning(
                    WarningLevel.INFO,
                    f"protocol {ptok} not modelled; treated as any (conditional)", s)
            i += 1

        # --- source
        src, i = self._addr(toks, i, table)
        if src is None:
            result.add_warning(WarningLevel.UNSUPPORTED, "unparseable ACE source", s)
            return
        # optional source-port match (not modelled)
        if i < len(toks) and proto in (Proto.TCP, Proto.UDP, Proto.ANY):
            if low[i] in _PORT_OPS:
                _, i, _ = _parse_port_op(proto, toks, i)
                result.add_warning(
                    WarningLevel.INFO, "source-port match not modelled; widened", s)
            elif low[i] == "object-group" and i + 1 < len(toks) \
                    and toks[i + 1] in table.services \
                    and toks[i + 1] not in table.addresses:
                i += 2
                result.add_warning(
                    WarningLevel.INFO, "source-port group not modelled; widened", s)
        # --- destination
        dst, i = self._addr(toks, i, table)
        if dst is None:
            result.add_warning(WarningLevel.UNSUPPORTED, "unparseable ACE destination", s)
            return

        # --- service
        service, i = self._service(proto, svc_from_proto, toks, low, i, table, result, s)

        # --- trailers
        if "time-range" in low[i:]:
            extra_cond = True
            result.add_warning(
                WarningLevel.INFO, "time-range ACE treated as conditional", s)

        order = orders.get(acl, 0) + 1
        orders[acl] = order
        rule, warns = build_rule(
            rule_id=f"{acl}#{order}", action=action, order=order,
            src=src, dst=dst, service=service, vendor=_VENDOR,
            raw_ref=s, extra_conditional=extra_cond)
        result.warnings.extend(warns)
        rs = result.rulesets.get(acl)
        if rs is None:
            rs = RuleSet(id=acl, rules=[], default_action=Action.DENY, vendor=_VENDOR)
            result.rulesets[acl] = rs
        rs.rules.append(rule)

    def _service(
        self,
        proto: Proto,
        preset: Optional[ResolvedService],
        toks: list[str],
        low: list[str],
        i: int,
        table: ObjectTable,
        result: ParseResult,
        ref: str,
    ) -> tuple[ResolvedService, int]:
        if preset is not None:
            return preset, i
        if proto is Proto.ANY:
            # ``ip`` (or an unmodelled protocol): any port. A trailing
            # object-group service is honoured if present.
            if i + 1 < len(toks) and low[i] in ("object-group", "object") \
                    and toks[i + 1] in table.services:
                return table.resolve_service(toks[i + 1]), i + 2
            return ResolvedService((PortRange.any(),)), i
        if proto is Proto.ICMP:
            if i < len(toks) and low[i] in ("object-group", "object") \
                    and i + 1 < len(toks):
                i += 2
                result.add_warning(
                    WarningLevel.INFO, "ICMP type group not modelled; widened", ref)
            elif i < len(toks) and low[i] not in _ACE_TRAILERS:
                i += 1
                result.add_warning(
                    WarningLevel.INFO, "ICMP type not modelled; widened", ref)
            return ResolvedService((PortRange(Proto.ICMP, 0, 65535),)), i
        full = ResolvedService((port_range(proto, 0, 65535),))
        if i >= len(toks):
            return full, i
        if low[i] in _PORT_OPS:
            rngs, j, bad = _parse_port_op(proto, toks, i)
            if bad:
                return ResolvedService(
                    tuple(rngs) or full.ports, True,
                    (ConditionalFeature.UNRESOLVED,), tuple(bad)), j
            return ResolvedService(tuple(rngs)), j
        if low[i] in ("object-group", "object") and i + 1 < len(toks):
            return table.resolve_service(toks[i + 1]), i + 2
        return full, i


def _looks_like_ip(tok: str) -> bool:
    return normalize_cidrs(tok) is not None or tok.count(".") == 3
