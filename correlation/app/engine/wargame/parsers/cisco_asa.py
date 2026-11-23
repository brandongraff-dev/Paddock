"""Cisco ASA config -> vendor-neutral RuleSet.

Defensive and static: this reads an ASA running-config and produces the rule
model the solver consumes. Nothing is sent or executed.

Supported constructs
* ``object network`` (host / subnet / range / fqdn, and its object ``nat``)
* ``object-group network`` (network-object, group-object, nested groups)
* ``object service`` and ``object-group service`` (port-object,
  service-object, group-object), ``object-group protocol`` and
  ``object-group icmp-type``
* ``access-list NAME [line N] [extended] permit|deny PROTO SRC [SPORT] DST
  [DPORT]`` with ``any``/``any4``/``any6``, host, mask, object, object-group,
  ``interface``, user / security-group prefixes, ``inactive``, ``time-range``
* ``access-group NAME in|out interface IFACE`` and ``access-group NAME
  global`` (``control-plane`` bindings are to-the-box, not through-traffic)
* ``interface`` / ``nameif`` / ``security-level`` and
  ``same-security-traffic permit inter-interface``
* twice NAT (``nat (a,b) source static ...``), object NAT, and pre-8.3
  ``static`` (flagged, see below)

ASA semantics that decide correctness
* **Implicit deny** at the end of every ACL (``default_action=DENY``).
* **Interface ACL, then global ACL, then implicit deny.** When a global ACL
  exists, its rules are appended after each inbound interface ACL's rules
  (the interface ACL's implicit deny moves to the end of the global ACL).
* **No inbound ACL is NOT default-deny.** An interface without an inbound
  ACL (and no global ACL) uses the security-level default: traffic to a
  *lower* security interface is permitted, to a higher one denied, and to an
  equal one denied unless ``same-security-traffic permit inter-interface``.
  This is emitted as ``asa:security-level:permit`` / ``:deny`` rule sets
  with one binding per (ingress, egress) nameif pair.
* **NAT.** On 8.3+ ACLs match the *real* address. A topology may describe the
  mapped (public) one, so rules that touch a translated address get the
  other half of the translation added and are flagged conditional (NAT).
  Pre-8.3 ACLs match mapped addresses; with NAT present every rule is
  flagged conditional.

Honesty rule. Anything we cannot model exactly is over-approximated toward
"reachable" and flagged ``conditional`` (unknown objects, unmodelled
protocols, source-port and ICMP-type matches, time-ranges, FQDN objects,
user/TrustSec matches), never silently dropped. An ACE we cannot parse at
all becomes a conditional permit-any when it is a ``permit`` (dropping it
could only make the boundary look *more* closed) and is skipped, with a
warning, when it is a ``deny``.

Two passes: objects first (so ACLs may reference objects defined later), then
ACLs and bindings. Unknown lines yield a warning and never raise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Optional

from ..model import Action, PortRange, Proto, Rule, RuleSet
from .base import (
    ANY4_CIDRS,
    ANY6_CIDRS,
    ANY_CIDRS,
    CONDITIONAL_REASON,
    AddressObject,
    ConditionalFeature,
    ObjectTable,
    ParseResult,
    ParseWarning,
    Parser,
    ResolvedAddresses,
    ResolvedService,
    RuleSetBinding,
    ServiceObject,
    WarningLevel,
    apply_nat_overapprox,
    build_rule,
    filter_family,
    normalize_cidrs,
    port_from_name,
    port_range,
    register,
)

_VENDOR = "cisco_asa"
_PORT_OPS = ("eq", "neq", "lt", "gt", "range")
_ACE_TRAILERS = frozenset(
    {"log", "inactive", "time-range", "disable", "default", "debugging",
     "interval", "informational", "notifications", "warnings", "errors",
     "critical", "alerts", "emergencies"}
)
# Top-level lines that are ordinary ASA chrome: skipped without a warning.
_BENIGN_PREFIXES = (
    "asa version", "hostname", "domain-name", "enable", "passwd", "password",
    "names", "name ", "interface", "nameif", "security-level", "ip address",
    "ipv6 address", "no ", "service-module", "boot", "banner", "clock",
    "dns", "ftp", "pager", "mtu", "icmp", "arp", "route", "ssh", "telnet",
    "console", "terminal", "logging", "aaa", "snmp-server",
    "ntp", "http", "crypto", "username", "class-map", "policy-map",
    "service-policy", "policy", "prompt", "cryptochecksum", "failover",
    "monitor-interface", "timeout", "user-identity", "ssl", "tls-proxy",
    "call-home", "dynamic-access-policy-record", "vpn",
    "group-policy", "tunnel-group", "webvpn", "end", "time-range",
    "threat-detection", "license", "license-server", "flow-export",
    "dhcpd", "dhcprelay", "firewall transparent", "mac-address", "context",
)
_SILENT_MEMBERS = frozenset({"description"})

#: ASA named ports. ``kerberos`` differs by protocol (tcp/88, udp/750).
_ASA_TCP_PORTS: dict[str, int] = {
    "aol": 5190, "bgp": 179, "chargen": 19, "cifs": 3020, "citrix-ica": 1494,
    "cmd": 514, "ctiqbe": 2748, "daytime": 13, "discard": 9, "domain": 53,
    "echo": 7, "exec": 512, "finger": 79, "ftp": 21, "ftp-data": 20,
    "gopher": 70, "h323": 1720, "hostname": 101, "http": 80, "https": 443,
    "ident": 113, "imap4": 143, "irc": 194, "kerberos": 88, "klogin": 543,
    "kshell": 544, "ldap": 389, "ldaps": 636, "login": 513,
    "lotusnotes": 1352, "lpd": 515, "netbios-ssn": 139, "nfs": 2049,
    "nntp": 119, "pcanywhere-data": 5631, "pim-auto-rp": 496, "pop2": 109,
    "pop3": 110, "pptp": 1723, "rsh": 514, "rtsp": 554, "sip": 5060,
    "smtp": 25, "sqlnet": 1521, "ssh": 22, "sunrpc": 111, "tacacs": 49,
    "talk": 517, "telnet": 23, "uucp": 540, "whois": 43, "www": 80,
}
_ASA_UDP_PORTS: dict[str, int] = {
    "biff": 512, "bootpc": 68, "bootps": 67, "cifs": 3020, "discard": 9,
    "dnsix": 195, "domain": 53, "echo": 7, "http": 80, "isakmp": 500,
    "kerberos": 750, "mobile-ip": 434, "nameserver": 42, "netbios-dgm": 138,
    "netbios-ns": 137, "nfs": 2049, "ntp": 123, "pcanywhere-status": 5632,
    "pim-auto-rp": 496, "radius": 1645, "radius-acct": 1646, "rip": 520,
    "secureid-udp": 5510, "sip": 5060, "snmp": 161, "snmptrap": 162,
    "sunrpc": 111, "syslog": 514, "tacacs": 49, "talk": 517, "tftp": 69,
    "time": 37, "vxlan": 4789, "who": 513, "www": 80, "xdmcp": 177,
}

#: Protocol keywords the model represents exactly.
_EXACT_PROTOS: dict[str, Proto] = {
    "ip": Proto.ANY, "tcp": Proto.TCP, "udp": Proto.UDP,
    "icmp": Proto.ICMP, "icmp6": Proto.ICMP, "icmpv6": Proto.ICMP,
    "6": Proto.TCP, "17": Proto.UDP, "1": Proto.ICMP, "58": Proto.ICMP,
}


def _proto(tok: str) -> tuple[Proto, bool]:
    """(Proto, exact). Anything but tcp/udp/icmp/ip (gre, esp, 47, sctp, …)
    widens to ANY and is *not* exact, so the rule must be conditional."""
    t = tok.lower()
    if t in _EXACT_PROTOS:
        return _EXACT_PROTOS[t], True
    return Proto.ANY, False


def _icmp_family(tok: str) -> Optional[int]:
    t = tok.lower()
    if t in ("icmp", "1"):
        return 4
    if t in ("icmp6", "icmpv6", "58"):
        return 6
    return None


def _is_member_line(raw_line: str, toks: list[str], kind: str) -> bool:
    if raw_line[:1] in (" ", "\t"):
        return True
    return toks[0] in _MEMBER_KEYWORDS.get(kind, ())


_MEMBER_KEYWORDS: dict[str, tuple[str, ...]] = {
    "onet": ("host", "subnet", "range", "fqdn", "description", "nat"),
    "gnet": ("network-object", "group-object", "description"),
    "osvc": ("service", "description"),
    "gsvc": ("port-object", "service-object", "group-object", "description"),
    "gproto": ("protocol-object", "group-object", "description"),
    "gicmp": ("icmp-object", "group-object", "description"),
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
    nat: list[list[str]] = field(default_factory=list)


@dataclass
class _Iface:
    name: str                       # hardware name (GigabitEthernet0/0)
    nameif: str = ""
    level: Optional[int] = None
    ip: str = ""


def _port_tok(tok: str, proto: Proto) -> Optional[int]:
    t = tok.strip().lower()
    if t.isdigit():
        n = int(t)
        return n if 0 <= n <= 65535 else None
    if proto is Proto.TCP and t in _ASA_TCP_PORTS:
        return _ASA_TCP_PORTS[t]
    if proto is Proto.UDP and t in _ASA_UDP_PORTS:
        return _ASA_UDP_PORTS[t]
    if proto is Proto.ANY:
        a, b = _ASA_TCP_PORTS.get(t), _ASA_UDP_PORTS.get(t)
        if a is not None and b is not None and a != b:
            return None             # ambiguous (kerberos): unresolved
        if a is not None or b is not None:
            return a if a is not None else b
    if t in _ASA_TCP_PORTS or t in _ASA_UDP_PORTS:
        return None                 # a name for the *other* protocol
    return port_from_name(t)


def _parse_port_op(
    proto: Proto, toks: list[str], i: int
) -> tuple[list[PortRange], int, list[str]]:
    """Parse ``OP ARGS`` at ``toks[i]``. Returns (ranges, next index,
    unresolved port names). An unreadable port widens to the whole protocol.
    ``lt``/``gt`` are exclusive; ``neq`` is two ranges. An empty list means
    the operator matches no port at all (``lt 0``)."""
    op = toks[i].lower()
    full = [port_range(proto, 0, 65535)]
    if op == "range":
        if i + 2 >= len(toks):
            return full, len(toks), [" ".join(toks[i:])]
        lo, hi = _port_tok(toks[i + 1], proto), _port_tok(toks[i + 2], proto)
        bad = [t for t, v in ((toks[i + 1], lo), (toks[i + 2], hi)) if v is None]
        if bad:
            return full, i + 3, bad
        return [port_range(proto, lo, hi)], i + 3, []  # type: ignore[arg-type]
    if i + 1 >= len(toks):
        return full, len(toks), [op]
    val = _port_tok(toks[i + 1], proto)
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


def _version(text: str) -> Optional[tuple[int, int]]:
    m = re.search(r"^\s*ASA Version (\d+)\.(\d+)", text, re.IGNORECASE | re.MULTILINE)
    return (int(m.group(1)), int(m.group(2))) if m else None


@register(_VENDOR)
class CiscoAsaParser(Parser):
    """Parse a Cisco ASA running-config into a :class:`ParseResult`."""

    def parse(self, raw: str, **opts) -> ParseResult:  # type: ignore[override]
        result = ParseResult(vendor=_VENDOR)
        text = raw if isinstance(raw, str) else str(raw or "")
        lines = text.splitlines()
        table = ObjectTable()
        self._ifaces: list[_Iface] = []
        self._same_security_inter = False
        self._object_nat: list[tuple[str, list[str]]] = []
        self._twice_nat: list[list[str]] = []
        self._legacy_nat: list[list[str]] = []
        claimed = self._pass_objects(lines, table, result)
        self._pass_interfaces(lines)
        self._pass_acls(lines, claimed, table, result)
        self._apply_nat(text, table, result)
        self._finish_bindings(result)
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
        if head == "object-group" and kind_word == "icmp-type":
            return _Block("gicmp", name)
        if head == "object-group" and kind_word in ("user", "security"):
            # Identity / TrustSec groups: runtime membership. Registered as
            # a conditional "any" address so a reference never narrows.
            b = _Block("gnet", name)
            b.conditional, b.feature = True, ConditionalFeature.USER_ID
            b.kind = "gident"
            return b
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
                p, exact = _proto(toks[1])
                if not exact:
                    b.conditional, b.feature = True, ConditionalFeature.PARTIAL_MATCH
                    result.add_warning(
                        WarningLevel.INFO,
                        f"protocol {toks[1]} not modelled; treated as any (conditional)",
                        ref,
                    )
                b.ports.append(PortRange(p, 0, 65535))
            elif w == "group-object" and len(toks) >= 2:
                b.members.append(toks[1])
            else:
                self._unknown_member(b, ref, result)
        elif b.kind == "gicmp":
            # ICMP types are not modelled: the group means "some ICMP".
            if w == "group-object" and len(toks) >= 2:
                b.members.append(toks[1])
            b.ports = [PortRange(Proto.ICMP, 0, 65535)]
            b.conditional, b.feature = True, ConditionalFeature.PARTIAL_MATCH
        # gother / gident: members consumed silently (one warning at open)

    def _unknown_member(self, b: _Block, ref: str, result: ParseResult) -> None:
        # An unread member line could have added addresses/ports: the object
        # must not be trusted as complete.
        b.conditional = True
        if b.feature is None:
            b.feature = ConditionalFeature.UNRESOLVED
        result.add_warning(
            WarningLevel.UNSUPPORTED,
            f"unsupported line in {b.kind} {b.name}; object treated as conditional",
            ref,
        )

    def _addr_literal(self, toks: list[str]) -> Optional[list[str]]:
        if not toks:
            return None
        if len(toks) >= 2 and toks[0].lower() != "object":
            got = normalize_cidrs(f"{toks[0]} {toks[1]}", mask_style="netmask")
            if got is not None:
                return got
            if _looks_like_ip(toks[1]):
                # "addr mask" with a mask we can't read: never fall back to
                # the bare address (that would narrow it to one host).
                return None
        return normalize_cidrs(toks[0], mask_style="netmask")

    def _member_onet(
        self, b: _Block, toks: list[str], ref: str, result: ParseResult
    ) -> None:
        w = toks[0]
        got: Optional[list[str]] = None
        if w == "nat":
            b.nat.append(toks[1:])
            return
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
            b.conditional, b.feature = True, ConditionalFeature.UNRESOLVED
            return
        b.cidrs.extend(got)

    def _service_spec(
        self, b: _Block, toks: list[str], ref: str, result: ParseResult
    ) -> None:
        """``tcp [source OP..] [destination OP..]`` (object service line or
        service-object body). ``tcp-udp`` expands to both protocols."""
        if not toks:
            self._unknown_member(b, ref, result)
            return
        if toks[0].lower() == "object" and len(toks) >= 2:
            b.members.append(toks[1])
            return
        ptok = toks[0].lower()
        if ptok == "tcp-udp":
            protos = [Proto.TCP, Proto.UDP]
        else:
            proto, exact = _proto(ptok)
            protos = [proto]
            if not exact:
                b.conditional, b.feature = True, ConditionalFeature.PARTIAL_MATCH
                result.add_warning(
                    WarningLevel.INFO,
                    f"protocol {ptok} not modelled; treated as any (conditional)", ref)
        for proto in protos:
            if proto not in (Proto.TCP, Proto.UDP):
                if proto is Proto.ICMP and len(toks) > 1:
                    b.conditional, b.feature = True, ConditionalFeature.PARTIAL_MATCH
                    result.add_warning(
                        WarningLevel.INFO,
                        "ICMP type not modelled; widened (conditional)", ref)
                b.ports.append(PortRange(proto, 0, 65535))
                continue
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
                        b.conditional = True
                        if b.feature is None:
                            b.feature = ConditionalFeature.PARTIAL_MATCH
                        result.add_warning(
                            WarningLevel.INFO,
                            "source-port match not modelled; widened (conditional)", ref)
                elif kw in _PORT_OPS:
                    # bare "tcp eq 80" (no 'destination' keyword)
                    rngs, i, bad = _parse_port_op(proto, toks, i)
                    if bad:
                        b.conditional, b.feature = True, ConditionalFeature.UNRESOLVED
                    dst_ranges = rngs
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
        if b.kind in ("onet", "gnet", "gident"):
            table.add_address(AddressObject(
                b.name, cidrs=tuple(dict.fromkeys(b.cidrs)),
                members=tuple(b.members),
                conditional=b.conditional, feature=b.feature))
            for spec in b.nat:
                self._object_nat.append((b.name, spec))
        elif b.kind in ("osvc", "gsvc", "gproto", "gicmp"):
            table.add_service(ServiceObject(
                b.name, ports=tuple(dict.fromkeys(b.ports)),
                members=tuple(b.members),
                conditional=b.conditional, feature=b.feature))

    # ----------------------------------------------------------- interfaces
    def _pass_interfaces(self, lines: list[str]) -> None:
        cur: Optional[_Iface] = None
        for line in lines:
            toks = line.split()
            if not toks:
                continue
            low = [t.lower() for t in toks]
            if not line[:1].isspace():
                cur = None
                if low[0] == "interface" and len(toks) >= 2:
                    cur = _Iface(toks[1])
                    self._ifaces.append(cur)
                elif low[:3] == ["same-security-traffic", "permit", "inter-interface"]:
                    self._same_security_inter = True
                continue
            if cur is None:
                continue
            if low[0] == "nameif" and len(toks) >= 2:
                cur.nameif = toks[1]
            elif low[0] == "security-level" and len(toks) >= 2 and toks[1].isdigit():
                cur.level = int(toks[1])
            elif low[:2] == ["ip", "address"] and len(toks) >= 3:
                cur.ip = toks[2]

    # ------------------------------------------------------------------ pass 2
    def _pass_acls(
        self,
        lines: list[str],
        claimed: set[int],
        table: ObjectTable,
        result: ParseResult,
    ) -> None:
        self._orders: dict[str, int] = {}
        self._bound: list[RuleSetBinding] = []
        for idx, line in enumerate(lines):
            if idx in claimed:
                continue
            s = line.strip()
            if not s:
                continue
            toks = s.split()
            head = toks[0].lower()
            if head == "access-list":
                self._acl_line(toks, s, self._orders, table, result)
            elif head == "access-group":
                self._access_group(toks, s, self._bound, result)
            elif line[:1].isspace():
                continue  # child of a benign / already-reported parent
            elif head == "nat" and len(toks) >= 2:
                self._twice_nat.append(toks[1:])
            elif head == "static" and len(toks) >= 2:
                self._legacy_nat.append(toks[1:])
            elif head in ("global", "same-security-traffic"):
                continue
            elif s.lower().startswith(_BENIGN_PREFIXES):
                continue
            else:
                result.add_warning(
                    WarningLevel.UNSUPPORTED, "unsupported line skipped", s)

    def _access_group(
        self, toks: list[str], s: str, bound: list[RuleSetBinding],
        result: ParseResult,
    ) -> None:
        low = [t.lower() for t in toks]
        if "control-plane" in low:
            # To-the-box (management plane) ACL: it does not govern
            # through-traffic, so binding it to the data path would apply
            # its denies to flows it never sees.
            result.add_warning(
                WarningLevel.INFO,
                "control-plane access-group governs to-the-box traffic only; "
                "not bound to the data path", s)
            return
        if len(toks) >= 3 and low[2] == "global":
            bound.append(RuleSetBinding(toks[1], interface="global", direction="in"))
        elif len(toks) >= 5 and low[2] in ("in", "out") and low[3] == "interface":
            bound.append(RuleSetBinding(toks[1], interface=toks[4], direction=low[2]))
        else:
            result.add_warning(
                WarningLevel.UNSUPPORTED, "unsupported access-group form", s)

    def _literal(self, tok: str) -> Optional[ResolvedAddresses]:
        got = normalize_cidrs(tok, mask_style="netmask")
        return ResolvedAddresses(tuple(got)) if got is not None else None

    def _addr(
        self, toks: list[str], i: int, table: ObjectTable,
        feats: list[ConditionalFeature],
    ) -> tuple[Optional[ResolvedAddresses], int]:
        """Parse one address spec at ``toks[i]``. ``None`` if malformed.
        Identity prefixes (``user``, ``user-group``, ``object-group-user``,
        ``security-group``, ``object-group-security``) are consumed and
        recorded in ``feats``: they only *narrow* the match at runtime."""
        while i < len(toks):
            t = toks[i].lower()
            if t in ("user", "user-group", "object-group-user") and i + 1 < len(toks):
                feats.append(ConditionalFeature.USER_ID)
                i += 2
            elif t == "security-group" and i + 2 < len(toks):
                feats.append(ConditionalFeature.USER_ID)
                i += 3
            elif t == "object-group-security" and i + 1 < len(toks):
                feats.append(ConditionalFeature.USER_ID)
                i += 2
            else:
                break
        if i >= len(toks):
            return None, i
        t = toks[i].lower()
        if t == "any":
            return ResolvedAddresses(ANY_CIDRS), i + 1
        if t == "any4":
            return ResolvedAddresses(ANY4_CIDRS), i + 1
        if t == "any6":
            return ResolvedAddresses(ANY6_CIDRS), i + 1
        if t == "host" and i + 1 < len(toks):
            lit = self._literal(toks[i + 1])
            if lit is not None:
                return lit, i + 2
            return table.resolve_addresses(toks[i + 1]), i + 2
        if t in ("object", "object-group") and i + 1 < len(toks):
            return table.resolve_addresses(toks[i + 1]), i + 2
        if t == "interface" and i + 1 < len(toks):
            name = f"interface {toks[i + 1]}"
            return ResolvedAddresses(
                ANY_CIDRS, True,
                (ConditionalFeature.UNRESOLVED,), (name,)), i + 2
        if i + 1 < len(toks) and _looks_like_ip(toks[i]) and _looks_like_ip(toks[i + 1]):
            lit = self._literal(f"{toks[i]} {toks[i + 1]}")
            if lit is not None:
                return lit, i + 2
            # address + a mask we cannot express as one CIDR
            tok = f"{toks[i]} {toks[i + 1]}"
            return ResolvedAddresses(
                ANY_CIDRS, True,
                (ConditionalFeature.UNRESOLVED,), (tok,)), i + 2
        lit = self._literal(toks[i])
        if lit is not None:
            return lit, i + 1
        return None, i

    def _ensure_rs(self, acl: str, result: ParseResult) -> RuleSet:
        rs = result.rulesets.get(acl)
        if rs is None:
            rs = RuleSet(id=acl, rules=[], default_action=Action.DENY, vendor=_VENDOR)
            result.rulesets[acl] = rs
        return rs

    def _add_rule(
        self, acl: str, result: ParseResult, orders: dict[str, int], **kw
    ) -> None:
        order = orders.get(acl, 0) + 1
        orders[acl] = order
        rule, warns = build_rule(
            rule_id=f"{acl}#{order}", order=order, vendor=_VENDOR, **kw)
        result.warnings.extend(warns)
        self._ensure_rs(acl, result).rules.append(rule)

    def _fallback(
        self, acl: str, action: Action, proto: Proto, s: str, why: str,
        orders: dict[str, int], result: ParseResult,
    ) -> None:
        """An ACE we could not parse. A permit becomes a conditional
        permit-any (dropping it could only fake a closed door); a deny is
        skipped, which can only over-approximate reachability."""
        if action is Action.DENY:
            result.add_warning(
                WarningLevel.UNSUPPORTED, f"{why}; deny ACE skipped (over-approximates open)", s)
            self._ensure_rs(acl, result)
            return
        result.add_warning(
            WarningLevel.UNSUPPORTED,
            f"{why}; permit ACE kept as a conditional permit-any", s)
        any_addr = ResolvedAddresses(ANY_CIDRS, True, (ConditionalFeature.UNRESOLVED,))
        self._add_rule(
            acl, result, orders, action=action, src=any_addr, dst=any_addr,
            service=ResolvedService((PortRange(proto, 0, 65535),)),
            raw_ref=s)

    def _acl_line(
        self,
        toks: list[str],
        s: str,
        orders: dict[str, int],
        table: ObjectTable,
        result: ParseResult,
    ) -> None:
        if len(toks) < 3:
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
        if kind in ("permit", "deny"):
            # pre-7.0 / abbreviated form without the 'extended' keyword
            pass
        elif kind in ("extended", "advanced"):
            i += 1
        else:
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"access-list type '{kind}' not modelled; skipped", s)
            return
        if i >= len(toks) or toks[i].lower() not in ("permit", "deny", "trust"):
            result.add_warning(WarningLevel.UNSUPPORTED, "unsupported ACE action", s)
            return
        action = Action.DENY if toks[i].lower() == "deny" else Action.ALLOW
        i += 1
        low = [t.lower() for t in toks]
        if "inactive" in low[i:]:
            # An inactive ACE is not evaluated by the ASA at all.
            result.add_warning(WarningLevel.INFO, "inactive ACE skipped", s)
            self._ensure_rs(acl, result)
            return
        if i >= len(toks):
            self._fallback(acl, action, Proto.ANY, s, "truncated ACE", orders, result)
            return

        feats: list[ConditionalFeature] = []
        # --- protocol (or a protocol/service object in its place)
        svc_from_proto: Optional[ResolvedService] = None
        ptok = low[i]
        proto = Proto.ANY
        icmp_family: Optional[int] = None
        if ptok in ("object", "object-group") and i + 1 < len(toks):
            svc_from_proto = table.resolve_service(toks[i + 1])
            i += 2
        else:
            proto, exact = _proto(ptok)
            icmp_family = _icmp_family(ptok)
            if not exact:
                feats.append(ConditionalFeature.PARTIAL_MATCH)
                result.add_warning(
                    WarningLevel.INFO,
                    f"protocol {ptok} not modelled; treated as any (conditional)", s)
            i += 1

        # --- source
        src, i = self._addr(toks, i, table, feats)
        if src is None:
            self._fallback(acl, action, proto, s, "unparseable ACE source", orders, result)
            return
        # optional source-port match (not modelled: widened + conditional)
        if i < len(toks) and proto in (Proto.TCP, Proto.UDP, Proto.ANY):
            if low[i] in _PORT_OPS:
                _, i, _ = _parse_port_op(proto, toks, i)
                feats.append(ConditionalFeature.PARTIAL_MATCH)
                result.add_warning(
                    WarningLevel.INFO, "source-port match not modelled; widened (conditional)", s)
            elif low[i] in ("object-group", "object") and i + 1 < len(toks) \
                    and toks[i + 1] in table.services \
                    and toks[i + 1] not in table.addresses:
                i += 2
                feats.append(ConditionalFeature.PARTIAL_MATCH)
                result.add_warning(
                    WarningLevel.INFO, "source-port group not modelled; widened (conditional)", s)
        # --- destination
        dst, i = self._addr(toks, i, table, feats)
        if dst is None:
            self._fallback(acl, action, proto, s, "unparseable ACE destination", orders, result)
            return

        # --- service
        service, i, empty = self._service(
            proto, svc_from_proto, toks, low, i, table, result, s, feats)
        if empty:
            result.add_warning(
                WarningLevel.INFO, "port operator matches no port; ACE never matches", s)
            self._ensure_rs(acl, result)
            return

        # --- trailers
        if "time-range" in low[i:]:
            feats.append(ConditionalFeature.SCHEDULE)
            result.add_warning(
                WarningLevel.INFO, "time-range ACE treated as conditional", s)

        # ICMP / ICMPv6 only ever match their own address family.
        if icmp_family is not None:
            fs, fd = filter_family(src.cidrs, icmp_family), filter_family(dst.cidrs, icmp_family)
            if not fs or not fd:
                result.add_warning(
                    WarningLevel.INFO,
                    "ICMP ACE with no address of its family; ACE never matches", s)
                self._ensure_rs(acl, result)
                return
            src = replace(src, cidrs=fs)
            dst = replace(dst, cidrs=fd)

        self._add_rule(
            acl, result, orders, action=action, src=src, dst=dst,
            service=service, raw_ref=s, extra_conditional=bool(feats),
            extra_features=tuple(dict.fromkeys(feats)))

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
        feats: list[ConditionalFeature],
    ) -> tuple[ResolvedService, int, bool]:
        """Returns (service, next index, matches_nothing)."""
        if preset is not None:
            return preset, i, False
        if proto is Proto.ANY:
            # ``ip`` (or an unmodelled protocol): any port. A trailing
            # object-group service is honoured if present.
            if i + 1 < len(toks) and low[i] in ("object-group", "object") \
                    and toks[i + 1] in table.services:
                return table.resolve_service(toks[i + 1]), i + 2, False
            return ResolvedService((PortRange.any(),)), i, False
        if proto is Proto.ICMP:
            if i < len(toks) and low[i] in ("object-group", "object") \
                    and i + 1 < len(toks):
                i += 2
                feats.append(ConditionalFeature.PARTIAL_MATCH)
                result.add_warning(
                    WarningLevel.INFO, "ICMP type group not modelled; widened (conditional)", ref)
            elif i < len(toks) and low[i] not in _ACE_TRAILERS:
                i += 1
                feats.append(ConditionalFeature.PARTIAL_MATCH)
                result.add_warning(
                    WarningLevel.INFO, "ICMP type not modelled; widened (conditional)", ref)
            return ResolvedService((PortRange(Proto.ICMP, 0, 65535),)), i, False
        full = ResolvedService((port_range(proto, 0, 65535),))
        if i >= len(toks):
            return full, i, False
        if low[i] in _PORT_OPS:
            rngs, j, bad = _parse_port_op(proto, toks, i)
            if bad:
                return ResolvedService(
                    tuple(rngs) or full.ports, True,
                    (ConditionalFeature.UNRESOLVED,), tuple(bad)), j, False
            if not rngs:
                return full, j, True
            return ResolvedService(tuple(rngs)), j, False
        if low[i] in ("object-group", "object") and i + 1 < len(toks):
            return table.resolve_service(toks[i + 1]), i + 2, False
        return full, i, False

    # ------------------------------------------------------------- NAT
    def _nat_side(self, tok: str, table: ObjectTable, mapped_if: str = "") -> tuple[str, ...]:
        t = tok.lower()
        if t == "any":
            return ()
        if t == "interface":
            ip = self._iface_ip(mapped_if)
            return (f"{ip}/32",) if ip else ()
        lit = normalize_cidrs(tok, mask_style="netmask")
        if lit is not None:
            return tuple(lit)
        r = table.resolve_addresses(tok)
        if set(r.cidrs) <= set(ANY_CIDRS):
            return ()
        return tuple(r.cidrs)

    def _iface_ip(self, nameif: str) -> str:
        for f in self._ifaces:
            if f.nameif == nameif and normalize_cidrs(f.ip):
                return f.ip
        return ""

    @staticmethod
    def _ifpair(tok: str) -> tuple[str, str]:
        m = re.match(r"^\(([^,]*),([^)]*)\)$", tok)
        return (m.group(1), m.group(2)) if m else ("", "")

    def _apply_nat(self, text: str, table: ObjectTable, result: ParseResult) -> None:
        pairs: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
        # object NAT: nat (real_if,mapped_if) static MAPPED ...
        for obj, spec in self._object_nat:
            low = [t.lower() for t in spec]
            _, mif = self._ifpair(spec[0]) if spec else ("", "")
            if "static" in low:
                k = low.index("static")
                if k + 1 < len(spec):
                    real = self._nat_side(obj, table)
                    mapped = self._nat_side(spec[k + 1], table, mif)
                    pairs.append((real, mapped))
        # twice NAT: nat (a,b) [after-auto] source static R M [destination static MD RD]
        for spec in self._twice_nat:
            low = [t.lower() for t in spec]
            _, mif = self._ifpair(spec[0]) if spec else ("", "")
            if "source" in low:
                k = low.index("source")
                if k + 3 < len(spec) and low[k + 1] == "static":
                    pairs.append((self._nat_side(spec[k + 2], table),
                                  self._nat_side(spec[k + 3], table, mif)))
            if "destination" in low:
                k = low.index("destination")
                if k + 3 < len(spec) and low[k + 1] == "static":
                    # destination static MAPPED REAL
                    pairs.append((self._nat_side(spec[k + 3], table),
                                  self._nat_side(spec[k + 2], table)))
        # pre-8.3: static (in,out) [tcp|udp] MAPPED [port] REAL [port] [netmask M]
        for spec in self._legacy_nat:
            ips = [t for t in spec[1:] if t.lower() == "interface" or normalize_cidrs(t)]
            ips = [t for t in ips if t.lower() not in ("tcp", "udp")]
            _, mif = self._ifpair(spec[0]) if spec else ("", "")
            if len(ips) >= 2:
                pairs.append((self._nat_side(ips[1], table),
                              self._nat_side(ips[0], table, mif)))
        has_nat = bool(self._object_nat or self._twice_nat or self._legacy_nat)
        if not has_nat:
            return
        ver = _version(text)
        legacy = (ver is not None and ver < (8, 3)) or bool(self._legacy_nat)
        result.add_warning(
            WarningLevel.CONDITIONAL,
            "NAT is configured: ACLs match the "
            + ("mapped (pre-8.3)" if legacy else "real (8.3+)")
            + " address; rules touching a translated address are widened to "
              "both halves and flagged conditional")
        pairs = [(r, m) for r, m in pairs if r and m]
        for rs in result.rulesets.values():
            if rs.id.startswith("asa:"):
                continue
            new_rules: list[Rule] = []
            for rule in rs.rules:
                nr, changed = apply_nat_overapprox(rule, pairs)
                if legacy and not nr.conditional:
                    nr, changed = replace(nr, conditional=True), True
                if changed:
                    result.warnings.append(ParseWarning(
                        WarningLevel.CONDITIONAL,
                        CONDITIONAL_REASON[ConditionalFeature.NAT], rule.raw_ref))
                new_rules.append(nr)
            rs.rules[:] = new_rules

    # ------------------------------------------------------------- bindings
    def _finish_bindings(self, result: ParseResult) -> None:
        bound = self._bound
        # An access-group naming an ACL we never saw: ASA would apply that
        # ACL, whose content we do not know. Over-approximate open.
        for b in bound:
            if b.ruleset_id not in result.rulesets:
                result.add_warning(
                    WarningLevel.UNRESOLVED,
                    f"access-group references unknown access-list {b.ruleset_id}; "
                    "modelled as a conditional permit-any",
                    b.ruleset_id,
                )
                any_addr = ResolvedAddresses(
                    ANY_CIDRS, True, (ConditionalFeature.UNRESOLVED,), (b.ruleset_id,))
                rule, warns = build_rule(
                    rule_id=f"{b.ruleset_id}#unresolved", action=Action.ALLOW, order=1,
                    src=any_addr, dst=any_addr,
                    service=ResolvedService((PortRange.any(),)), vendor=_VENDOR,
                    raw_ref=f"access-group {b.ruleset_id}")
                result.rulesets[b.ruleset_id] = RuleSet(
                    id=b.ruleset_id, rules=[rule], default_action=Action.DENY,
                    vendor=_VENDOR)

        globals_ = [b for b in bound if b.interface == "global"]
        if len(globals_) > 1:
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                "more than one global access-group; the last one wins on an ASA",
                ", ".join(b.ruleset_id for b in globals_))
        g = globals_[-1].ruleset_id if globals_ else None
        out_acls = {b.ruleset_id for b in bound if b.direction == "out"}
        final: list[RuleSetBinding] = []
        merged: dict[str, str] = {}
        for b in bound:
            if g is not None and b.interface != "global" and b.direction == "in":
                # interface ACL first, then the global ACL, then implicit deny
                rid = self._merge_global(b.ruleset_id, g, out_acls, merged, result)
                final.append(replace(b, ruleset_id=rid))
            else:
                final.append(b)

        # Interfaces with no inbound ACL.
        named = [f for f in self._ifaces if f.nameif]
        with_in = {b.interface for b in bound if b.direction == "in" and b.interface != "global"}
        no_acl = [f for f in named if f.nameif not in with_in]
        if g is not None:
            for f in no_acl:
                final.append(RuleSetBinding(g, interface=f.nameif, direction="in"))
        elif no_acl and len(named) > 1:
            self._security_levels(named, no_acl, final, result)
        result.bindings.extend(final)

    def _merge_global(
        self, acl: str, g: str, out_acls: set[str], merged: dict[str, str],
        result: ParseResult,
    ) -> str:
        if acl in merged:
            return merged[acl]
        base_rs = result.rulesets[acl]
        g_rs = result.rulesets[g]
        # If the same ACL is also applied outbound, keep it unmerged for that
        # binding and give the inbound binding a merged copy.
        rid = acl if acl not in out_acls else f"{acl}+{g}"
        start = max((r.order for r in base_rs.rules), default=0)
        appended = [
            replace(r, order=start + k + 1)
            for k, r in enumerate(sorted(g_rs.rules, key=lambda r: (r.order, r.id)))
        ]
        if rid == acl:
            base_rs.rules.extend(appended)
        else:
            result.rulesets[rid] = RuleSet(
                id=rid, rules=list(base_rs.rules) + appended,
                default_action=Action.DENY, vendor=_VENDOR)
        result.add_warning(
            WarningLevel.INFO,
            f"global access-list {g} appended after interface access-list {acl} "
            "(interface rules, then global rules, then implicit deny)", rid)
        merged[acl] = rid
        return rid

    def _security_levels(
        self, named: list[_Iface], no_acl: list[_Iface],
        final: list[RuleSetBinding], result: ParseResult,
    ) -> None:
        def level(f: _Iface) -> int:
            if f.level is not None:
                return f.level
            return 100 if f.nameif.lower() == "inside" else 0

        permit_id, deny_id = "asa:security-level:permit", "asa:security-level:deny"
        any_addr = ResolvedAddresses(ANY_CIDRS)
        used: set[str] = set()
        for src in no_acl:
            for dst in named:
                if dst.nameif == src.nameif:
                    continue
                ls, ld = level(src), level(dst)
                ok = ls > ld or (ls == ld and self._same_security_inter)
                rid = permit_id if ok else deny_id
                used.add(rid)
                final.append(RuleSetBinding(
                    rid, interface=src.nameif, direction="in",
                    src_zone=src.nameif, dst_zone=dst.nameif))
            result.add_warning(
                WarningLevel.INFO,
                f"interface {src.nameif} (security-level {level(src)}) has no inbound "
                "access-list: security-level default applies (to lower: permit; "
                "to higher: deny; equal: "
                + ("permit (same-security-traffic)" if self._same_security_inter else "deny")
                + ")", src.nameif)
        for rid, act in ((permit_id, Action.ALLOW), (deny_id, Action.DENY)):
            if rid not in used:
                continue
            rule, _ = build_rule(
                rule_id=f"{rid}#1", action=act, order=1, src=any_addr, dst=any_addr,
                service=ResolvedService((PortRange.any(),)), vendor=_VENDOR,
                raw_ref="security-level default")
            result.rulesets[rid] = RuleSet(
                id=rid, rules=[rule], default_action=act, vendor=_VENDOR)


def _looks_like_ip(tok: str) -> bool:
    return normalize_cidrs(tok) is not None and "/" not in tok
