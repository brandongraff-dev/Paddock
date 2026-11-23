"""Shared foundation for the Wargame config parsers.

A parser turns a real firewall or cloud export into the vendor-neutral
:class:`~app.engine.wargame.model.RuleSet` the solver consumes. Every
vendor parser builds on the machinery here so they behave identically on
the things that decide correctness:

* **Object / group resolution.** Real configs name their addresses and
  services and nest groups. :class:`ObjectTable` resolves a token —
  literal, named object, or (nested) group — to concrete CIDRs or port
  ranges, with cycle and depth guards.

* **The honesty rule.** Anything whose real effect the static config
  *cannot* prove is marked ``conditional``. That covers runtime-only
  features (FQDN objects, App-ID, User-ID, dynamic address groups,
  external dynamic lists, URL/geo categories, SD-WAN) and — critically —
  any object we could not resolve. A conditional rule can only ever yield
  a CONDITIONAL hop in the solver, never a PROVED_CONFIG "closed". When in
  doubt we over-approximate toward *reachable* (resolve the unknown to
  "any" and flag it), because a defensive tool must never claim a door is
  shut when it simply failed to read the config.

* **Normalisation.** Hosts, CIDRs, ranges, netmasks and Cisco wildcard
  masks all collapse to canonical CIDR strings; service specs (eq/range/
  lt/gt, named ports, protocol-only) collapse to
  :class:`~app.engine.wargame.model.PortRange` tuples.

Nothing here does I/O. Parsers take already-read text or already-parsed
JSON. Output is deterministic for a fixed input.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from ..model import Action, PortRange, Proto, Rule, RuleSet

_MAX_GROUP_DEPTH = 32
#: Tokens meaning "any address in either family". ``0.0.0.0/0`` and
#: ``0.0.0.0 0.0.0.0`` are deliberately NOT here: they are IPv4-only, and
#: widening them to ``::/0`` would broaden a DENY over IPv6 traffic.
_ANY_TOKENS: frozenset[str] = frozenset({"any", "all", "*"})
_ANY4_TOKENS: frozenset[str] = frozenset({"any4", "0.0.0.0 0.0.0.0"})
_ANY6_TOKENS: frozenset[str] = frozenset({"any6"})
ANY_CIDRS: tuple[str, ...] = ("0.0.0.0/0", "::/0")
ANY4_CIDRS: tuple[str, ...] = ("0.0.0.0/0",)
ANY6_CIDRS: tuple[str, ...] = ("::/0",)


# ---------------------------------------------------------------------------
# The honesty rule: features the static config can't prove
# ---------------------------------------------------------------------------

class ConditionalFeature(str, Enum):
    """Why a rule's real effect can't be proved from config alone."""

    FQDN = "fqdn"                       # resolves at runtime via DNS
    APP_ID = "app_id"                   # L7 app identification
    USER_ID = "user_id"                 # identity-based match
    DYNAMIC_ADDRESS_GROUP = "dynamic_address_group"  # tag-driven, runtime
    EXTERNAL_DYNAMIC_LIST = "external_dynamic_list"   # fetched at runtime
    URL_CATEGORY = "url_category"
    GEO = "geo"                         # geo-IP, data-driven
    SDWAN = "sdwan"                     # path chosen at runtime
    UNRESOLVED = "unresolved_object"    # we could not read the referenced object
    NAT = "nat"                         # address translation changes the match
    SCHEDULE = "schedule"               # rule only active in a time window
    PARTIAL_MATCH = "partial_match"     # matches on fields the model lacks


CONDITIONAL_REASON: dict[ConditionalFeature, str] = {
    ConditionalFeature.FQDN: "address resolves by DNS at runtime; the set of IPs is not fixed in config",
    ConditionalFeature.APP_ID: "match depends on L7 application identification, not on ports",
    ConditionalFeature.USER_ID: "match depends on the authenticated user/group, not on addresses",
    ConditionalFeature.DYNAMIC_ADDRESS_GROUP: "membership is tag-driven and resolved at runtime",
    ConditionalFeature.EXTERNAL_DYNAMIC_LIST: "list contents are fetched at runtime",
    ConditionalFeature.URL_CATEGORY: "match depends on a runtime URL/category lookup",
    ConditionalFeature.GEO: "match depends on a runtime geo-IP lookup",
    ConditionalFeature.SDWAN: "the egress path is chosen at runtime",
    ConditionalFeature.UNRESOLVED: "a referenced object could not be resolved from the supplied config",
    ConditionalFeature.NAT: "address translation (NAT/VIP) means the matched address differs from the real one; both are assumed reachable",
    ConditionalFeature.SCHEDULE: "rule is only active during a schedule / time-range that the static model does not evaluate",
    ConditionalFeature.PARTIAL_MATCH: "rule also matches on a field the model does not represent (source port, ICMP type, protocol number, ...); it was widened",
}


# ---------------------------------------------------------------------------
# Warnings & result
# ---------------------------------------------------------------------------

class WarningLevel(str, Enum):
    INFO = "info"
    UNSUPPORTED = "unsupported"     # a construct we skipped entirely
    UNRESOLVED = "unresolved"       # a named object/group we couldn't find
    CONDITIONAL = "conditional"     # a rule marked conditional, and why


@dataclass
class ParseWarning:
    level: WarningLevel
    message: str
    ref: str = ""                   # source line, object name, rule id

    def __str__(self) -> str:       # pragma: no cover - convenience
        head = f"[{self.level.value}]"
        return f"{head} {self.message}" + (f" ({self.ref})" if self.ref else "")


@dataclass
class RuleSetBinding:
    """Where a RuleSet is enforced, so the graph can attach it to an edge.

    Vendors populate whatever they know: an interface + direction (ASA
    access-group), a zone pair (PAN/Fortinet srcintf/dstintf), or the
    objects it is attached to (AWS SG → ENIs, NACL → subnets).
    """

    ruleset_id: str
    interface: str = ""
    direction: str = ""             # "in" | "out"
    src_zone: str = ""
    dst_zone: str = ""
    attached_to: tuple[str, ...] = ()


@dataclass
class ParseResult:
    """Everything a parser produces: the rule sets, where they bind, and an
    honest list of what it could not fully model."""

    vendor: str
    rulesets: dict[str, RuleSet] = field(default_factory=dict)
    bindings: list[RuleSetBinding] = field(default_factory=list)
    warnings: list[ParseWarning] = field(default_factory=list)

    def add_warning(self, level: WarningLevel, message: str, ref: str = "") -> None:
        self.warnings.append(ParseWarning(level, message, ref))

    def conditional_count(self) -> int:
        return sum(
            1 for rs in self.rulesets.values() for r in rs.rules if r.conditional
        )

    def merge(self, other: "ParseResult") -> "ParseResult":
        """Fold another result into this one (e.g. SGs + NACLs)."""
        self.rulesets.update(other.rulesets)
        self.bindings.extend(other.bindings)
        self.warnings.extend(other.warnings)
        return self


# ---------------------------------------------------------------------------
# Address / service normalisation
# ---------------------------------------------------------------------------

def normalize_cidrs(token: str, mask_style: str = "auto") -> Optional[list[str]]:
    """Normalise an address literal to a list of canonical CIDR strings.

    Accepts: ``any``/``all``/``*`` (both families); ``any4`` /
    ``0.0.0.0 0.0.0.0`` / ``0.0.0.0/0`` (IPv4 only); ``any6`` / ``::/0``
    (IPv6 only); a bare host (``10.0.0.1`` → ``/32``); a CIDR
    (``10.0.0.0/24``, host bits are masked off); an ``addr mask`` pair
    (``10.0.0.0 255.255.255.0``); an ``addr/mask`` pair; an inclusive range
    (``10.0.0.1-10.0.0.9``, summarised to the exact CIDR cover); IPv6 forms.
    Returns ``None`` when the token is not an address literal at all (so the
    caller treats it as an object name, which resolves as UNRESOLVED if no
    such object exists). Never raises.

    ``mask_style`` says how to read the second half of an ``addr mask``
    pair: ``"auto"`` (the historical default) guesses netmask vs Cisco
    wildcard from the leading bit; ``"netmask"`` (ASA, FortiOS) only accepts
    a contiguous netmask, so ``0.0.0.0`` is ``/0`` (not a host); ``"wildcard"``
    only accepts a contiguous wildcard (IOS). An unreadable mask → ``None``.
    """
    if token is None:
        return None
    try:
        t = str(token).strip()
    except Exception:  # pragma: no cover - defensive
        return None
    if not t:
        return None
    low = " ".join(t.lower().split())
    if low in _ANY_TOKENS:
        return list(ANY_CIDRS)
    if low in _ANY4_TOKENS:
        return list(ANY4_CIDRS)
    if low in _ANY6_TOKENS:
        return list(ANY6_CIDRS)

    # addr mask  OR  addr wildcard  (space-separated)
    parts = t.split()
    if len(parts) == 2:
        return _addr_mask(parts[0], parts[1], mask_style)  # may be None

    # range a-b (also "a - b")
    if "-" in t and "/" not in t:
        lo, _, hi = t.partition("-")
        rng = _range_to_cidrs(lo.strip(), hi.strip())
        if rng is not None:
            return rng
    if len(parts) != 1:
        return None

    # addr/mask where mask is dotted (IPv4) e.g. 10.0.0.0/255.255.255.0
    if "/" in t:
        addr, _, mask = t.partition("/")
        if "." in mask and not mask.isdigit():
            return _addr_mask(addr.strip(), mask.strip(), mask_style)

    # plain CIDR or host
    try:
        net = ipaddress.ip_network(t, strict=False)
        return [str(net)]
    except ValueError:
        pass
    try:
        addr = ipaddress.ip_address(t)
        suffix = 32 if addr.version == 4 else 128
        return [f"{addr}/{suffix}"]
    except ValueError:
        return None


def _addr_mask(addr: str, mask: str, mask_style: str = "auto") -> Optional[list[str]]:
    """Resolve ``addr mask`` where mask is a netmask (255.255.255.0),
    a Cisco wildcard (0.0.0.255), or ``host``/a prefix length."""
    addr = addr.strip()
    mask = mask.strip()
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    if mask.lower() == "host":
        return [f"{ip}/{32 if ip.version == 4 else 128}"]
    if mask.isdigit():
        try:
            return [str(ipaddress.ip_network(f"{addr}/{mask}", strict=False))]
        except ValueError:
            return None
    try:
        m = ipaddress.ip_address(mask)
    except ValueError:
        return None
    if m.version != ip.version:
        return None
    as_int = int(m)
    bits = ip.max_prefixlen
    full = (1 << bits) - 1
    if mask_style == "netmask":
        if not _is_contiguous_mask(as_int, bits):
            return None
        netmask_int = as_int
    elif mask_style == "wildcard":
        netmask_int = (~as_int) & full
        if not _is_contiguous_mask(netmask_int, bits):
            return None
    else:
        # Decide netmask vs wildcard by the leading bit: netmasks start 1s,
        # wildcards start 0s. (255.0.0.0 → netmask; 0.0.0.255 → wildcard.)
        if as_int == 0:
            # All-zero mask on a specific host. As a Cisco wildcard this
            # means "match this exact host"; the "match anything" case
            # (0.0.0.0 0.0.0.0) is handled earlier. Netmask-style vendors
            # pass mask_style="netmask" and get /0 instead.
            return [f"{ip}/{bits}"]
        netmask_int = as_int
        if not _is_contiguous_mask(netmask_int, bits):
            netmask_int = (~as_int) & full
            if not _is_contiguous_mask(netmask_int, bits):
                # non-contiguous wildcard (ACLs allow it): not one CIDR; the
                # caller must flag it (unresolved → conditional any).
                return None
    prefix = bin(netmask_int).count("1")
    try:
        return [str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))]
    except ValueError:
        return None


def cidr_family(cidr: str) -> Optional[int]:
    """4 or 6 for a CIDR string, ``None`` if it does not parse."""
    try:
        return ipaddress.ip_network(cidr, strict=False).version
    except ValueError:
        return None


def filter_family(cidrs: "tuple[str, ...] | list[str]", version: int) -> tuple[str, ...]:
    """Keep only the CIDRs of one address family (4 or 6)."""
    return tuple(c for c in cidrs if cidr_family(c) == version)


def exclude_cidrs(
    cidrs: "tuple[str, ...] | list[str]",
    minus: "tuple[str, ...] | list[str]",
) -> list[str]:
    """Exact set difference ``cidrs - minus`` as a minimal list of CIDRs.

    Unparseable entries in ``cidrs`` raise ``ValueError`` (the caller must
    not compute an exact difference over something it could not read);
    unparseable entries in ``minus`` do too, for the same reason.
    """
    nets4: list = []
    nets6: list = []
    for c in cidrs:
        n = ipaddress.ip_network(c, strict=False)
        (nets4 if n.version == 4 else nets6).append(n)
    sub4: list = []
    sub6: list = []
    for c in minus:
        n = ipaddress.ip_network(c, strict=False)
        (sub4 if n.version == 4 else sub6).append(n)
    out: list[str] = []
    for nets, subs in ((nets4, sub4), (nets6, sub6)):
        work = list(ipaddress.collapse_addresses(nets)) if nets else []
        for sub in (ipaddress.collapse_addresses(subs) if subs else []):
            nxt = []
            for n in work:
                if not n.overlaps(sub):
                    nxt.append(n)
                elif sub.supernet_of(n):
                    continue                       # fully removed
                else:                               # n strictly contains sub
                    nxt.extend(n.address_exclude(sub))
            work = nxt
        if work:
            out.extend(str(n) for n in ipaddress.collapse_addresses(work))
    return out


def complement_cidrs(
    cidrs: "tuple[str, ...] | list[str]",
    families: tuple[int, ...] = (4, 6),
) -> list[str]:
    """The exact complement of ``cidrs`` within the given address families
    (used for negated address matches). Raises ``ValueError`` on an
    unparseable entry. An empty result means "matches nothing"."""
    universe = [c for c, v in (("0.0.0.0/0", 4), ("::/0", 6)) if v in families]
    return exclude_cidrs(universe, cidrs)


def cidrs_overlap(a: "tuple[str, ...] | list[str]", b: "tuple[str, ...] | list[str]") -> bool:
    """True if any CIDR in ``a`` overlaps any CIDR in ``b`` (same family)."""
    for x in a:
        try:
            nx = ipaddress.ip_network(x, strict=False)
        except ValueError:
            continue
        for y in b:
            try:
                ny = ipaddress.ip_network(y, strict=False)
            except ValueError:
                continue
            if nx.version == ny.version and nx.overlaps(ny):
                return True
    return False


def _is_contiguous_mask(value: int, bits: int) -> bool:
    """True if ``value`` is 1…10…0 (a valid prefix netmask)."""
    inverted = (~value) & ((1 << bits) - 1)
    # value is contiguous leading-ones iff inverted+1 is a power of two
    return ((inverted + 1) & inverted) == 0


def _range_to_cidrs(lo: str, hi: str) -> Optional[list[str]]:
    try:
        a = ipaddress.ip_address(lo)
        b = ipaddress.ip_address(hi)
    except ValueError:
        return None
    if a.version != b.version or int(b) < int(a):
        return None
    return [str(n) for n in ipaddress.summarize_address_range(a, b)]


# ---------------------------------------------------------------------------
# Service / port normalisation
# ---------------------------------------------------------------------------

#: A pragmatic subset of named services firewalls use. (proto, low, high).
WELL_KNOWN_SERVICES: dict[str, tuple[Proto, int, int]] = {
    "ftp-data": (Proto.TCP, 20, 20),
    "ftp": (Proto.TCP, 21, 21),
    "ssh": (Proto.TCP, 22, 22),
    "telnet": (Proto.TCP, 23, 23),
    "smtp": (Proto.TCP, 25, 25),
    "domain": (Proto.TCP, 53, 53),
    "dns": (Proto.UDP, 53, 53),
    "tftp": (Proto.UDP, 69, 69),
    "http": (Proto.TCP, 80, 80),
    "www": (Proto.TCP, 80, 80),
    "pop3": (Proto.TCP, 110, 110),
    "ntp": (Proto.UDP, 123, 123),
    "netbios-ssn": (Proto.TCP, 139, 139),
    "imap": (Proto.TCP, 143, 143),
    "snmp": (Proto.UDP, 161, 161),
    "ldap": (Proto.TCP, 389, 389),
    "https": (Proto.TCP, 443, 443),
    "smb": (Proto.TCP, 445, 445),
    "microsoft-ds": (Proto.TCP, 445, 445),
    "syslog": (Proto.UDP, 514, 514),
    "ldaps": (Proto.TCP, 636, 636),
    "rdp": (Proto.TCP, 3389, 3389),
    "ms-wbt-server": (Proto.TCP, 3389, 3389),
    "mysql": (Proto.TCP, 3306, 3306),
    "postgresql": (Proto.TCP, 5432, 5432),
    "postgres": (Proto.TCP, 5432, 5432),
    "redis": (Proto.TCP, 6379, 6379),
    "mssql": (Proto.TCP, 1433, 1433),
    "oracle": (Proto.TCP, 1521, 1521),
    "mongodb": (Proto.TCP, 27017, 27017),
    "vnc": (Proto.TCP, 5900, 5900),
    "sip": (Proto.UDP, 5060, 5060),
    "modbus": (Proto.TCP, 502, 502),
    "dnp3": (Proto.TCP, 20000, 20000),
    "s7": (Proto.TCP, 102, 102),
    "bacnet": (Proto.UDP, 47808, 47808),
    "icmp": (Proto.ICMP, 0, 65535),
}

_PROTO_ALIASES: dict[str, Proto] = {
    "tcp": Proto.TCP, "6": Proto.TCP,
    "udp": Proto.UDP, "17": Proto.UDP,
    "icmp": Proto.ICMP, "1": Proto.ICMP, "icmpv6": Proto.ICMP, "icmp6": Proto.ICMP,
    "ipv6-icmp": Proto.ICMP, "58": Proto.ICMP,
    "ip": Proto.ANY, "any": Proto.ANY, "-1": Proto.ANY, "0": Proto.ANY,
}


def proto_from(token: str | int | None) -> Proto:
    """Map a protocol name/number to :class:`Proto`. Unknown → ANY.

    ANY is a *widening* for an unknown protocol (e.g. ``gre``, ``47``): fine
    for an allow, but a DENY of one protocol must not be read as a deny of
    every protocol. Use :func:`proto_is_exact` to decide whether the caller
    has to flag the rule conditional.
    """
    if token is None:
        return Proto.ANY
    return _PROTO_ALIASES.get(str(token).strip().lower(), Proto.ANY)


#: Tokens that genuinely mean "every IP protocol".
_ANY_PROTO_TOKENS: frozenset[str] = frozenset({"ip", "any", "-1", "all"})


def proto_is_exact(token: str | int | None) -> bool:
    """True when :func:`proto_from` represents ``token`` exactly: a
    tcp/udp/icmp alias, or a token meaning "all protocols". False for any
    other protocol (``gre``, ``esp``, ``47``, ``sctp``, garbage), which the
    neutral model can only widen to ANY."""
    if token is None:
        return True
    t = str(token).strip().lower()
    return t in _ANY_PROTO_TOKENS or (t in _PROTO_ALIASES and _PROTO_ALIASES[t] is not Proto.ANY)


def port_from_name(token: str) -> Optional[int]:
    """A numeric port, or a named service's port if unambiguous. ``None``
    when neither (caller decides whether it's an object name)."""
    t = token.strip().lower()
    if t.isdigit():
        n = int(t)
        return n if 0 <= n <= 65535 else None
    svc = WELL_KNOWN_SERVICES.get(t)
    if svc is None or svc[0] not in (Proto.TCP, Proto.UDP):
        return None                 # e.g. "icmp" is not a port
    return svc[1]


def port_range(proto: Proto, low: int, high: Optional[int] = None) -> PortRange:
    """Build a PortRange, clamping to valid bounds and ordering lo ≤ hi.

    Never raises: each end is clamped into 0..65535 *before* ordering, so an
    out-of-range port (``70000``) cannot produce an invalid PortRange."""
    hi = low if high is None else high
    lo_c = max(0, min(65535, int(low)))
    hi_c = max(0, min(65535, int(hi)))
    return PortRange(proto, min(lo_c, hi_c), max(lo_c, hi_c))


def service_from_name(token: str) -> Optional[tuple[PortRange, ...]]:
    """Resolve a named service to port ranges, or ``None`` if not known."""
    t = token.strip().lower()
    if t in _ANY_TOKENS or t in ("ip", "any/any"):
        return (PortRange.any(),)
    svc = WELL_KNOWN_SERVICES.get(t)
    if svc:
        return (port_range(svc[0], svc[1], svc[2]),)
    return None


# ---------------------------------------------------------------------------
# Object table (named addresses/services + nested groups)
# ---------------------------------------------------------------------------

@dataclass
class AddressObject:
    name: str
    cidrs: tuple[str, ...] = ()
    members: tuple[str, ...] = ()               # group member names/literals
    conditional: bool = False
    feature: Optional[ConditionalFeature] = None


@dataclass
class ServiceObject:
    name: str
    ports: tuple[PortRange, ...] = ()
    members: tuple[str, ...] = ()
    conditional: bool = False
    feature: Optional[ConditionalFeature] = None


@dataclass
class ResolvedAddresses:
    cidrs: tuple[str, ...]
    conditional: bool = False
    features: tuple[ConditionalFeature, ...] = ()
    unresolved: tuple[str, ...] = ()


@dataclass
class ResolvedService:
    ports: tuple[PortRange, ...]
    conditional: bool = False
    features: tuple[ConditionalFeature, ...] = ()
    unresolved: tuple[str, ...] = ()


class ObjectTable:
    """Named address/service objects and groups, with safe resolution.

    Resolution never raises: an unknown token resolves to "any" and is
    reported as :attr:`ConditionalFeature.UNRESOLVED`, so a rule that
    references something we couldn't read is conservatively treated as
    *possibly reachable* and can never prove a boundary closed.
    """

    def __init__(self) -> None:
        self.addresses: dict[str, AddressObject] = {}
        self.services: dict[str, ServiceObject] = {}

    # -- registration ------------------------------------------------------
    def add_address(self, obj: AddressObject) -> None:
        self.addresses[obj.name] = obj

    def add_service(self, obj: ServiceObject) -> None:
        self.services[obj.name] = obj

    # -- resolution --------------------------------------------------------
    def resolve_addresses(self, token: str) -> ResolvedAddresses:
        cidrs: list[str] = []
        feats: set[ConditionalFeature] = set()
        unresolved: list[str] = []
        self._resolve_addr(token, cidrs, feats, unresolved, set(), 0)
        # de-dup, stable order
        seen: list[str] = []
        for c in cidrs:
            if c not in seen:
                seen.append(c)
        if not seen:
            # Nothing concrete (an empty group, or one whose only members
            # were cyclic). Never let "empty" silently become a clean "any":
            # widen to any *and* flag it, so a DENY on it can't prove closed.
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(f"{token} (resolves to no addresses)")
            seen = list(ANY_CIDRS)
        return ResolvedAddresses(
            cidrs=tuple(seen),
            conditional=bool(feats),
            features=tuple(sorted(feats, key=lambda f: f.value)),
            unresolved=tuple(dict.fromkeys(unresolved)),
        )

    def _resolve_addr(
        self,
        token: str,
        out: list[str],
        feats: set[ConditionalFeature],
        unresolved: list[str],
        seen: set[str],
        depth: int,
    ) -> None:
        if token in seen or depth > _MAX_GROUP_DEPTH:
            # A cycle (or absurd nesting) means the config is not what we
            # think it is: over-approximate to "any" and flag it, rather than
            # silently contributing nothing.
            why = "group cycle" if token in seen else "group nesting too deep"
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(f"{token} ({why})")
            out.extend(ANY_CIDRS)
            return
        # A user-defined object/group wins over a same-named literal: real
        # configs do name objects, and the table is authoritative.
        obj = self.addresses.get(token)
        if obj is None:
            literal = normalize_cidrs(token)
            if literal is not None:
                out.extend(literal)
                return
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(token)
            out.extend(ANY_CIDRS)
            return
        seen = seen | {token}
        if obj.conditional:
            feat = obj.feature if obj.feature is not None else ConditionalFeature.UNRESOLVED
            feats.add(feat)
            out.extend(obj.cidrs)
            # A NAT/VIP object is exactly its real + mapped addresses (the
            # flag is about *which* one matches). Any other conditional
            # object may hold addresses we could not read (FQDN, dynamic
            # group, a member line we skipped, ...), so it also contributes
            # "any": a partial CIDR list would *narrow* an allow.
            if feat is not ConditionalFeature.NAT or not obj.cidrs:
                out.extend(ANY_CIDRS)
        else:
            out.extend(obj.cidrs)
        for m in obj.members:
            self._resolve_addr(m, out, feats, unresolved, seen, depth + 1)

    def resolve_service(self, token: str) -> ResolvedService:
        ports: list[PortRange] = []
        feats: set[ConditionalFeature] = set()
        unresolved: list[str] = []
        self._resolve_svc(token, ports, feats, unresolved, set(), 0)
        uniq: list[PortRange] = []
        for p in ports:
            if p not in uniq:
                uniq.append(p)
        if not uniq:
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(f"{token} (resolves to no ports)")
            uniq = [PortRange.any()]
        return ResolvedService(
            ports=tuple(uniq),
            conditional=bool(feats),
            features=tuple(sorted(feats, key=lambda f: f.value)),
            unresolved=tuple(dict.fromkeys(unresolved)),
        )

    def _resolve_svc(
        self,
        token: str,
        out: list[PortRange],
        feats: set[ConditionalFeature],
        unresolved: list[str],
        seen: set[str],
        depth: int,
    ) -> None:
        if token in seen or depth > _MAX_GROUP_DEPTH:
            why = "group cycle" if token in seen else "group nesting too deep"
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(f"{token} ({why})")
            out.append(PortRange.any())
            return
        # A user-defined service/group wins over a same-named built-in, and
        # vendor defaults (e.g. FortiGate DNS = tcp+udp/53) differ from the
        # generic table, so the config is authoritative when it defines one.
        obj = self.services.get(token)
        if obj is None:
            named = service_from_name(token)
            if named is not None:
                out.extend(named)
                return
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(token)
            out.append(PortRange.any())
            return
        seen = seen | {token}
        out.extend(obj.ports)
        if obj.conditional:
            feat = obj.feature if obj.feature is not None else ConditionalFeature.UNRESOLVED
            feats.add(feat)
            if feat is ConditionalFeature.UNRESOLVED or not obj.ports:
                # parts of the object could not be read: never narrower
                # than the truth
                out.append(PortRange.any())
        for m in obj.members:
            self._resolve_svc(m, out, feats, unresolved, seen, depth + 1)


# ---------------------------------------------------------------------------
# Rule assembly
# ---------------------------------------------------------------------------

def build_rule(
    *,
    rule_id: str,
    action: Action,
    order: int,
    src: ResolvedAddresses,
    dst: ResolvedAddresses,
    service: ResolvedService,
    vendor: str,
    raw_ref: str = "",
    cost_class: str = "network_rule",
    extra_conditional: bool = False,
    extra_feature: Optional[ConditionalFeature] = None,
    extra_features: "tuple[ConditionalFeature, ...] | list[ConditionalFeature]" = (),
) -> tuple[Rule, list[ParseWarning]]:
    """Assemble a :class:`Rule` from resolved parts, applying the honesty
    rule: the rule is ``conditional`` if any of its addresses/service were
    conditional, or the caller flags an L7/identity feature on the rule
    itself (App-ID, User-ID, …). ``extra_features`` lets a caller flag
    several rule-level features at once (each gets its own warning).

    An empty side (no CIDRs / no ports) is never silently read as a clean
    "any": it widens to any and makes the rule conditional."""
    feats = list(src.features) + list(dst.features) + list(service.features)
    if extra_feature is not None:
        feats.append(extra_feature)
    feats.extend(extra_features)
    empty: list[str] = []
    src_cidrs, dst_cidrs, ports = tuple(src.cidrs), tuple(dst.cidrs), tuple(service.ports)
    if not src_cidrs:
        src_cidrs = ANY_CIDRS
        empty.append("source")
    if not dst_cidrs:
        dst_cidrs = ANY_CIDRS
        empty.append("destination")
    if not ports:
        ports = (PortRange.any(),)
        empty.append("service")
    if empty:
        feats.append(ConditionalFeature.UNRESOLVED)
    conditional = (src.conditional or dst.conditional or service.conditional
                   or extra_conditional or bool(feats))
    rule = Rule(
        id=rule_id,
        action=action,
        order=order,
        src_cidrs=src_cidrs,
        dst_cidrs=dst_cidrs,
        ports=ports,
        vendor=vendor,
        conditional=conditional,
        raw_ref=raw_ref,
        cost_class=cost_class,
    )
    warnings: list[ParseWarning] = []
    for side in empty:
        warnings.append(ParseWarning(
            WarningLevel.UNRESOLVED, f"empty {side}; widened to any", raw_ref))
    for f in dict.fromkeys(feats):
        warnings.append(
            ParseWarning(WarningLevel.CONDITIONAL, CONDITIONAL_REASON[f], raw_ref)
        )
    for u in list(src.unresolved) + list(dst.unresolved) + list(service.unresolved):
        warnings.append(
            ParseWarning(WarningLevel.UNRESOLVED, f"unresolved object: {u}", raw_ref)
        )
    return rule, warnings


def _covered(cidr: str, among: "list[str] | tuple[str, ...]") -> bool:
    try:
        n = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return cidr in among
    for c in among:
        try:
            m = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if m.version == n.version and m.supernet_of(n):
            return True
    return False


def apply_nat_overapprox(
    rule: Rule,
    nat_pairs: "list[tuple[tuple[str, ...], tuple[str, ...]]]",
) -> tuple[Rule, bool]:
    """Over-approximate a rule across address translation.

    ``nat_pairs`` are ``(real_cidrs, mapped_cidrs)`` translations. Whether a
    firewall matches a rule on the real or the mapped address depends on
    vendor/version (ASA 8.3+ real, PAN-OS pre-NAT destination, ...), and the
    topology may describe either. So wherever a rule side overlaps one half
    of a translation, the other half is added and the rule is flagged
    ``conditional``. Returns ``(rule, changed)``.
    """
    from dataclasses import replace as _replace

    src, dst = list(rule.src_cidrs), list(rule.dst_cidrs)
    changed = False
    for real, mapped in nat_pairs:
        for side in (src, dst):
            snapshot = tuple(side)
            for a, b in ((real, mapped), (mapped, real)):
                if a and b and cidrs_overlap(snapshot, a):
                    for c in b:
                        if not _covered(c, side):
                            side.append(c)
                            changed = True
    if not changed:
        return rule, False
    return _replace(rule, src_cidrs=tuple(src), dst_cidrs=tuple(dst), conditional=True), True


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class Parser:
    """Base class for a vendor parser."""

    vendor: str = ""

    def parse(self, raw: Any, **opts: Any) -> ParseResult:  # pragma: no cover
        raise NotImplementedError


_PARSERS: dict[str, Callable[[], Parser]] = {}


def register(vendor: str) -> Callable[[type[Parser]], type[Parser]]:
    def deco(cls: type[Parser]) -> type[Parser]:
        cls.vendor = vendor
        _PARSERS[vendor] = cls
        return cls

    return deco


def available_vendors() -> list[str]:
    return sorted(_PARSERS)


def get_parser(vendor: str) -> Parser:
    try:
        return _PARSERS[vendor]()
    except KeyError:
        raise KeyError(
            f"no parser for {vendor!r}; have {available_vendors()}"
        ) from None


def parse(vendor: str, raw: Any, **opts: Any) -> ParseResult:
    """Parse ``raw`` with the named vendor parser."""
    return get_parser(vendor).parse(raw, **opts)
