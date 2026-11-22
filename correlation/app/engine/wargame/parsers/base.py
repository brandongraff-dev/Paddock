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
_ANY_TOKENS: frozenset[str] = frozenset(
    {"any", "all", "any4", "any6", "0.0.0.0/0", "::/0", "0.0.0.0 0.0.0.0", "*"}
)
ANY_CIDRS: tuple[str, ...] = ("0.0.0.0/0", "::/0")


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

def normalize_cidrs(token: str) -> Optional[list[str]]:
    """Normalise an address literal to a list of canonical CIDR strings.

    Accepts: ``any``/``all``/``*``; a bare host (``10.0.0.1`` → ``/32``);
    a CIDR (``10.0.0.0/24``); an ``addr mask`` pair (``10.0.0.0
    255.255.255.0``); an ``addr/mask`` pair; an inclusive range
    (``10.0.0.1-10.0.0.9``); IPv6 forms. Returns ``None`` when the token is
    not an address literal at all (so the caller treats it as an object
    name). Never raises.
    """
    if token is None:
        return None
    t = token.strip()
    if not t:
        return None
    if t.lower() in _ANY_TOKENS:
        return list(ANY_CIDRS)

    # addr mask  OR  addr wildcard  (space-separated)
    parts = t.split()
    if len(parts) == 2:
        got = _addr_mask(parts[0], parts[1])
        return got  # may be None if not parseable

    # range a-b
    if "-" in t and "/" not in t:
        lo, _, hi = t.partition("-")
        rng = _range_to_cidrs(lo.strip(), hi.strip())
        if rng is not None:
            return rng

    # addr/mask where mask is dotted (IPv4) e.g. 10.0.0.0/255.255.255.0
    if "/" in t:
        addr, _, mask = t.partition("/")
        if "." in mask and not mask.isdigit():
            got = _addr_mask(addr.strip(), mask.strip())
            if got is not None:
                return got

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


def _addr_mask(addr: str, mask: str) -> Optional[list[str]]:
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
    # Decide netmask vs wildcard by the leading bit: netmasks start 1s,
    # wildcards start 0s. (255.0.0.0 → netmask; 0.0.0.255 → wildcard.)
    as_int = int(m)
    bits = ip.max_prefixlen
    if as_int == 0:
        # All-zero mask on a specific host. As a Cisco wildcard this means
        # "match this exact host"; the "match anything" case (0.0.0.0
        # 0.0.0.0) is handled earlier via _ANY_TOKENS. So treat it as /32.
        return [f"{ip}/{bits}"]
    # A proper (contiguous) netmask?
    netmask_int = as_int
    is_netmask = _is_contiguous_mask(netmask_int, bits)
    if not is_netmask:
        # treat as wildcard: invert
        netmask_int = (~as_int) & ((1 << bits) - 1)
        if not _is_contiguous_mask(netmask_int, bits):
            # non-contiguous wildcard (ACLs allow it) — can't express as a
            # single CIDR; over-approximate to the host's /prefix by the
            # number of set bits, flagged by the caller via unresolved.
            return None
    prefix = bin(netmask_int).count("1")
    try:
        return [str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))]
    except ValueError:
        return None


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
    "icmp": Proto.ICMP, "1": Proto.ICMP, "icmpv6": Proto.ICMP, "58": Proto.ICMP,
    "ip": Proto.ANY, "any": Proto.ANY, "-1": Proto.ANY, "0": Proto.ANY,
}


def proto_from(token: str | int | None) -> Proto:
    """Map a protocol name/number to :class:`Proto`. Unknown → ANY."""
    if token is None:
        return Proto.ANY
    return _PROTO_ALIASES.get(str(token).strip().lower(), Proto.ANY)


def port_from_name(token: str) -> Optional[int]:
    """A numeric port, or a named service's port if unambiguous. ``None``
    when neither (caller decides whether it's an object name)."""
    t = token.strip().lower()
    if t.isdigit():
        n = int(t)
        return n if 0 <= n <= 65535 else None
    svc = WELL_KNOWN_SERVICES.get(t)
    return svc[1] if svc else None


def port_range(proto: Proto, low: int, high: Optional[int] = None) -> PortRange:
    """Build a PortRange, clamping to valid bounds and ordering lo ≤ hi."""
    hi = low if high is None else high
    low, hi = min(low, hi), max(low, hi)
    return PortRange(proto, max(0, low), min(65535, hi))


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
        return ResolvedAddresses(
            cidrs=tuple(seen) if seen else ANY_CIDRS,
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
        if depth > _MAX_GROUP_DEPTH or token in seen:
            return
        literal = normalize_cidrs(token)
        if literal is not None:
            out.extend(literal)
            return
        obj = self.addresses.get(token)
        if obj is None:
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(token)
            out.extend(ANY_CIDRS)
            return
        seen = seen | {token}
        if obj.conditional and obj.feature is not None:
            feats.add(obj.feature)
            # a conditional object still contributes any CIDRs it has, plus
            # "any" so the over-approximation is safe
            out.extend(obj.cidrs or ANY_CIDRS)
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
        return ResolvedService(
            ports=tuple(uniq) if uniq else (PortRange.any(),),
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
        if depth > _MAX_GROUP_DEPTH or token in seen:
            return
        named = service_from_name(token)
        if named is not None:
            out.extend(named)
            return
        obj = self.services.get(token)
        if obj is None:
            feats.add(ConditionalFeature.UNRESOLVED)
            unresolved.append(token)
            out.append(PortRange.any())
            return
        seen = seen | {token}
        if obj.conditional and obj.feature is not None:
            feats.add(obj.feature)
        out.extend(obj.ports)
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
) -> tuple[Rule, list[ParseWarning]]:
    """Assemble a :class:`Rule` from resolved parts, applying the honesty
    rule: the rule is ``conditional`` if any of its addresses/service were
    conditional, or the caller flags an L7/identity feature on the rule
    itself (App-ID, User-ID, …)."""
    conditional = src.conditional or dst.conditional or service.conditional or extra_conditional
    rule = Rule(
        id=rule_id,
        action=action,
        order=order,
        src_cidrs=tuple(src.cidrs),
        dst_cidrs=tuple(dst.cidrs),
        ports=tuple(service.ports) or (PortRange.any(),),
        vendor=vendor,
        conditional=conditional,
        raw_ref=raw_ref,
        cost_class=cost_class,
    )
    warnings: list[ParseWarning] = []
    feats = list(src.features) + list(dst.features) + list(service.features)
    if extra_feature is not None:
        feats.append(extra_feature)
    for f in dict.fromkeys(feats):
        warnings.append(
            ParseWarning(WarningLevel.CONDITIONAL, CONDITIONAL_REASON[f], raw_ref)
        )
    for u in list(src.unresolved) + list(dst.unresolved) + list(service.unresolved):
        warnings.append(
            ParseWarning(WarningLevel.UNRESOLVED, f"unresolved object: {u}", raw_ref)
        )
    return rule, warnings


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
