"""Scope service: the authorized-target allowlist and its audit log.

This is the enforcement point. Every worker MUST call `check()` before it
touches a target; every call writes a row to `scope_decisions` so the
audit trail is complete, whether the decision was allow or deny.

Normalisation is deliberately conservative: we strip the things that are
unambiguously not identity (scheme, path, user-info, port, square-brackets
around IPv6), lowercase, and trim a trailing dot. Everything else is left
alone. If a caller gives us garbage, we deny-fail-closed and audit it.

Scope-kind semantics:

- `domain`              exact match on the normalized hostname
- `subdomain_wildcard`  matches the base AND any depth of subdomain
                        (`example.com` AND `a.b.example.com` both match the
                        entry whose value is `example.com`)
- `ipv4_cidr`           containment via `ipaddress`
- `ipv6_cidr`           containment via `ipaddress`
- `asn`                 unsupported in this MVP; logged and skipped

If the target is a hostname and no hostname rule matches, we resolve it
to IPs via `socket.getaddrinfo` (60s cache, fail-closed on error) and try
the CIDR rules against each resolved address.

Defensive note: this module exposes no 'bypass', 'ignore', or 'override'
helpers. The only way a target is allowed is by matching an active
scope_entries row. Attack-aid helpers (exploit launchers, stealth
configs, credential testers) are categorically out of scope -- see
docs/CONTRACTS.md "Do-not-build list".
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import asyncpg

from .config import settings

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Normalization
#
# Threat model: a scope check is only as good as the agreement between OUR
# parse of a target and the parse done by whatever tool eventually opens the
# socket (httpx, Go's net/url in nuclei/naabu, Chromium in the screenshotter).
# Any input where those parsers could disagree -- "parser differentials" -- is
# a potential scope bypass (e.g. ``http://evil.com#@target.com`` used to
# normalize to ``target.com`` while httpx connected to ``evil.com``).
#
# So normalization is STRICT and fail-closed: we extract the authority exactly
# as RFC 3986 / WHATWG do (it ends at the first '/', '?' or '#'), and we refuse
# anything that real-world parsers treat inconsistently (backslashes, control
# characters, whitespace, percent-encoding in the host, empty labels, bad
# ports). Legacy IPv4 spellings (``0x7f.1``, ``2130706433``) are canonicalised
# the way browsers and libc do, and IPv4-mapped IPv6 collapses to IPv4, so the
# CIDR rules and guardrails see the address the socket will really reach.
#
# The differential fuzzer in tests/test_scope_adversarial.py holds this
# function to that contract against a WHATWG (Ada) and an RFC 3986 parser.
# --------------------------------------------------------------------------- #

# Never legitimate anywhere in a target; WHATWG silently strips some of them
# (tab, CR, LF) which is exactly the kind of disagreement we refuse.
_FORBIDDEN_ANYWHERE = re.compile("[\x00-\x20\x7f-\x9f\u00a0\u1680\u2000-\u200f\u2028-\u202f\u205f\u3000\ufeff]")
# Never legitimate in the authority; WHATWG reads '\\' as '/', and percent-
# encoding in a host is decoded by some parsers and not others.
_FORBIDDEN_IN_AUTHORITY = re.compile(r'[\\%<>"`{}|^]')
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_NUMERICISH_LABEL = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")


def _canonical_ipv4(host: str) -> str | None:
    """Parse ``host`` as an IPv4 address using WHATWG/inet_aton rules.

    Returns dotted-quad, or None if the host is not numeric. Raises
    ValueError when the host *looks* numeric (its last label is a number)
    but is not a valid address -- browsers refuse those, and so do we.
    """
    labels = host.split(".")
    if labels and labels[-1] == "":
        labels = labels[:-1]
    if not labels or not _NUMERICISH_LABEL.match(labels[-1]):
        return None
    if len(labels) > 4:
        raise ValueError("too many ipv4 parts")
    nums: list[int] = []
    for lab in labels:
        if not _NUMERICISH_LABEL.match(lab):
            raise ValueError("non-numeric ipv4 part")
        if lab.startswith("0x"):
            n = int(lab[2:] or "0", 16)
        elif len(lab) > 1 and lab.startswith("0"):
            if any(c not in "01234567" for c in lab):
                raise ValueError("bad octal ipv4 part")
            n = int(lab, 8)
        else:
            n = int(lab)
        nums.append(n)
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(nums)):
        raise ValueError("ipv4 part out of range")
    value = last
    for i, n in enumerate(head):
        value += n << (8 * (3 - i))
    return str(ipaddress.IPv4Address(value))


def _canonical_ipv6(host: str) -> str:
    """Canonical IPv6, collapsing IPv4-mapped addresses to dotted IPv4."""
    if "%" in host:  # zone ids are interface-local; never a scan target
        raise ValueError("ipv6 zone id")
    addr = ipaddress.IPv6Address(host)
    if addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _canonical_hostname(host: str) -> str:
    """IDNA-normalise and validate a DNS hostname. Raises ValueError."""
    if host.endswith("."):
        host = host[:-1]  # exactly one root dot is legal; '..' fails below
    if not host:
        raise ValueError("empty host")
    if not host.isascii():
        # Same mapping a browser applies (nameprep/NFKC + punycode), so
        # fullwidth 'ｅｘａｍｐｌｅ.com' and 'example.com' are one identity.
        host = host.encode("idna").decode("ascii")
    host = host.lower()
    if len(host) > 253:
        raise ValueError("hostname too long")
    for label in host.split("."):
        if not _LABEL_RE.match(label):
            raise ValueError(f"invalid label {label!r}")
    return host


def strict_normalize(target: str | None) -> str:
    """Return the canonical host of ``target`` or raise ValueError.

    Accepts: full URL, bare host, host:port, IPv4 (incl. legacy forms),
    IPv6 (bracketed, or bare without a port), trailing root dot, mixed case,
    and internationalised names. Rejects anything ambiguous.
    """
    if target is None:
        raise ValueError("empty target")
    # Trim plain spaces only. Tabs/CR/LF are rejected below rather than
    # trimmed: a tool handed the raw string would not trim them the same way.
    t = target.strip(" ")
    if not t:
        raise ValueError("empty target")
    if len(t) > 2048:
        raise ValueError("target too long")
    if _FORBIDDEN_ANYWHERE.search(t):
        raise ValueError("forbidden character in target")

    # Scheme
    idx = t.find("://")
    has_scheme = idx != -1
    if has_scheme:
        if not _SCHEME_RE.match(t[:idx]):
            raise ValueError("invalid scheme")
        t = t[idx + 3 :]

    # Authority ends at the FIRST '/', '?' or '#' -- exactly as RFC 3986 and
    # WHATWG define it. Everything after that is path/query/fragment and can
    # never contribute to the host, no matter how many '@'s it contains.
    m = re.search(r"[/?#]", t)
    authority = t[: m.start()] if m else t
    if _FORBIDDEN_IN_AUTHORITY.search(authority):
        raise ValueError("forbidden character in host")

    # Userinfo: only the LAST '@' inside the authority separates it.
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if not authority:
        raise ValueError("empty host")

    # Bracketed IPv6 with optional :port
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise ValueError("unterminated ipv6 literal")
        rest = authority[end + 1 :]
        if rest and not re.fullmatch(r":\d{0,5}", rest):
            raise ValueError("garbage after ipv6 literal")
        return _canonical_ipv6(authority[1:end])

    # Bare IPv6 (no port possible without brackets). Inside a URL it MUST be
    # bracketed; bare, it must be the WHOLE target (no path) and must not end
    # in ':' ("c1::" reads as host "c1" + empty port to a URL parser).
    if authority.count(":") >= 2:
        if has_scheme or m is not None or "@" in t or authority.endswith(":"):
            raise ValueError("ambiguous unbracketed ipv6")
        return _canonical_ipv6(authority)

    # host:port
    if ":" in authority:
        host, port = authority.rsplit(":", 1)
        if not port.isdigit() or int(port) > 65535:
            raise ValueError("invalid port")
    else:
        host = authority

    # WHATWG order: map to ASCII (IDNA) FIRST, then decide whether the result
    # is an IPv4 address. Otherwise '１２７.0.0.1' or '¹' would skip the
    # IPv4 parser here while a browser happily connects to 127.0.0.1 / 0.0.0.1.
    if not host.isascii():
        host = host.encode("idna").decode("ascii")
    v4 = _canonical_ipv4(host.lower())
    if v4 is not None:
        return v4
    return _canonical_hostname(host)


def normalize(target: str | None) -> str:
    """Return the canonical host form of `target`, or "" if it is rejected.

    Kept as the non-raising API used across the codebase: an empty string
    always means *deny*.

    >>> normalize("https://Example.COM:8443/foo?q=1")
    'example.com'
    >>> normalize("[2001:db8::1]:443")
    '2001:db8::1'
    >>> normalize("http://evil.com#@target.com")
    'evil.com'
    """
    try:
        return strict_normalize(target)
    except (ValueError, UnicodeError):
        return ""


def _is_ip(t: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(t)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Guardrails: addresses that are never a legitimate ASM target
#
# Even when a hostname is in scope, the address it RESOLVES to may not be:
# an in-scope name with a dangling or hostile DNS record can point at cloud
# instance metadata (credential theft from the scanner's own cloud account),
# at the scanner's own private network, or at loopback. These rules are
# checked against every resolved address of an allowed hostname.
#
# * HARD_DENY  -- never allowed, no scope entry can override it.
# * PRIVATE    -- allowed only when an explicit CIDR scope entry covers the
#                 address. A *hostname* rule alone never authorises a
#                 private/loopback/link-local destination.
# --------------------------------------------------------------------------- #

HARD_DENY_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.169.254/32",  # AWS/GCP/Azure/OCI/DO instance metadata
        "169.254.170.2/32",    # AWS ECS task metadata
        "100.100.100.200/32",  # Alibaba Cloud metadata
        "168.63.129.16/32",    # Azure WireServer
        "fd00:ec2::254/128",   # AWS IMDS over IPv6
        "0.0.0.0/8",           # "this network"
        "224.0.0.0/4",         # multicast
        "240.0.0.0/4",         # reserved / broadcast
        "::/128",
        "ff00::/8",            # multicast
    )
)


def hard_denied(ip: ipaddress._BaseAddress) -> bool:
    return any(ip.version == n.version and ip in n for n in HARD_DENY_NETS)


def _unmap(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def is_internal(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified
        or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"))
    )


# --------------------------------------------------------------------------- #
# Decision object
# --------------------------------------------------------------------------- #

@dataclass
class ScopeDecision:
    allow: bool
    normalized: str
    reason: str = ""
    matched_entry_id: int | None = None

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "allow": self.allow,
            "normalized": self.normalized,
            "reason": self.reason,
        }
        if self.matched_entry_id is not None:
            d["matched_entry"] = self.matched_entry_id
        return d


# --------------------------------------------------------------------------- #
# Caches: active scope entries + DNS resolution
# --------------------------------------------------------------------------- #

class ScopeCache:
    """Process-local cache of active scope_entries.

    Reload is debounced; concurrent reloads collapse to a single DB read
    behind an asyncio.Lock.
    """

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []
        self._loaded_at: float = 0.0
        self._lock = asyncio.Lock()

    def invalidate(self) -> None:
        self._loaded_at = 0.0

    async def entries(self, pool: asyncpg.Pool) -> list[dict[str, Any]]:
        if time.monotonic() - self._loaded_at < settings.scope_cache_ttl_sec and self._rows:
            return self._rows
        async with self._lock:
            # re-check under lock
            if time.monotonic() - self._loaded_at < settings.scope_cache_ttl_sec and self._rows:
                return self._rows
            async with pool.acquire() as con:
                rows = await con.fetch(
                    """
                    SELECT id, kind, value, expires_at
                      FROM scope_entries
                     WHERE active = TRUE
                       AND (expires_at IS NULL OR expires_at > NOW())
                    """
                )
            self._rows = [dict(r) for r in rows]
            self._loaded_at = time.monotonic()
            return self._rows


class DNSCache:
    """Tiny TTL cache for getaddrinfo results. Fail-closed."""

    def __init__(self) -> None:
        self._by_host: dict[str, tuple[float, list[str]]] = {}
        self._lock = asyncio.Lock()

    async def resolve(self, host: str) -> list[str]:
        now = time.monotonic()
        hit = self._by_host.get(host)
        if hit and now - hit[0] < settings.dns_cache_ttl_sec:
            return hit[1]
        async with self._lock:
            hit = self._by_host.get(host)
            if hit and time.monotonic() - hit[0] < settings.dns_cache_ttl_sec:
                return hit[1]
            try:
                loop = asyncio.get_running_loop()
                infos = await loop.run_in_executor(
                    None, lambda: socket.getaddrinfo(host, None)
                )
                addrs = sorted({info[4][0] for info in infos})
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "dns_resolve_failed", extra={"host": host, "err": str(exc)}
                )
                # fail-closed: no addresses on error
                addrs = []
            self._by_host[host] = (time.monotonic(), addrs)
            return addrs


scope_cache = ScopeCache()
dns_cache = DNSCache()


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

def _match_domain(normalized: str, entry_value: str) -> bool:
    return normalized == entry_value.lower().rstrip(".")


def _match_subdomain_wildcard(normalized: str, entry_value: str) -> bool:
    base = entry_value.lower().rstrip(".").lstrip("*.")
    if normalized == base:
        return True
    return normalized.endswith("." + base)


def _match_cidr(ip: ipaddress._BaseAddress, entry_value: str) -> bool:
    try:
        net = ipaddress.ip_network(entry_value, strict=False)
    except ValueError:
        return False
    if ip.version != net.version:
        return False
    return ip in net


def _match_host_rules(
    normalized: str, entries: list[dict[str, Any]]
) -> tuple[bool, int | None]:
    """Try `domain` and `subdomain_wildcard` entries against a hostname."""
    for e in entries:
        kind = e["kind"]
        value = e["value"]
        if kind == "domain" and _match_domain(normalized, value):
            return True, e["id"]
        if kind == "subdomain_wildcard" and _match_subdomain_wildcard(normalized, value):
            return True, e["id"]
    return False, None


def _match_ip_rules(
    ip: ipaddress._BaseAddress, entries: list[dict[str, Any]]
) -> tuple[bool, int | None]:
    want_kind = "ipv4_cidr" if ip.version == 4 else "ipv6_cidr"
    for e in entries:
        kind = e["kind"]
        value = e["value"]
        if kind == want_kind and _match_cidr(ip, value):
            return True, e["id"]
        if kind == "asn":
            # ASN resolution is out of scope for the MVP; log once per call.
            logger.debug("scope_asn_skipped", extra={"entry_id": e.get("id"), "value": value})
            continue
    return False, None


# --------------------------------------------------------------------------- #
# Decision + audit
# --------------------------------------------------------------------------- #

async def _write_decision(
    pool: asyncpg.Pool,
    *,
    target: str,
    normalized: str,
    allow: bool,
    matched_entry_id: int | None,
    worker: str,
    reason: str,
) -> None:
    sql = """
        INSERT INTO scope_decisions
            (target, normalized, decision, matched_entry, worker, reason)
        VALUES ($1, $2, $3, $4, $5, $6)
    """
    async with pool.acquire() as con:
        await con.execute(
            sql,
            target,
            normalized,
            "allow" if allow else "deny",
            matched_entry_id,
            worker,
            reason or ("match" if allow else "no matching active scope_entry"),
        )


async def check(
    pool: asyncpg.Pool,
    target: str,
    worker: str,
    reason: str = "",
) -> ScopeDecision:
    """Decide whether `target` is in scope, write an audit row, and return.

    Always writes a `scope_decisions` row. Fails closed if normalisation
    produces an empty string.
    """
    normalized = normalize(target)
    if not normalized:
        why = "empty_target" if not (target or "").strip() else "rejected_target: malformed or ambiguous"
        decision = ScopeDecision(allow=False, normalized="", reason=why)
        await _write_decision(
            pool,
            target=(target or "")[:2048],
            normalized="",
            allow=False,
            matched_entry_id=None,
            worker=worker,
            reason=why,
        )
        return decision

    entries = await scope_cache.entries(pool)
    if not entries:
        await _write_decision(
            pool,
            target=target,
            normalized=normalized,
            allow=False,
            matched_entry_id=None,
            worker=worker,
            reason="no_active_scope_entries",
        )
        return ScopeDecision(
            allow=False, normalized=normalized, reason="no_active_scope_entries"
        )

    # Expiry is enforced at decision time, not only at cache-load time, so an
    # entry can't outlive its authorisation window by up to a cache TTL.
    now = datetime.now(UTC)
    entries = [
        e for e in entries
        if e.get("expires_at") is None or _aware(e["expires_at"]) > now
    ]

    ip = _is_ip(normalized)

    matched_entry_id: int | None = None
    allow = False
    resolved_from: str | None = None
    guard_reason: str | None = None

    if ip is None:
        # Hostname path: try host rules first.
        allow, matched_entry_id = _match_host_rules(normalized, entries)
        addrs = await dns_cache.resolve(normalized)
        resolved = [a for a in (_is_ip(x) for x in addrs) if a is not None]
        resolved = [_unmap(a) for a in resolved]
        if allow:
            # The NAME is authorised -- but every address it resolves to
            # must also be a legitimate destination (anti-rebinding / SSRF).
            for a in resolved:
                if hard_denied(a):
                    guard_reason = f"guardrail: {normalized} resolves to protected address {a}"
                    break
                if is_internal(a) and not _match_ip_rules(a, entries)[0]:
                    guard_reason = (
                        f"guardrail: {normalized} resolves to internal address {a} "
                        "not covered by an explicit CIDR scope entry"
                    )
                    break
            if guard_reason:
                allow, matched_entry_id = False, None
        else:
            # Fall back to IP rules: EVERY resolved address must be in scope,
            # otherwise a round-robin record could steer a tool outside it.
            if resolved and not any(hard_denied(a) for a in resolved):
                hits = [_match_ip_rules(a, entries) for a in resolved]
                if all(h[0] for h in hits):
                    allow, matched_entry_id = hits[0]
                    resolved_from = str(resolved[0])
                elif any(h[0] for h in hits):
                    guard_reason = "guardrail: only some resolved addresses are in scope"
    else:
        # Numeric IP path: only CIDR rules apply; protected addresses never.
        if hard_denied(ip):
            guard_reason = f"guardrail: {ip} is a protected address"
        else:
            allow, matched_entry_id = _match_ip_rules(ip, entries)

    if guard_reason:
        logger.warning("scope_guardrail_deny", extra={"target": target, "why": guard_reason})
        reason = guard_reason

    if allow:
        decision_reason = reason or (
            f"match via {resolved_from}" if resolved_from else "match"
        )
    else:
        decision_reason = reason or "no matching active scope_entry"

    await _write_decision(
        pool,
        target=target,
        normalized=normalized,
        allow=allow,
        matched_entry_id=matched_entry_id,
        worker=worker,
        reason=decision_reason,
    )

    return ScopeDecision(
        allow=allow,
        normalized=normalized,
        matched_entry_id=matched_entry_id,
        reason=decision_reason,
    )
