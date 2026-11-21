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
import socket
import time
from dataclasses import dataclass
from typing import Any

import asyncpg

from .config import settings

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #

def _strip_scheme(t: str) -> str:
    idx = t.find("://")
    if idx != -1:
        return t[idx + 3 :]
    return t


def _strip_userinfo(t: str) -> str:
    # Only the last '@' is the userinfo separator; path-less URL host section
    # cannot contain '@' legitimately.
    at = t.rfind("@")
    if at != -1 and "/" not in t[: at]:
        return t[at + 1 :]
    return t


def _strip_path_and_query(t: str) -> str:
    for sep in ("/", "?", "#"):
        i = t.find(sep)
        if i != -1:
            t = t[:i]
    return t


def normalize(target: str) -> str:
    """Return the canonical host form of `target`.

    Handles: full URL, bare domain, IPv4, IPv6 (bracketed or bare),
    host:port, trailing dot, mixed case.

    >>> normalize("https://Example.COM:8443/foo?q=1")
    'example.com'
    >>> normalize("[2001:db8::1]:443")
    '2001:db8::1'
    """
    if target is None:
        return ""
    t = target.strip()
    if not t:
        return ""
    t = _strip_scheme(t)
    t = _strip_userinfo(t)
    t = _strip_path_and_query(t)

    # Bracketed IPv6 with optional :port
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            host = t[1:end]
            # ignore whatever follows ']' (port)
            try:
                return str(ipaddress.IPv6Address(host)).lower()
            except ValueError:
                return host.lower().rstrip(".")

    # Try bare IPv6 (two or more colons, no square brackets)
    if t.count(":") >= 2:
        try:
            return str(ipaddress.IPv6Address(t)).lower()
        except ValueError:
            # not a valid v6 literal -- fall through to port-stripping
            pass

    # host:port (single colon)
    if ":" in t:
        host, _port = t.rsplit(":", 1)
        t = host

    # Numeric IPv4?
    try:
        return str(ipaddress.IPv4Address(t))
    except ValueError:
        pass

    return t.lower().rstrip(".")


def _is_ip(t: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(t)
    except ValueError:
        return None


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
        decision = ScopeDecision(allow=False, normalized="", reason="empty_target")
        await _write_decision(
            pool,
            target=target or "",
            normalized="",
            allow=False,
            matched_entry_id=None,
            worker=worker,
            reason="empty_target",
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

    ip = _is_ip(normalized)

    matched_entry_id: int | None = None
    allow = False
    resolved_from: str | None = None

    if ip is None:
        # Hostname path: try host rules first.
        allow, matched_entry_id = _match_host_rules(normalized, entries)
        if not allow:
            # Fall back to IP rules via DNS resolution.
            addrs = await dns_cache.resolve(normalized)
            for a in addrs:
                aip = _is_ip(a)
                if aip is None:
                    continue
                allow, matched_entry_id = _match_ip_rules(aip, entries)
                if allow:
                    resolved_from = a
                    break
    else:
        # Numeric IP path: only CIDR rules apply.
        allow, matched_entry_id = _match_ip_rules(ip, entries)

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
