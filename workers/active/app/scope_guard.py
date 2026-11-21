"""Scope guard: defense in depth.

Every packet this service emits passes through here first. The authoritative
check is the orchestrator's /v1/scope/check — this layer adds:

* a short TTL cache so we are not rate-limited by our own API
* an httpx event hook that re-checks on every redirect
* a subprocess pre-flight that aborts before the binary even starts
* an output filter that drops tool output rows for hosts that fell out of scope
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
import structlog

from app import tenancy
from app.config import settings
from app.orchestrator import OrchestratorClient

log = structlog.get_logger(__name__)


class ScopeDenied(RuntimeError):
    """The scope guard refused a target. No retry: fix the scope or walk away."""

    def __init__(self, target: str, reason: str, normalized: str | None = None):
        super().__init__(f"scope denied: {target!r}: {reason}")
        self.target = target
        self.normalized = normalized or target
        self.reason = reason


@dataclass
class ScopeDecision:
    allow: bool
    normalized: str
    matched_entry: int | None
    reason: str
    cached_at: float
    # Addresses the orchestrator vetted for this target. Connections to the
    # target MUST go to one of these (see ``ScopeGuard.vetted_addrs``).
    resolved_ips: tuple[str, ...] = ()


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")


def normalize_target(target: str) -> str:
    """Best-effort client-side normalization.

    Strips scheme/path, lowercases, drops default ports. The orchestrator
    performs the authoritative normalization; this is only for the cache key.
    """
    t = target.strip()
    if "://" in t:
        parts = urlsplit(t)
        host = parts.hostname or ""
        port = parts.port
        default = {"http": 80, "https": 443}.get(parts.scheme.lower())
        if port and port != default:
            return f"{host.lower()}:{port}"
        return host.lower()
    # host[:port]
    return t.lower()


class ScopeGuard:
    """Per-request scope re-checker with a tiny TTL cache."""

    def __init__(
        self,
        orchestrator: OrchestratorClient,
        *,
        ttl_sec: int | None = None,
    ):
        self._orch = orchestrator
        self._ttl = ttl_sec if ttl_sec is not None else settings.scope_cache_ttl_sec
        self._cache: dict[str, ScopeDecision] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _ckey(key: str) -> str:
        return f"{tenancy.current_tenant_id()}|{key}"

    # -------- primary check -----------------------------------------------

    async def allow(self, target: str) -> ScopeDecision:
        """Return a ScopeDecision for ``target`` or raise ScopeDenied.

        The caller MUST not emit a request if this raises.
        """
        key = normalize_target(target)
        # Cache per TENANT: a worker runs jobs of many tenants, and tenant A's
        # allowed target must never authorise tenant B's scan of the same name.
        ckey = self._ckey(key)
        now = time.time()
        cached = self._cache.get(ckey)
        if cached and (now - cached.cached_at) < self._ttl:
            # fail-closed on stale cache is handled by the ttl expiry
            if not cached.allow:
                raise ScopeDenied(target, cached.reason, cached.normalized)
            return cached

        # miss: ask the orchestrator (serialized per-key would be nicer; the
        # lock here prevents a stampede if many concurrent jobs share a target).
        async with self._lock:
            cached = self._cache.get(ckey)
            if cached and (time.time() - cached.cached_at) < self._ttl:
                if not cached.allow:
                    raise ScopeDenied(target, cached.reason, cached.normalized)
                return cached
            try:
                resp = await self._orch.scope_check(target)
            except Exception as e:  # fail-closed
                raise ScopeDenied(target, f"scope-check failed: {e}") from e

            dec = ScopeDecision(
                allow=bool(resp.get("allow")),
                normalized=resp.get("normalized") or key,
                matched_entry=resp.get("matched_entry"),
                reason=resp.get("reason") or ("ok" if resp.get("allow") else "denied"),
                cached_at=time.time(),
                resolved_ips=tuple(str(x) for x in (resp.get("resolved_ips") or ()) if x),
            )
            self._cache[ckey] = dec

        if not dec.allow:
            log.warning("scope.deny", target=target, normalized=dec.normalized, reason=dec.reason)
            raise ScopeDenied(target, dec.reason, dec.normalized)
        log.debug("scope.allow", target=target, normalized=dec.normalized, matched=dec.matched_entry)
        return dec

    async def is_allowed(self, target: str) -> bool:
        """Non-raising variant used by output filters."""
        try:
            await self.allow(target)
            return True
        except ScopeDenied:
            return False

    # -------- pinned addresses (anti DNS-rebinding) -------------------------

    async def vetted_addrs(self, target: str) -> list[str]:
        """Scope-check ``target`` and return the addresses a connection may use.

        The orchestrator resolved and vetted these (HARD_DENY nets, internal
        ranges, rebinding checks). Connect to them and NOTHING else: resolving
        the name again here would let a hostile DNS server answer a public
        address for the check and 169.254.169.254 / an internal IP for the
        connect. Raises ScopeDenied when out of scope or when no vetted
        address exists (fail closed).
        """
        dec = await self.allow(target)
        host = _host_of(target)
        lit = _ip_or_none(host)
        cands = [str(lit)] if lit is not None else list(dec.resolved_ips)
        out: list[str] = []
        for c in cands:
            ip = _ip_or_none(c)
            if ip is None:
                continue
            if _never_dial(ip):
                raise ScopeDenied(target, f"guardrail: {ip} is a protected address", dec.normalized)
            out.append(str(ip))
        if not out:
            raise ScopeDenied(target, "no vetted addresses for this host (refusing to resolve it myself)",
                              dec.normalized)
        return out

    def pinned_transport(self, *, verify: Any = True) -> httpx.AsyncBaseTransport:
        from app.pinned import VettedTransport

        return VettedTransport(self, verify=verify)

    # -------- httpx integration -------------------------------------------

    def httpx_request_hook(self):
        """An httpx request event hook that re-checks every request, including
        every redirect target.

        httpx walks redirects as fresh ``request`` events, so attaching this
        hook to ``event_hooks={"request": [...]}`` is sufficient.
        """

        async def _hook(request: httpx.Request) -> None:
            url = str(request.url)
            await self.allow(url)

        return _hook

    def build_client(self, **kwargs) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient pre-wired with the scope hook and the
        defensive User-Agent.

        Unless the caller supplies its own ``transport`` (tests), the client
        dials ONLY the addresses the orchestrator vetted for each request's
        host, for every redirect hop too (``app.pinned.VettedTransport``);
        it never resolves DNS itself and ignores proxy environment variables.
        """
        from app import USER_AGENT  # local to avoid cycle at import

        if kwargs.get("proxy") or kwargs.get("mounts") or kwargs.get("proxies"):
            raise ValueError("a pinned scope client cannot use proxies or mounts")
        verify = kwargs.pop("verify", True)
        if "transport" not in kwargs:
            kwargs["transport"] = self.pinned_transport(verify=verify)
            kwargs["trust_env"] = False
        elif verify is not True:
            kwargs["verify"] = verify

        hooks = kwargs.pop("event_hooks", {})
        hooks.setdefault("request", []).append(self.httpx_request_hook())
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", USER_AGENT)
        return httpx.AsyncClient(
            event_hooks=hooks,
            headers=headers,
            follow_redirects=kwargs.pop("follow_redirects", True),
            timeout=kwargs.pop("timeout", httpx.Timeout(settings.http_timeout_sec)),
            **kwargs,
        )

    # -------- output row filter -------------------------------------------

    async def filter_in_scope(self, hosts: list[str]) -> list[str]:
        """Return the subset of hosts that are currently in scope."""
        kept: list[str] = []
        for h in hosts:
            if await self.is_allowed(h):
                kept.append(h)
            else:
                log.info("scope.drop_output", host=h)
        return kept

    # -------- tests / debug -----------------------------------------------

    def _seed(self, target: str, decision: ScopeDecision) -> None:
        """Test-only cache injection."""
        self._cache[self._ckey(normalize_target(target))] = decision


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return (urlsplit(t).hostname or "").lower()
    try:
        return (urlsplit("//" + t).hostname or "").lower()
    except ValueError:
        return t.lower()


def _ip_or_none(v: str):
    try:
        return ipaddress.ip_address(v.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


_NEVER = tuple(ipaddress.ip_network(n) for n in (
    "169.254.0.0/16", "fd00:ec2::/32", "fe80::/10", "0.0.0.0/8", "::/128",
    "224.0.0.0/4", "ff00::/8", "100.100.100.200/32",
))


def _never_dial(ip) -> bool:
    """Defense in depth behind the orchestrator's guardrails: cloud metadata,
    link-local, unspecified and multicast are never a legitimate destination."""
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in _NEVER)
