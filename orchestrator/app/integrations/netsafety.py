"""Outbound URL validation for customer-configured endpoints.

A webhook/SIEM/ticketing URL is attacker-influenced input: without checks it
turns Paddock into an SSRF proxy into its own network or the cloud metadata
service. Reuses the scope guardrails (``app.scope``) so there is ONE
definition of "protected address" in the codebase.

* https only (http allowed only for explicitly private, opted-in targets)
* host must resolve; EVERY resolved address must pass
* cloud metadata / reserved ranges: always refused
* private / loopback / link-local: refused unless ``allow_private=True``
  (self-hosted Jira on the LAN is legitimate -- but it must be a deliberate,
  audited choice on that integration)

``validate_outbound_url`` alone is a check-then-use: the HTTP client resolves
the name AGAIN when it connects, so a DNS-rebinding server (public answer
first, 127.0.0.1 second, TTL 0) passes the check and is then connected to.
``resolve_validated`` returns the validated addresses so the caller can
connect to THOSE; ``app.integrations.pinned.PinnedTransport`` does exactly that
for every httpx client the orchestrator builds.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import urlsplit

from .. import scope


class UnsafeURL(ValueError):
    pass


# --------------------------------------------------------------------------- #
# Resolution (one hook, so tests can script rebinding)
# --------------------------------------------------------------------------- #

Resolver = Callable[[str, int], Awaitable[list[str]]]
_resolver: Optional[Resolver] = None


def set_resolver(fn: Optional[Resolver]) -> None:
    """Replace the resolver (tests). ``None`` restores ``socket.getaddrinfo``."""
    global _resolver
    _resolver = fn


async def _system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, port))
    return [str(i[4][0]) for i in infos]


def _parse_ip(text: str) -> ipaddress._BaseAddress:
    return ipaddress.ip_address(text.split("%", 1)[0])  # drop an IPv6 zone id


def check_addresses(host: str, addrs: Iterable[ipaddress._BaseAddress], *, allow_private: bool) -> None:
    """Raise ``UnsafeURL`` unless EVERY address is acceptable (mixed answers
    are refused: a name that also resolves internally is not trusted)."""
    n = 0
    for a in addrs:
        n += 1
        a = scope._unmap(a)
        if scope.hard_denied(a):
            raise UnsafeURL(f"{host} resolves to a protected address")
        if scope.is_internal(a) and not allow_private:
            raise UnsafeURL(f"{host} resolves to a private address; enable allow_private on this integration")
    if not n:
        raise UnsafeURL(f"host does not resolve: {host}")


async def resolve_validated(host: str, port: int, *, allow_private: bool = False) -> list[str]:
    """Resolve ``host`` ONCE, validate every answer, return them (deduplicated,
    in resolver order) as literal IP strings to connect to."""
    host = host.strip("[]")
    try:
        _parse_ip(host)
        raw = [host]
    except ValueError:
        try:
            raw = await (_resolver or _system_resolver)(host, port)
        except OSError as exc:
            raise UnsafeURL(f"host does not resolve: {host}") from exc
    try:
        parsed = [_parse_ip(a) for a in raw]
    except ValueError as exc:
        raise UnsafeURL(f"{host} resolved to an unparseable address") from exc
    check_addresses(host, parsed, allow_private=allow_private)
    return list(dict.fromkeys(raw))


async def validate_outbound_url(url: str, *, allow_private: bool = False) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise UnsafeURL("only https:// URLs are allowed")
    if parts.scheme == "http" and not allow_private:
        raise UnsafeURL("plain http is only allowed for private targets with allow_private")
    if parts.username or parts.password:
        raise UnsafeURL("credentials in the URL are not allowed; use the secret fields")
    host = scope.normalize(url)
    if not host:
        raise UnsafeURL("malformed or ambiguous URL")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeURL("malformed port") from exc
    await resolve_validated(host, port, allow_private=allow_private)
    return url
