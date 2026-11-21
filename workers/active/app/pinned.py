"""Vetted-address HTTP transport (closes the DNS-rebinding window).

The orchestrator's ``/v1/scope/check`` resolves a hostname once and vets every
answer (HARD_DENY nets, internal ranges). If this worker then connected by
NAME, its resolver would be asked again and a hostile DNS server could hand
back ``169.254.169.254`` or an internal address (TTL 0). ``VettedTransport``
removes the second lookup:

1. ``scope.vetted_addrs(url)`` re-checks scope and returns the addresses the
   orchestrator vetted (an empty list refuses the request);
2. the request is dialled to one of those literal IPs, trying the next on a
   connect failure;
3. the ``Host`` header and, for HTTPS, the TLS SNI and certificate
   verification keep the original hostname (``sni_hostname`` extension), so a
   certificate is checked against the name, not the IP.

httpx walks redirects as fresh requests through the transport, so every hop is
re-checked and re-pinned. Connections are never reused across requests (a pool
is keyed by IP; reusing a socket for another hostname would skip the
certificate check). Environment proxies are ignored: through a proxy the proxy
resolves the name.
"""
from __future__ import annotations

import ipaddress
import ssl
from typing import Any, Optional, Union

import httpx

from app.scope_guard import ScopeDenied

MAX_ADDRS = 4  # connect attempts per request

VerifyType = Union[bool, ssl.SSLContext]


class VettedTransport(httpx.AsyncBaseTransport):
    def __init__(self, scope: Any, *, verify: VerifyType = True, max_addrs: int = MAX_ADDRS) -> None:
        self.scope = scope
        self.max_addrs = max_addrs
        self._inner = httpx.AsyncHTTPTransport(
            verify=verify, trust_env=False,
            limits=httpx.Limits(max_keepalive_connections=0, max_connections=100),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.scheme not in ("http", "https"):
            raise ScopeDenied(str(url), "only http(s) URLs are allowed")
        host = url.host
        if not host:
            raise ScopeDenied(str(url), "malformed or ambiguous URL")
        addrs = await self.scope.vetted_addrs(str(url))
        literal = _is_ip(host)
        last: Optional[Exception] = None
        for ip in addrs[: self.max_addrs]:
            try:
                return await self._inner.handle_async_request(_pin(request, ip, None if literal else host))
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last = exc
        assert last is not None
        raise last

    async def aclose(self) -> None:
        await self._inner.aclose()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _pin(request: httpx.Request, ip: str, sni: Optional[str]) -> httpx.Request:
    ext = dict(request.extensions)
    if sni:
        ext["sni_hostname"] = sni
    return httpx.Request(
        request.method,
        request.url.copy_with(host=ip),
        headers=request.headers,  # carries the original Host header
        stream=request.stream,
        extensions=ext,
    )
