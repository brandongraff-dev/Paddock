"""DNS-pinned HTTP transport: closes the rebinding gap in ``netsafety``.

``netsafety.validate_outbound_url`` resolves a name and checks the answers, but
an HTTP client then resolves it a second time to connect. An attacker's DNS
server can answer a public address for the check and ``127.0.0.1`` /
``169.254.169.254`` for the connect (TTL 0). ``PinnedTransport`` removes the
second lookup:

1. resolve the request host ONCE (``netsafety.resolve_validated``: every A/AAAA
   answer must pass the private / HARD_DENY rules, or the whole request is
   refused);
2. connect to one of those validated literal IPs, trying the next on a
   connect failure;
3. keep the original hostname for the ``Host`` header AND for TLS: the
   handshake sends it as SNI and the certificate is verified against it
   (``sni_hostname`` request extension), not against the IP.

Every request goes through this, so a redirect that the caller follows is
re-resolved and re-validated per hop. Connections are never reused across
requests (``max_keepalive_connections=0``): a pooled socket is keyed by IP, and
reusing it for a different hostname would skip the certificate check.

Proxies: environment proxies (``HTTP(S)_PROXY``) are deliberately ignored.
Through a proxy the proxy resolves the name, which re-opens the rebinding
window. An operator who must egress via a proxy sets
``PADDOCK_OUTBOUND_PROXY``; the transport then still refuses any name whose
answers fail the policy, but the final connect is the proxy's, so the proxy
itself must enforce egress policy (see docs/INTEGRATIONS.md "Outbound safety").
"""
from __future__ import annotations

import ipaddress
import os
import ssl
from typing import Any, Optional, Union

import httpx

from . import netsafety

MAX_ADDRS = 4  # connect attempts per request

VerifyType = Union[bool, ssl.SSLContext]


def outbound_proxy() -> Optional[str]:
    v = (os.environ.get("PADDOCK_OUTBOUND_PROXY") or "").strip()
    return v or None


class PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, *, allow_private: bool = False, verify: VerifyType = True,
                 proxy: Optional[str] = None, max_addrs: int = MAX_ADDRS) -> None:
        self.allow_private = allow_private
        self.max_addrs = max_addrs
        self.proxy = proxy if proxy is not None else outbound_proxy()
        self._inner = httpx.AsyncHTTPTransport(
            verify=verify, trust_env=False, proxy=self.proxy,
            limits=httpx.Limits(max_keepalive_connections=0, max_connections=100),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.scheme not in ("http", "https"):
            raise netsafety.UnsafeURL("only http(s) URLs are allowed")
        host = url.host
        port = url.port or (443 if url.scheme == "https" else 80)
        if not host:
            raise netsafety.UnsafeURL("malformed or ambiguous URL")
        addrs = await netsafety.resolve_validated(host, port, allow_private=self.allow_private)
        if self.proxy:
            return await self._inner.handle_async_request(request)
        literal = _is_ip(host)
        last: Optional[Exception] = None
        for ip in addrs[: self.max_addrs]:
            req = _pin(request, ip, None if literal else host)
            try:
                return await self._inner.handle_async_request(req)
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
    ip = ip.split("%", 1)[0]
    ext = dict(request.extensions)
    if sni:
        ext["sni_hostname"] = sni
    return httpx.Request(
        request.method,
        request.url.copy_with(host=ip),
        headers=request.headers,  # includes the original Host header
        stream=request.stream,
        extensions=ext,
    )


def pinned_client(*, allow_private: bool = False, verify: VerifyType = True, **kwargs: Any) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` that never follows redirects and connects only
    to addresses it validated itself."""
    kwargs["follow_redirects"] = False
    kwargs.setdefault("transport", PinnedTransport(allow_private=allow_private, verify=verify))
    return httpx.AsyncClient(**kwargs)
