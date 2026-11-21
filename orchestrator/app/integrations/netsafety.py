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
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from .. import scope


class UnsafeURL(ValueError):
    pass


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
        ip = ipaddress.ip_address(host)
        addrs = [ip]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, parts.port or 443))
        except OSError as exc:
            raise UnsafeURL(f"host does not resolve: {host}") from exc
        addrs = [ipaddress.ip_address(i[4][0]) for i in infos]
    for a in addrs:
        a = scope._unmap(a)
        if scope.hard_denied(a):
            raise UnsafeURL(f"{host} resolves to a protected address")
        if scope.is_internal(a) and not allow_private:
            raise UnsafeURL(f"{host} resolves to a private address; enable allow_private on this integration")
    return url
