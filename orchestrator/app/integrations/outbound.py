"""The ONLY way connectors talk to the outside world.

``GuardedAsyncClient`` is an ``httpx.AsyncClient`` that runs
``netsafety.validate_outbound_url`` on every request it sends (so a connector
cannot forget), never follows redirects (a 30x to ``http://169.254.169.254``
would otherwise bypass the check), and carries the integration's
``allow_private`` opt-in so non-HTTP connectors (SMTP) can apply the same rule
via ``check_host``.

``post`` maps transport outcomes onto ``DeliveryResult`` without ever putting
a URL, header or exception message into ``detail`` (those can carry secrets:
a Slack webhook URL *is* the credential).
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

import httpx

from . import netsafety
from .base import DeliveryResult
from .pinned import PinnedTransport
from .settings import isettings

USER_AGENT = "Paddock-Integrations/1.0 (+https://github.com/brandongraff-dev/paddock)"


class GuardedAsyncClient(httpx.AsyncClient):
    def __init__(self, *, allow_private: bool = False, **kwargs: Any) -> None:
        kwargs["follow_redirects"] = False
        kwargs.setdefault("timeout", isettings.integrations_http_timeout_sec)
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("User-Agent", USER_AGENT)
        # No injected transport (tests) => the DNS-pinned one: connect only to
        # addresses it validated itself, never to a second lookup.
        kwargs.setdefault("transport", PinnedTransport(allow_private=allow_private))
        super().__init__(headers=headers, **kwargs)
        self.allow_private = allow_private

    async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:  # type: ignore[override]
        await netsafety.validate_outbound_url(str(request.url), allow_private=self.allow_private)
        kwargs["follow_redirects"] = False
        return await super().send(request, **kwargs)

    async def check_host(self, host: str, port: int) -> list[str]:
        """Apply the outbound-URL policy to a non-HTTP endpoint (e.g. SMTP).

        Returns the validated addresses, so the caller can connect to THOSE
        (pinned) instead of resolving the name a second time."""
        h = host.strip()
        if ":" in h and not h.startswith("["):
            h = f"[{h}]"                     # IPv6 literal
        await netsafety.validate_outbound_url(f"https://{h}:{int(port)}/", allow_private=self.allow_private)
        return await netsafety.resolve_validated(host.strip(), int(port), allow_private=self.allow_private)


def make_client(*, allow_private: bool = False, transport: Optional[httpx.AsyncBaseTransport] = None) -> GuardedAsyncClient:
    kw: dict[str, Any] = {} if transport is None else {"transport": transport}
    return GuardedAsyncClient(allow_private=allow_private, **kw)


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Remove any secret value that a remote echoed back into a response body."""
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "********")
    return text


def _snippet(resp: httpx.Response, secrets: Iterable[str]) -> str:
    try:
        body = resp.text
    except Exception:  # noqa: BLE001
        return ""
    body = " ".join(body.split())[:200]
    return scrub(body, secrets)


def result_from_response(resp: httpx.Response, secrets: Iterable[str] = ()) -> DeliveryResult:
    code = resp.status_code
    snip = _snippet(resp, secrets)
    if 200 <= code < 300:
        return DeliveryResult(ok=True, status_code=code, detail=f"HTTP {code}" + (f": {snip}" if snip else ""))
    if 300 <= code < 400:
        return DeliveryResult(ok=False, status_code=code, retryable=False,
                              detail=f"HTTP {code}: redirects are not followed; configure the final URL")
    retryable = code in (408, 409, 425, 429) or code >= 500
    return DeliveryResult(ok=False, status_code=code, retryable=retryable,
                          detail=f"HTTP {code}" + (f": {snip}" if snip else ""))


def result_from_exception(exc: BaseException) -> DeliveryResult:
    if isinstance(exc, netsafety.UnsafeURL):
        # UnsafeURL messages name the host and the rule, never the path/query.
        return DeliveryResult(ok=False, retryable=False, detail=f"blocked by outbound URL policy: {exc}")
    if isinstance(exc, httpx.TimeoutException):
        return DeliveryResult(ok=False, retryable=True, detail="timed out")
    if isinstance(exc, httpx.HTTPError):
        return DeliveryResult(ok=False, retryable=True, detail=f"network error ({type(exc).__name__})")
    return DeliveryResult(ok=False, retryable=True, detail=f"unexpected error ({type(exc).__name__})")


async def post(
    http: httpx.AsyncClient,
    url: str,
    *,
    json_body: Any = None,
    content: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    secrets: Iterable[str] = (),
) -> tuple[DeliveryResult, Optional[httpx.Response]]:
    """POST and translate the outcome. Never raises for expected failures."""
    try:
        if content is not None:
            resp = await http.post(url, content=content, headers=dict(headers or {}))
        else:
            resp = await http.post(url, json=json_body, headers=dict(headers or {}))
    except Exception as exc:  # noqa: BLE001 -- mapped, never echoed
        return result_from_exception(exc), None
    return result_from_response(resp, secrets), resp
