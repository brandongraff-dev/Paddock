"""Shared plumbing for the SIEM connectors (Splunk HEC, Sentinel, Elastic, syslog).

Every SIEM connector:

* is ``Capability.NOTIFY`` in category ``siem`` and sends **OCSF 1.3 JSON**
  (``app.integrations.ocsf``);
* implements ``deliver(event)`` and the additive batch entry point
  ``deliver_batch(events)`` (one HTTP request / one connection for the whole
  batch where the remote API supports it). The dispatcher may call either;
  ``deliver`` is just a batch of one;
* validates every customer-configured URL with
  ``netsafety.validate_outbound_url(url, allow_private=self.allow_private)``
  immediately before each request, and never follows redirects;
* classifies failures into ``DeliveryResult(ok=False, retryable=...)`` instead
  of raising, and never puts a secret (token, API key, client secret, bearer)
  in ``detail``.

``allow_private`` comes from the integration row's ``allow_private`` column.
The dispatcher passes it either as the ``allow_private`` attribute after
construction or as ``config["allow_private"]``; anything else defaults to
``False`` (deny private targets).
"""
from __future__ import annotations

import logging
from typing import Any, ClassVar, Mapping, Optional, Sequence

import httpx

from .. import netsafety, ocsf
from ..base import Capability, Connector, DeliveryResult, Event, HealthResult

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


def classify_status(code: int) -> bool:
    """Is an HTTP failure status worth retrying?"""
    return code in (408, 425, 429) or code >= 500


def scrub(text: str, secrets: Mapping[str, str]) -> str:
    """Remove any secret value that a remote error body might echo back."""
    out = text or ""
    for v in secrets.values():
        if v and len(v) >= 4:
            out = out.replace(v, "********")
    return out


def short_body(resp: httpx.Response, secrets: Mapping[str, str], limit: int = 300) -> str:
    try:
        text = resp.text
    except Exception:  # noqa: BLE001
        return ""
    return scrub(text[:limit], secrets).replace("\n", " ").strip()


def test_event() -> Event:
    return Event(
        type="integration.test",
        title="Paddock test event",
        summary="Sent from the Integrations page to verify connectivity.",
        severity="info",
    )


class SiemConnector(Connector):
    """Base class for OCSF-emitting SIEM connectors."""

    category: ClassVar[str] = "siem"
    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.NOTIFY})
    max_batch: ClassVar[int] = 100

    def __init__(self, config: Mapping[str, Any], secrets: Mapping[str, str], http: Any) -> None:
        super().__init__(config, secrets, http)
        self.allow_private: bool = self.config.get("allow_private") is True
        self._own_http: Optional[httpx.AsyncClient] = None

    # -- helpers ----------------------------------------------------------- #
    def client(self) -> Any:
        if self.http is not None:
            return self.http
        if self._own_http is None:
            self._own_http = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        return self._own_http

    async def aclose(self) -> None:
        if self._own_http is not None:
            await self._own_http.aclose()
            self._own_http = None

    async def safe_url(self, url: str) -> str:
        return await netsafety.validate_outbound_url(url, allow_private=self.allow_private)

    def records(self, events: Sequence[Event]) -> list[dict[str, Any]]:
        return [ocsf.event_to_ocsf(e) for e in events]

    def fail(self, detail: str, *, retryable: bool, status_code: Optional[int] = None) -> DeliveryResult:
        return DeliveryResult(ok=False, status_code=status_code, retryable=retryable,
                              detail=scrub(detail, self.secrets))

    def transport_failure(self, exc: Exception) -> DeliveryResult:
        if isinstance(exc, netsafety.UnsafeURL):
            return self.fail(f"refused unsafe destination: {exc}", retryable=False)
        if isinstance(exc, httpx.TimeoutException):
            return self.fail("timed out contacting the SIEM", retryable=True)
        if isinstance(exc, httpx.HTTPError):
            return self.fail(f"transport error: {type(exc).__name__}", retryable=True)
        return self.fail(f"unexpected error: {type(exc).__name__}", retryable=True)

    def http_failure(self, resp: httpx.Response, what: str = "SIEM") -> DeliveryResult:
        code = resp.status_code
        hint = {401: "authentication failed (check the credential)",
                403: "permission denied (check the credential's rights)",
                404: "endpoint not found (check the URL / index / stream)",
                413: "payload too large",
                429: "rate limited"}.get(code, "")
        body = short_body(resp, self.secrets)
        detail = f"{what} returned HTTP {code}"
        if hint:
            detail += f": {hint}"
        if body:
            detail += f" -- {body}"
        return self.fail(detail, retryable=classify_status(code), status_code=code)

    # -- contract ---------------------------------------------------------- #
    async def deliver(self, event: Event) -> DeliveryResult:
        return await self.deliver_batch([event])

    async def deliver_batch(self, events: Sequence[Event]) -> DeliveryResult:
        """Send up to ``max_batch`` events per request; all-or-nothing result."""
        if not events:
            return DeliveryResult(ok=True, detail="nothing to send")
        sent = 0
        last: Optional[DeliveryResult] = None
        for i in range(0, len(events), self.max_batch):
            chunk = list(events[i:i + self.max_batch])
            try:
                last = await self.send_records(self.records(chunk), chunk)
            except Exception as exc:  # noqa: BLE001 -- map, never raise
                log.warning("%s delivery failed: %s", self.kind, type(exc).__name__)
                last = self.transport_failure(exc)
            if not last.ok:
                if sent:
                    last.detail = f"{last.detail} (after {sent} event(s) were accepted)"
                return last
            sent += len(chunk)
        assert last is not None
        last.detail = last.detail or f"sent {sent} event(s)"
        return last

    async def test(self) -> HealthResult:
        res = await self.deliver_batch([test_event()])
        return HealthResult(ok=res.ok, detail=res.detail or ("ok" if res.ok else "failed"))

    async def send_records(self, records: list[dict[str, Any]], events: list[Event]) -> DeliveryResult:
        raise NotImplementedError
