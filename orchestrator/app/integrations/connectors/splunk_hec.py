"""Splunk HTTP Event Collector (HEC) connector -- OCSF JSON events.

* ``POST {url}/services/collector/event`` with ``Authorization: Splunk <token>``.
* Batched: HEC accepts many event envelopes concatenated in one body
  (``{"event":...}{"event":...}``), so a batch is one request.
* Each envelope carries ``time`` (epoch seconds), ``sourcetype``
  (default ``paddock:ocsf``), optional ``index`` / ``source`` / ``host``, and
  ``fields.paddock_event_id`` (the idempotency key, indexed) so duplicates
  from a dispatcher retry can be de-duplicated in SPL.
* HEC replies ``{"text": "...", "code": N}``. ``code`` 9 (server busy) and
  HTTP 429/5xx are retryable; 4 (invalid token), 6/7 (bad data / index) are not.
* ``tls_verify: false`` is honoured ONLY for ``allow_private`` integrations
  (a lab Splunk with a self-signed cert on the LAN). For any public target it
  is refused outright.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, ClassVar, Optional

import httpx

from ..base import DeliveryResult, Event, register
from ..pinned import pinned_client
from ._siem import DEFAULT_TIMEOUT, SiemConnector, classify_status, short_body

# HEC response codes that mean "try again later".
_HEC_RETRYABLE_CODES = {8, 9}  # 8 internal server error, 9 server busy


@register
class SplunkHecConnector(SiemConnector):
    kind = "splunk_hec"
    display_name = "Splunk (HTTP Event Collector)"
    docs_url = "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector"
    secret_fields = ("token",)
    max_batch: ClassVar[int] = 200
    config_schema = {
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string", "format": "uri",
                    "description": "HEC base URL, e.g. https://splunk.example.com:8088"},
            "index": {"type": "string", "description": "Target index (token default if empty)"},
            "sourcetype": {"type": "string", "default": "paddock:ocsf"},
            "source": {"type": "string", "default": "paddock"},
            "host": {"type": "string", "description": "Value for the event `host` field"},
            "channel": {"type": "string",
                        "description": "HEC channel GUID (needed if indexer acknowledgement is on)"},
            "tls_verify": {"type": "boolean", "default": True,
                           "description": "Only allow_private integrations may turn this off"},
        },
    }

    # Patched by tests; production uses httpx.AsyncClient.
    _insecure_client_factory = staticmethod(
        lambda: pinned_client(allow_private=True, verify=False, timeout=DEFAULT_TIMEOUT))

    def __init__(self, config, secrets, http) -> None:  # type: ignore[no-untyped-def]
        super().__init__(config, secrets, http)
        self._insecure: Optional[httpx.AsyncClient] = None

    def endpoint(self) -> str:
        base = str(self.config.get("url") or "").rstrip("/")
        if base.endswith("/services/collector/event"):
            return base
        if base.endswith("/services/collector"):
            return base + "/event"
        return base + "/services/collector/event"

    def _http(self) -> Any:
        if self.config.get("tls_verify", True) is False:
            if not self.allow_private:
                raise PermissionError("tls_verify=false is only allowed for allow_private integrations")
            if self._insecure is None:
                self._insecure = self._insecure_client_factory()
            return self._insecure
        return self.client()

    async def aclose(self) -> None:
        await super().aclose()
        if self._insecure is not None:
            await self._insecure.aclose()
            self._insecure = None

    def envelope(self, record: dict[str, Any], event: Event) -> dict[str, Any]:
        env: dict[str, Any] = {
            "time": round((record.get("time") or 0) / 1000.0, 3),
            "sourcetype": self.config.get("sourcetype") or "paddock:ocsf",
            "source": self.config.get("source") or "paddock",
            "event": record,
            "fields": {
                "paddock_event_id": event.id,
                "paddock_event_type": event.type,
                "ocsf_class_uid": str(record.get("class_uid")),
            },
        }
        if self.config.get("index"):
            env["index"] = self.config["index"]
        if self.config.get("host"):
            env["host"] = self.config["host"]
        return env

    async def send_records(self, records: list[dict[str, Any]], events: list[Event]) -> DeliveryResult:
        token = self.secrets.get("token")
        if not token:
            return self.fail("missing secret 'token'", retryable=False)
        if not self.config.get("url"):
            return self.fail("missing config 'url'", retryable=False)
        try:
            http = self._http()
        except PermissionError as exc:
            return self.fail(str(exc), retryable=False)
        url = await self.safe_url(self.endpoint())
        body = "".join(json.dumps(self.envelope(r, e), separators=(",", ":"), default=str)
                       for r, e in zip(records, events))
        headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
            "X-Splunk-Request-Channel": str(self.config.get("channel") or uuid.uuid5(
                uuid.NAMESPACE_URL, "paddock:" + url)),
        }
        resp = await http.post(url, content=body.encode("utf-8"), headers=headers,
                               follow_redirects=False)
        code: Optional[int] = None
        text = ""
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                code = payload.get("code") if isinstance(payload.get("code"), int) else None
                text = str(payload.get("text") or "")
        except ValueError:
            pass
        if 200 <= resp.status_code < 300 and (code in (None, 0)):
            ack = ""
            try:
                ack_id = resp.json().get("ackId")
                ack = f" (ackId {ack_id})" if ack_id is not None else ""
            except (ValueError, AttributeError):
                pass
            return DeliveryResult(ok=True, status_code=resp.status_code,
                                  detail=f"Splunk accepted {len(records)} event(s){ack}")
        retryable = classify_status(resp.status_code) or (code in _HEC_RETRYABLE_CODES)
        if code is not None:
            detail = f"Splunk HEC returned HTTP {resp.status_code} code {code}: {text}"
        else:
            detail = f"Splunk HEC returned HTTP {resp.status_code}: {short_body(resp, self.secrets)}"
        return self.fail(detail, retryable=retryable, status_code=resp.status_code)
