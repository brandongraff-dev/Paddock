"""Google SecOps (Chronicle) via the Ingestion API -- UDM events or OCSF logs.

Auth is a service-account key (``service_account_json`` secret, role
*Chronicle Ingestion*/``malachite-ingestion`` scope), exchanged for an OAuth2
token with ``_gcp_auth`` (JWT bearer, ``cryptography`` only). The token is
cached and refreshed once on a 401.

Two ``format`` modes, both fed by the shared OCSF 1.3 record from
``app.integrations.ocsf`` (``SiemConnector.records``):

* ``udm`` (default): the OCSF record is mapped to a Chronicle **UDM** event
  (``GENERIC_EVENT`` + ``security_result``; the asset becomes ``target``;
  the whole OCSF record rides in ``additional``) and sent to
  ``POST {host}/v2/udmevents:batchCreate`` with ``{customer_id, events}``.
  No parser is needed.
* ``ocsf``: the OCSF JSON is sent as raw log lines to
  ``POST {host}/v2/unstructuredlogs:batchCreate`` with your ``log_type``
  (a custom log type with an OCSF-JSON parser).

``{host}`` is ``malachiteingestion-pa.googleapis.com`` for ``region: us`` and
``{region}-malachiteingestion-pa.googleapis.com`` otherwise (``europe``,
``europe-west2``, ``asia-southeast1``...); ``ingestion_url`` overrides it.
Bodies are split at 1 MB. Success is HTTP 200; 429 and 5xx are retryable, 400
(bad UDM / unknown log type) and 401/403 are not.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, ClassVar, Optional

from ..base import DeliveryResult, Event, register
from ._common import SourceError
from ._gcp_auth import access_token, parse_key
from ._siem import SiemConnector

SCOPE_URL = "https://www.googleapis.com/auth/malachite-ingestion"
MAX_BODY_BYTES = 1_000_000

_UDM_SEVERITY = {0: "INFORMATIONAL", 1: "INFORMATIONAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH",
                 5: "CRITICAL", 6: "CRITICAL"}
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_IP_TYPES = {"ipv4", "ipv6", "ipv4_cidr", "ipv6_cidr"}


def ocsf_to_udm(record: dict[str, Any], event: Event) -> dict[str, Any]:
    """OCSF Detection/Vulnerability Finding -> a Chronicle UDM ``GENERIC_EVENT``."""
    ms = record.get("time")
    ts = (datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc) if isinstance(ms, (int, float))
          else event.occurred_at)
    fi = record.get("finding_info") or {}
    md = record.get("metadata") or {}
    sev = _UDM_SEVERITY.get(int(record.get("severity_id") or 0), "UNKNOWN_SEVERITY")
    sr: dict[str, Any] = {
        "summary": str(fi.get("title") or record.get("message") or event.title)[:512],
        "description": str(fi.get("desc") or event.summary or "")[:4000],
        "severity": sev,
        "category_details": [str(t) for t in (fi.get("types") or [])][:10],
        "rule_name": str((fi.get("analytic") or {}).get("name") or record.get("class_name") or ""),
        "rule_id": str(fi.get("uid") or ""),
        "url_back_to_product": fi.get("src_url") or event.url or "",
    }
    udm: dict[str, Any] = {
        "metadata": {
            "event_timestamp": ts.isoformat().replace("+00:00", "Z"),
            "event_type": "GENERIC_EVENT",
            "vendor_name": "Paddock",
            "product_name": "Paddock",
            "product_event_type": str(record.get("type_name") or event.type),
            "product_log_id": event.id,
            "description": str(record.get("message") or event.title)[:1000],
        },
        "security_result": [{k: v for k, v in sr.items() if v not in ("", [], None)}],
        "additional": {"ocsf": record, "paddock_event_id": event.id,
                       "paddock_event_type": event.type, "ocsf_version": md.get("version")},
    }
    res = (record.get("resources") or [{}])[0] or {}
    name, rtype = res.get("name"), str(res.get("type") or "")
    if name:
        target: dict[str, Any] = {}
        if rtype in _IP_TYPES:
            target["ip"] = [str(name).split("/")[0]]
        elif "://" in str(name):
            target["url"] = str(name)
        else:
            target["hostname"] = str(name)
        target["asset"] = {"product_object_id": str(res.get("uid") or name)}
        udm["target"] = target
    return udm


@register
class GoogleSecOpsConnector(SiemConnector):
    kind = "google_secops"
    display_name = "Google SecOps (Chronicle Ingestion API)"
    docs_url = "https://cloud.google.com/chronicle/docs/reference/ingestion-api"
    secret_fields = ("service_account_json",)
    max_batch: ClassVar[int] = 200
    config_schema = {
        "type": "object",
        "required": ["customer_id"],
        "properties": {
            "customer_id": {"type": "string", "description": "SecOps customer (instance) GUID"},
            "region": {"type": "string", "default": "us",
                       "description": "us, europe, europe-west2, asia-southeast1, ..."},
            "format": {"type": "string", "enum": ["udm", "ocsf"], "default": "udm"},
            "log_type": {"type": "string", "default": "PADDOCK_OCSF",
                         "description": "Log type for format=ocsf (needs an OCSF JSON parser)"},
            "ingestion_url": {"type": "string", "format": "uri",
                              "description": "Override the regional ingestion host"},
            "token_uri": {"type": "string", "description": "Override the OAuth token endpoint"},
        },
    }

    # -- config ------------------------------------------------------------- #
    def host(self) -> str:
        override = str(self.config.get("ingestion_url") or "").rstrip("/")
        if override:
            return override
        region = str(self.config.get("region") or "us").strip().lower()
        if not re.match(r"^[a-z][a-z0-9-]{1,30}$", region):
            raise SourceError("invalid region", retryable=False)
        return ("https://malachiteingestion-pa.googleapis.com" if region == "us"
                else f"https://{region}-malachiteingestion-pa.googleapis.com")

    def mode(self) -> str:
        return "ocsf" if str(self.config.get("format") or "udm").lower() == "ocsf" else "udm"

    # -- body building ------------------------------------------------------- #
    def _items(self, records: list[dict[str, Any]], events: list[Event]) -> list[Any]:
        if self.mode() == "udm":
            return [ocsf_to_udm(r, e) for r, e in zip(records, events)]
        out = []
        for r, e in zip(records, events):
            ms = r.get("time")
            us = int(ms * 1000) if isinstance(ms, (int, float)) else int(e.occurred_at.timestamp() * 1e6)
            out.append({"log_text": json.dumps(r, separators=(",", ":"), default=str),
                        "ts_epoch_microseconds": us})
        return out

    def _body(self, items: list[Any]) -> bytes:
        cid = str(self.config.get("customer_id"))
        if self.mode() == "udm":
            doc = {"customer_id": cid, "events": items}
        else:
            doc = {"customer_id": cid, "log_type": str(self.config.get("log_type") or "PADDOCK_OCSF"),
                   "entries": items}
        return json.dumps(doc, separators=(",", ":"), default=str).encode("utf-8")

    def split(self, items: list[Any]) -> list[tuple[bytes, int]]:
        """(body, item count) pairs each <= MAX_BODY_BYTES; one oversize item goes alone."""
        out: list[tuple[bytes, int]] = []
        cur: list[Any] = []
        size = 0
        for it in items:
            enc = len(json.dumps(it, separators=(",", ":"), default=str).encode("utf-8")) + 1
            if cur and size + enc > MAX_BODY_BYTES - 1024:
                out.append((self._body(cur), len(cur)))
                cur, size = [], 0
            cur.append(it)
            size += enc
        if cur:
            out.append((self._body(cur), len(cur)))
        return out

    def endpoint(self) -> str:
        path = "/v2/udmevents:batchCreate" if self.mode() == "udm" else "/v2/unstructuredlogs:batchCreate"
        return self.host() + path

    # -- delivery ------------------------------------------------------------ #
    async def _token(self, key: dict[str, Any], *, force: bool = False) -> str:
        return await access_token(self.client(), key, self.config, SCOPE_URL,
                                  allow_private=self.allow_private, force=force)

    async def send_records(self, records: list[dict[str, Any]], events: list[Event]) -> DeliveryResult:
        cid = str(self.config.get("customer_id") or "")
        if not _GUID.match(cid):
            return self.fail("config 'customer_id' must be the SecOps customer GUID", retryable=False)
        try:
            key = parse_key(self.secrets.get("service_account_json"))
            url = await self.safe_url(self.endpoint())
            token = await self._token(key)
        except SourceError as exc:
            return self.fail(str(exc), retryable=exc.retryable, status_code=exc.status_code)
        accepted = 0
        for body, count in self.split(self._items(records, events)):
            refreshed = False
            while True:
                resp = await self.client().post(url, content=body, headers={
                    "Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    follow_redirects=False)
                if resp.status_code == 401 and not refreshed:
                    refreshed = True      # cached token revoked / key rotated: refresh once
                    try:
                        token = await self._token(key, force=True)
                    except SourceError as exc:
                        return self.fail(str(exc), retryable=exc.retryable, status_code=exc.status_code)
                    continue
                break
            if resp.status_code == 200:
                accepted += count
                continue
            res = self.http_failure(resp, "SecOps Ingestion API")
            if accepted:
                res.detail += f" (after {accepted} event(s) were accepted)"
            return res
        return DeliveryResult(ok=True, status_code=200, detail=f"SecOps accepted {accepted} event(s)")

    def transport_failure(self, exc: Exception) -> DeliveryResult:
        if isinstance(exc, SourceError):
            return self.fail(str(exc), retryable=exc.retryable, status_code=exc.status_code)
        return super().transport_failure(exc)
