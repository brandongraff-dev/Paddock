"""Microsoft Sentinel via the Azure Monitor Logs Ingestion API -- OCSF JSON.

Flow (client-credentials, no user interaction):

1. ``POST https://{authority_host}/{tenant_id}/oauth2/v2.0/token`` with the
   Entra app's ``client_id`` / ``client_secret`` and
   ``scope=https://monitor.azure.com//.default``. The access token is cached
   per (authority, tenant, client, secret-fingerprint) until 5 minutes before
   it expires, and dropped on a 401 so a rotated secret recovers by itself.
2. ``POST {dce_endpoint}/dataCollectionRules/{dcr_immutable_id}/streams/
   {stream_name}?api-version=2023-01-01`` with a JSON **array** of records.
   Each record is the OCSF object plus ``TimeGenerated`` (required by every
   custom table) and ``EventId``. Batches are split so no request body
   exceeds 1 MB (the API limit). Success is HTTP 204.

The app registration needs the *Monitoring Metrics Publisher* role on the
DCR. See docs/INTEGRATIONS-SIEM.md for the table / DCR stream declaration.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, ClassVar, Optional
from urllib.parse import quote

from ..base import DeliveryResult, Event, register
from ._siem import SiemConnector, short_body

API_VERSION = "2023-01-01"
MONITOR_SCOPE = "https://monitor.azure.com//.default"
MAX_BODY_BYTES = 1_000_000  # Logs Ingestion API: 1 MB per call
_REFRESH_MARGIN_S = 300

# (authority, tenant, client_id, sha256(secret)) -> (access_token, expires_at_monotonic)
_TOKEN_CACHE: dict[tuple[str, str, str, str], tuple[str, float]] = {}


def clear_token_cache() -> None:
    _TOKEN_CACHE.clear()


class _TokenError(Exception):
    def __init__(self, detail: str, retryable: bool, status_code: Optional[int] = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.retryable = retryable
        self.status_code = status_code


@register
class SentinelConnector(SiemConnector):
    kind = "sentinel"
    display_name = "Microsoft Sentinel (Logs Ingestion API)"
    docs_url = "https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview"
    secret_fields = ("client_secret",)
    max_batch: ClassVar[int] = 500
    config_schema = {
        "type": "object",
        "required": ["dce_endpoint", "dcr_immutable_id", "stream_name", "tenant_id", "client_id"],
        "properties": {
            "dce_endpoint": {"type": "string", "format": "uri",
                             "description": "Data collection endpoint, e.g. "
                                            "https://my-dce-abcd.eastus-1.ingest.monitor.azure.com"},
            "dcr_immutable_id": {"type": "string", "pattern": "^dcr-[0-9a-f]{32}$",
                                 "description": "DCR immutable id (dcr-...)"},
            "stream_name": {"type": "string", "default": "Custom-PaddockOCSF_CL"},
            "tenant_id": {"type": "string", "description": "Entra (Azure AD) tenant id"},
            "client_id": {"type": "string", "description": "Entra app (client) id"},
            "authority_host": {"type": "string", "default": "login.microsoftonline.com",
                               "description": "Override for sovereign clouds"},
        },
    }

    # -- token -------------------------------------------------------------- #
    def _client_id(self) -> str:
        return str(self.config.get("client_id") or self.secrets.get("client_id") or "")

    def _cache_key(self) -> tuple[str, str, str, str]:
        secret = self.secrets.get("client_secret") or ""
        return (
            str(self.config.get("authority_host") or "login.microsoftonline.com").lower(),
            str(self.config.get("tenant_id") or ""),
            self._client_id(),
            hashlib.sha256(secret.encode()).hexdigest(),
        )

    async def _token(self, *, force: bool = False) -> str:
        key = self._cache_key()
        now = time.monotonic()
        cached = _TOKEN_CACHE.get(key)
        if cached and not force and cached[1] - _REFRESH_MARGIN_S > now:
            return cached[0]
        authority, tenant, client_id, _ = key
        secret = self.secrets.get("client_secret")
        if not (tenant and client_id and secret):
            raise _TokenError("tenant_id, client_id and secret 'client_secret' are required", False)
        # The token endpoint is customer-influenced (authority_host), so it is
        # validated like any other outbound URL. It is always public.
        url = await self.safe_url(f"https://{authority}/{quote(tenant, safe='')}/oauth2/v2.0/token")
        resp = await self.client().post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
            "scope": MONITOR_SCOPE,
        }, follow_redirects=False)
        if resp.status_code != 200:
            err = ""
            try:
                err = str(resp.json().get("error") or "")
            except (ValueError, AttributeError):
                pass
            retry = resp.status_code == 429 or resp.status_code >= 500
            raise _TokenError(
                f"Entra token request failed: HTTP {resp.status_code}" + (f" ({err})" if err else ""),
                retry, resp.status_code)
        try:
            body = resp.json()
            token = str(body["access_token"])
            ttl = float(body.get("expires_in") or 3600)
        except (ValueError, KeyError, TypeError) as exc:
            raise _TokenError("Entra token response was malformed", True) from exc
        _TOKEN_CACHE[key] = (token, now + ttl)
        return token

    # -- ingest ------------------------------------------------------------- #
    def endpoint(self) -> str:
        dce = str(self.config.get("dce_endpoint") or "").rstrip("/")
        dcr = quote(str(self.config.get("dcr_immutable_id") or ""), safe="")
        stream = quote(str(self.config.get("stream_name") or "Custom-PaddockOCSF_CL"), safe="")
        return f"{dce}/dataCollectionRules/{dcr}/streams/{stream}?api-version={API_VERSION}"

    @staticmethod
    def to_row(record: dict[str, Any], event: Event) -> dict[str, Any]:
        ts = record.get("time")
        tg = (datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc) if isinstance(ts, (int, float))
              else event.occurred_at)
        return {"TimeGenerated": tg.isoformat().replace("+00:00", "Z"), "EventId": event.id, **record}

    @staticmethod
    def split(rows: list[dict[str, Any]]) -> list[tuple[bytes, int]]:
        """(JSON-array body, row count) pairs, each body <= MAX_BODY_BYTES (a
        single oversize row still goes alone; the API rejects it with 413,
        which is non-retryable)."""
        bodies: list[tuple[bytes, int]] = []
        cur: list[bytes] = []
        size = 2
        for row in rows:
            enc = json.dumps(row, separators=(",", ":"), default=str).encode("utf-8")
            if cur and size + len(enc) + 1 > MAX_BODY_BYTES:
                bodies.append((b"[" + b",".join(cur) + b"]", len(cur)))
                cur, size = [], 2
            cur.append(enc)
            size += len(enc) + 1
        if cur:
            bodies.append((b"[" + b",".join(cur) + b"]", len(cur)))
        return bodies

    async def send_records(self, records: list[dict[str, Any]], events: list[Event]) -> DeliveryResult:
        for f in ("dce_endpoint", "dcr_immutable_id"):
            if not self.config.get(f):
                return self.fail(f"missing config '{f}'", retryable=False)
        url = await self.safe_url(self.endpoint())
        rows = [self.to_row(r, e) for r, e in zip(records, events)]
        try:
            token = await self._token()
        except _TokenError as exc:
            return self.fail(exc.detail, retryable=exc.retryable, status_code=exc.status_code)
        accepted = 0
        for body, count in self.split(rows):
            refreshed = False
            while True:
                resp = await self.client().post(url, content=body, headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }, follow_redirects=False)
                if resp.status_code == 401 and not refreshed:
                    # Cached token revoked / expired early: refresh once.
                    refreshed = True
                    try:
                        token = await self._token(force=True)
                    except _TokenError as exc:
                        return self.fail(exc.detail, retryable=exc.retryable,
                                         status_code=exc.status_code)
                    continue
                break
            if resp.status_code in (200, 204):
                accepted += count
                continue
            if resp.status_code == 403:
                return self.fail(
                    "Sentinel returned HTTP 403: the app needs the 'Monitoring Metrics Publisher' "
                    f"role on the DCR -- {short_body(resp, self.secrets)}",
                    retryable=False, status_code=403)
            res = self.http_failure(resp, "Logs Ingestion API")
            if accepted:
                res.detail += f" (after {accepted} record(s) were accepted)"
            return res
        return DeliveryResult(ok=True, status_code=204, detail=f"Sentinel accepted {accepted} record(s)")
