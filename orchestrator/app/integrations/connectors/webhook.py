"""Generic outbound webhook, HMAC-SHA256 signed.

Every request carries::

    Content-Type:      application/json
    Paddock-Event:     finding.opened
    Paddock-Delivery:  <event id>            # stable across retries -> dedupe on it
    Paddock-Signature: t=<unix seconds>,v1=<hex hmac_sha256(secret, f"{t}.{raw body}")>

Receivers recompute the HMAC over the RAW body bytes, compare in constant
time, and reject timestamps older than 5 minutes (replay window). See
``verify_signature`` below and docs/INTEGRATIONS.md for Python/Node snippets.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Mapping

from .. import outbound
from ..base import Capability, Connector, DeliveryResult, Event, HealthResult, register

SIGNATURE_HEADER = "Paddock-Signature"
REPLAY_WINDOW_SEC = 300


def compute_signature(secret: str, body: bytes, timestamp: int) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return mac.hexdigest()


def signature_header(secret: str, body: bytes, timestamp: int | None = None) -> str:
    t = int(time.time()) if timestamp is None else int(timestamp)
    return f"t={t},v1={compute_signature(secret, body, t)}"


def verify_signature(secret: str, body: bytes, header: str, *, tolerance: int = REPLAY_WINDOW_SEC,
                     now: int | None = None) -> bool:
    """Reference receiver-side check (also used by our tests)."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
        t = int(parts["t"])
    except (KeyError, ValueError):
        return False
    current = int(time.time()) if now is None else now
    if abs(current - t) > tolerance:
        return False
    expected = compute_signature(secret, body, t)
    sigs = [v for k, v in (p.split("=", 1) for p in header.split(",") if "=" in p) if k == "v1"]
    return any(hmac.compare_digest(expected, s) for s in sigs)


def encode_body(event: Event) -> bytes:
    return json.dumps(event.as_dict(), separators=(",", ":"), sort_keys=True, default=str).encode()


@register
class WebhookConnector(Connector):
    kind = "webhook"
    display_name = "Webhook"
    category = "webhook"
    capabilities = frozenset({Capability.NOTIFY})
    config_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["url"],
        "properties": {
            "url": {"type": "string", "format": "uri", "title": "Endpoint URL",
                    "description": "HTTPS endpoint that receives signed JSON events."},
        },
    }
    secret_fields = ("signing_secret",)
    required_secrets = ("signing_secret",)
    url_fields = ("url",)
    docs_url = "docs/INTEGRATIONS.md#webhook"

    async def deliver(self, event: Event) -> DeliveryResult:
        secret = self.secrets.get("signing_secret")
        if not secret:
            return DeliveryResult(ok=False, retryable=False, detail="signing secret is not set")
        body = encode_body(event)
        headers: Mapping[str, str] = {
            "Content-Type": "application/json",
            "Paddock-Event": event.type,
            "Paddock-Delivery": event.id,
            SIGNATURE_HEADER: signature_header(secret, body),
        }
        result, _ = await outbound.post(self.http, self.config["url"], content=body, headers=headers,
                                        secrets=self.secrets.values())
        return result

    async def test(self) -> HealthResult:
        res = await self.deliver(Event(type="integration.test", title="Paddock webhook test",
                                       summary="Signature check: verify Paddock-Signature on your side.",
                                       severity="info"))
        return HealthResult(ok=res.ok, detail=res.detail)
