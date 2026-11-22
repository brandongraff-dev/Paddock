"""A minimal Stripe REST client (httpx, no SDK) + webhook signature checking.

Only what billing needs: Checkout Sessions, Customer Portal sessions,
Customers and Billing Meter Events. Requests are form-encoded with Stripe's
bracket notation; every mutating call can carry an ``Idempotency-Key``.
The secret key is never logged and never echoed into errors.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Any, Iterable

import httpx

from .config import BillingSettings, settings as default_settings

logger = logging.getLogger(__name__)

STRIPE_API_VERSION = "2025-04-30.basil"
_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


class StripeError(Exception):
    """Stripe answered with an error (or could not be reached)."""

    def __init__(self, message: str, *, status: int = 0, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


class SignatureError(ValueError):
    """The ``Stripe-Signature`` header did not verify."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Form encoding (Stripe style: a[b][0][c]=v)
# --------------------------------------------------------------------------- #

def encode_form(params: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def walk(prefix: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                walk(f"{prefix}[{k}]", v)
        elif isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                walk(f"{prefix}[{i}]", v)
        elif isinstance(value, bool):
            out.append((prefix, "true" if value else "false"))
        else:
            out.append((prefix, str(value)))

    for k, v in params.items():
        walk(k, v)
    return out


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class StripeClient:
    def __init__(
        self,
        secret_key: str,
        *,
        base_url: str = "https://api.stripe.com",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._key = secret_key
        self._base = base_url.rstrip("/")
        self._transport = transport

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self._key}",
            "Stripe-Version": STRIPE_API_VERSION,
            "User-Agent": "paddock-billing/1",
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        data = dict(encode_form(params or {}))  # bracketed keys are unique
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=_TIMEOUT) as http:
                if method == "GET":
                    resp = await http.get(self._base + path, params=data, headers=headers)
                else:
                    resp = await http.request(method, self._base + path, data=data, headers=headers)
        except httpx.HTTPError as exc:
            raise StripeError(f"stripe unreachable ({type(exc).__name__})") from exc
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code >= 400:
            err = body.get("error", {}) if isinstance(body, dict) else {}
            raise StripeError(
                str(err.get("message") or f"stripe returned {resp.status_code}")[:300],
                status=resp.status_code,
                code=err.get("code") or err.get("type"),
            )
        return body if isinstance(body, dict) else {}

    async def create_customer(self, *, tenant_id: str, name: str | None, email: str | None = None,
                              idempotency_key: str | None = None) -> dict[str, Any]:
        return await self._request(
            "POST", "/v1/customers",
            {"name": name, "email": email, "metadata": {"paddock_tenant_id": tenant_id}},
            idempotency_key=idempotency_key,
        )

    async def create_checkout_session(
        self,
        *,
        customer: str,
        price_id: str,
        plan: str,
        tenant_id: str,
        success_url: str,
        cancel_url: str,
        trial_days: int | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        sub_data: dict[str, Any] = {"metadata": {"paddock_tenant_id": tenant_id, "plan": plan}}
        if trial_days:
            sub_data["trial_period_days"] = trial_days
        return await self._request(
            "POST", "/v1/checkout/sessions",
            {
                "mode": "subscription",
                "customer": customer,
                "client_reference_id": tenant_id,
                "line_items": [{"price": price_id, "quantity": 1}],
                "success_url": success_url,
                "cancel_url": cancel_url,
                "allow_promotion_codes": True,
                "metadata": {"paddock_tenant_id": tenant_id, "plan": plan},
                "subscription_data": sub_data,
            },
            idempotency_key=idempotency_key,
        )

    async def create_portal_session(self, *, customer: str, return_url: str) -> dict[str, Any]:
        return await self._request(
            "POST", "/v1/billing_portal/sessions", {"customer": customer, "return_url": return_url}
        )

    async def send_meter_event(
        self, *, event_name: str, customer: str, value: int, identifier: str, timestamp: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "event_name": event_name,
            "identifier": identifier,
            "payload": {"stripe_customer_id": customer, "value": value},
        }
        if timestamp is not None:
            params["timestamp"] = timestamp
        return await self._request("POST", "/v1/billing/meter_events", params, idempotency_key=identifier)


def make_client(app=None, cfg: BillingSettings | None = None) -> StripeClient:
    """A client for the configured key. ``app.state.stripe_transport`` lets
    tests inject an ``httpx.MockTransport``."""
    c = cfg or default_settings
    if not c.enabled:
        raise StripeError("billing is not configured")
    transport = getattr(getattr(app, "state", None), "stripe_transport", None)
    return StripeClient(c.stripe_secret_key or "", base_url=c.stripe_api_base, transport=transport)


# --------------------------------------------------------------------------- #
# Webhook signature verification
# --------------------------------------------------------------------------- #

def parse_signature_header(header: str) -> tuple[int, list[str]]:
    ts: int | None = None
    sigs: list[str] = []
    for part in (header or "").split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            try:
                ts = int(v)
            except ValueError:
                raise SignatureError("malformed_timestamp") from None
        elif k == "v1" and v:
            sigs.append(v.strip().lower())
    if ts is None:
        raise SignatureError("missing_timestamp")
    if not sigs:
        raise SignatureError("missing_v1_signature")
    return ts, sigs


def compute_signature(secret: str, timestamp: int, payload: bytes) -> str:
    signed = str(timestamp).encode("ascii") + b"." + payload
    return hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def verify_signature(
    payload: bytes,
    header: str | None,
    secrets: Iterable[str],
    *,
    tolerance_sec: int = 300,
    now: float | None = None,
) -> int:
    """Verify a ``Stripe-Signature`` header; return the signed timestamp.

    HMAC-SHA256 over ``"<t>.<raw body>"`` with each configured secret, compared
    in constant time against every ``v1`` value (Stripe sends several during
    secret rotation). The timestamp must be within ``tolerance_sec`` of now in
    either direction, which bounds how long a captured request stays
    replayable (event-id dedupe closes the rest).
    """
    secret_list = [s for s in secrets if s]
    if not secret_list:
        raise SignatureError("no_webhook_secret_configured")
    if not header:
        raise SignatureError("missing_signature_header")
    ts, sigs = parse_signature_header(header)
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance_sec:
        raise SignatureError("timestamp_outside_tolerance")
    ok = False
    for secret in secret_list:
        expected = compute_signature(secret, ts, payload)
        for sig in sigs:
            # Evaluate every pair: no early exit on a match or a mismatch.
            ok |= hmac.compare_digest(expected.encode("ascii"), sig.encode("ascii", "ignore"))
    if not ok:
        raise SignatureError("signature_mismatch")
    return ts
