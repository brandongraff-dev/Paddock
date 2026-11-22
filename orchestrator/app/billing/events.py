"""Stripe webhook events -> subscription state.

``next_state`` is a pure transition function (current row + event -> new row),
so every event type is unit-tested without a database. ``process_event`` adds
tenant resolution and persistence; ``handle_webhook`` adds signature checking
and replay protection.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from . import store
from .config import BillingSettings, plan_for_price, plans, settings as default_settings
from .stripe import SignatureError, verify_signature

logger = logging.getLogger(__name__)

HANDLED_TYPES = frozenset({
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.paid",
    "invoice.payment_failed",
})
_DEAD = {"canceled", "unpaid", "incomplete", "incomplete_expired", "paused"}
_LIVE_FOR_DUNNING = {"active", "trialing", "past_due"}
_STATUSES = {"incomplete", "incomplete_expired", "trialing", "active", "past_due", "canceled", "unpaid", "paused"}
MAX_BODY_BYTES = 1_000_000


def _ts(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _get(d: Any, *path: str) -> Any:
    for p in path:
        if isinstance(d, dict):
            d = d.get(p)
        elif isinstance(d, list) and p.isdigit() and int(p) < len(d):
            d = d[int(p)]
        else:
            return None
    return d


def _blank() -> dict[str, Any]:
    return {c: None for c in store.SUB_COLS} | {"cancel_at_period_end": False}


def _plan_key(obj: dict, cfg: BillingSettings) -> str | None:
    price = _get(obj, "items", "data", "0", "price", "id") or _get(obj, "plan", "id")
    p = plan_for_price(price, cfg)
    if p:
        return p.key
    meta = _get(obj, "metadata", "plan")
    return meta if meta in plans(cfg) else None


def _invoice_subscription(obj: dict) -> str | None:
    return (
        obj.get("subscription")
        or _get(obj, "parent", "subscription_details", "subscription")
        or None
    )


def event_customer(event: dict) -> str | None:
    obj = _get(event, "data", "object") or {}
    cust = obj.get("customer")
    return cust if isinstance(cust, str) and cust else None


def event_tenant_hint(event: dict) -> str | None:
    """A tenant id WE put in Stripe metadata (only trusted when the customer
    is not mapped yet, and only because the whole event is signed)."""
    obj = _get(event, "data", "object") or {}
    cand = (
        obj.get("client_reference_id")
        or _get(obj, "metadata", "paddock_tenant_id")
        or _get(obj, "parent", "subscription_details", "metadata", "paddock_tenant_id")
    )
    return store.valid_uuid(cand) if cand else None


def next_state(
    cur: dict[str, Any] | None, event: dict, cfg: BillingSettings | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Pure transition. Returns ``(new_row | None, note)``; ``None`` = no change."""
    c = cfg or default_settings
    etype = event.get("type")
    obj = _get(event, "data", "object") or {}
    when = _ts(event.get("created")) or datetime.now(timezone.utc)
    grace = timedelta(days=c.billing_grace_days)
    customer = event_customer(event)

    def base() -> dict[str, Any]:
        return dict(cur) if cur else _blank()

    if etype == "checkout.session.completed":
        if obj.get("mode") != "subscription":
            return None, "not_a_subscription_checkout"
        sub_id = obj.get("subscription")
        if not isinstance(sub_id, str) or not sub_id:
            return None, "no_subscription"
        new = base()
        new["stripe_customer_id"] = customer or new["stripe_customer_id"]
        plan = _get(obj, "metadata", "plan")
        if plan in plans(c):
            new["plan"] = plan
        if new.get("stripe_subscription_id") != sub_id:
            # A different (new) subscription: start from a clean billing slate.
            new["stripe_subscription_id"] = sub_id
            new["payment_failed_at"] = None
            new["grace_until"] = None
            new["cancel_at_period_end"] = False
            paid = obj.get("payment_status") in {"paid", "no_payment_required"}
            new["status"] = "active" if paid and new["plan"] else "incomplete"
        return new, "checkout_completed"

    if etype in {"customer.subscription.created", "customer.subscription.updated"}:
        sub_id = obj.get("id")
        status = obj.get("status")
        if not isinstance(sub_id, str) or status not in _STATUSES:
            return None, "malformed_subscription"
        new = base()
        cur_sub = new.get("stripe_subscription_id")
        cur_dead = cur is None or new.get("status") in _DEAD or not cur_sub
        if cur_sub and cur_sub != sub_id:
            if status in _DEAD:
                return None, "stale_subscription"
            if not cur_dead and etype == "customer.subscription.updated":
                return None, "other_live_subscription"
            new["payment_failed_at"] = None
            new["grace_until"] = None
        new["stripe_customer_id"] = customer or new["stripe_customer_id"]
        new["stripe_subscription_id"] = sub_id
        new["status"] = status
        plan = _plan_key(obj, c)
        if plan:
            new["plan"] = plan
        new["cancel_at_period_end"] = bool(obj.get("cancel_at_period_end"))
        period_end = _ts(obj.get("current_period_end")) or _ts(_get(obj, "items", "data", "0", "current_period_end"))
        if period_end:
            new["current_period_end"] = period_end
        new["trial_end"] = _ts(obj.get("trial_end")) or new.get("trial_end")
        if status in {"active", "trialing"}:
            new["payment_failed_at"] = None
            new["grace_until"] = None
        elif status == "past_due":
            if new.get("payment_failed_at") is None:
                new["payment_failed_at"] = when
            new["grace_until"] = new["payment_failed_at"] + grace
        else:
            new["grace_until"] = None
        return new, f"subscription_{status}"

    if etype == "customer.subscription.deleted":
        sub_id = obj.get("id")
        if cur is not None and cur.get("stripe_subscription_id") not in (None, sub_id):
            return None, "stale_subscription"
        new = base()
        new["stripe_customer_id"] = customer or new["stripe_customer_id"]
        new["stripe_subscription_id"] = sub_id if isinstance(sub_id, str) else new["stripe_subscription_id"]
        new["status"] = "canceled"
        new["cancel_at_period_end"] = False
        new["grace_until"] = None
        return new, "subscription_deleted"

    if etype in {"invoice.paid", "invoice.payment_failed"}:
        if cur is None:
            return None, "no_subscription_yet"
        sub_id = _invoice_subscription(obj)
        if sub_id and cur.get("stripe_subscription_id") not in (None, sub_id):
            return None, "stale_subscription"
        new = base()
        if etype == "invoice.paid":
            new["payment_failed_at"] = None
            new["grace_until"] = None
            if new["status"] in {"past_due", "incomplete"} and new.get("plan"):
                new["status"] = "active"
            return new, "invoice_paid"
        # payment_failed: only a live subscription enters dunning, and a RETRY
        # never extends the grace window (it counts from the first failure).
        if new["status"] not in _LIVE_FOR_DUNNING:
            return None, "not_dunnable"
        first = new.get("payment_failed_at") or when
        new["payment_failed_at"] = first
        new["grace_until"] = first + grace
        new["status"] = "past_due"
        return new, "payment_failed"

    return None, "unhandled_type"


async def process_event(app, pool, event: dict, cfg: BillingSettings | None = None) -> tuple[str, str | None]:
    """Apply one verified event. Returns ``(outcome, tenant_id)`` where outcome
    is ``processed`` or ``ignored``."""
    c = cfg or default_settings
    etype = event.get("type")
    if etype not in HANDLED_TYPES:
        return "ignored", None
    customer = event_customer(event)
    tenant = await store.tenant_for_customer(pool, customer)
    hint = event_tenant_hint(event)
    if tenant is None:
        if hint and customer and await store.tenant_exists(pool, hint):
            await store.link_customer(pool, customer, hint)
            tenant = hint
        else:
            logger.warning("billing_event_unknown_customer", extra={"event_type": etype})
            return "ignored", None
    elif hint and hint != tenant:
        logger.warning("billing_event_tenant_mismatch", extra={"event_type": etype})

    created = _ts(event.get("created"))
    outcome = {"note": "noop"}

    def transition(cur):
        new, note = next_state(cur, event, c)
        outcome["note"] = note
        return new

    await store.write_subscription(
        pool, tenant, event_created=created, event_id=event.get("id"), transition=transition,
    )
    from . import service  # local: avoid import cycle

    service.invalidate(tenant)
    logger.info("billing_event_applied", extra={"event_type": etype, "note": outcome["note"], "tenant": tenant})
    return "processed", tenant


class WebhookResult:
    def __init__(self, status: int, body: dict[str, Any]):
        self.status = status
        self.body = body


async def handle_webhook(app, raw: bytes, signature: str | None, *, now: float | None = None,
                         cfg: BillingSettings | None = None) -> WebhookResult:
    """Verify, de-duplicate, process. Never raises."""
    c = cfg or default_settings
    if not c.enabled or not c.webhook_secrets():
        return WebhookResult(503, {"error": "billing_not_configured"})
    if len(raw) > MAX_BODY_BYTES:
        return WebhookResult(413, {"error": "payload_too_large"})
    try:
        verify_signature(raw, signature, c.webhook_secrets(),
                         tolerance_sec=c.billing_webhook_tolerance_sec, now=now)
    except SignatureError as exc:
        logger.warning("billing_webhook_rejected", extra={"reason": exc.reason})
        return WebhookResult(400, {"error": "invalid_signature"})
    try:
        event = json.loads(raw)
    except ValueError:
        return WebhookResult(400, {"error": "invalid_json"})
    if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not isinstance(event.get("type"), str):
        return WebhookResult(400, {"error": "invalid_event"})

    pool = app.state.pool
    event_id, etype = event["id"], event["type"]
    try:
        if not await store.claim_event(pool, event_id, etype, _ts(event.get("created"))):
            return WebhookResult(200, {"received": True, "duplicate": True})
    except Exception:  # noqa: BLE001
        logger.exception("billing_event_claim_failed")
        return WebhookResult(503, {"error": "temporarily_unavailable"})
    try:
        outcome, tenant = await process_event(app, pool, event, c)
    except Exception as exc:  # noqa: BLE001 -- Stripe retries a 5xx
        logger.exception("billing_event_failed", extra={"event_type": etype})
        try:
            await store.finish_event(pool, event_id, "failed", error=f"{type(exc).__name__}: {exc}")
        except Exception:  # noqa: BLE001
            logger.exception("billing_event_finish_failed")
        return WebhookResult(500, {"error": "processing_failed"})
    await store.finish_event(pool, event_id, outcome, tenant_id=tenant)
    return WebhookResult(200, {"received": True, "status": outcome})
