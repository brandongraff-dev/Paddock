"""Hosted-edition billing (schema 028, app/billing/): Stripe webhooks, state
machine, entitlements, trials/dunning, 402 gating, quotas, usage metering,
the public /status feed.

No network: Stripe is an ``httpx.MockTransport`` injected through
``app.state.stripe_transport``; webhooks are signed with a throwaway secret.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import Depends

from app import tenancy
from app.billing import config as bcfg
from app.billing import entitlements as ent
from app.billing import events as bevents
from app.billing import gate as bgate
from app.billing import metering, service
from app.billing import status as bstatus
from app.billing import stripe as bstripe
from app.config import settings
from app.licensing import FEATURES

SECRET = "whsec_unit_test_secret"
DEFAULT_TENANT = tenancy.DEFAULT_TENANT_ID
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def ts(dt: datetime) -> int:
    return int(dt.timestamp())


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def billing(monkeypatch):
    """Billing ON with placeholder (fake) keys and price ids."""
    s = bcfg.settings
    monkeypatch.setattr(s, "stripe_secret_key", "sk_test_not_a_real_key")
    monkeypatch.setattr(s, "stripe_webhook_secret", SECRET)
    monkeypatch.setattr(s, "stripe_price_team", "price_team_placeholder")
    monkeypatch.setattr(s, "stripe_price_enterprise", "price_ent_placeholder")
    monkeypatch.setattr(s, "billing_public_url", "https://app.example.test")
    monkeypatch.setattr(s, "billing_cache_ttl_sec", 0.0)
    monkeypatch.setattr(s, "enforce_editions", "auto")
    monkeypatch.setattr(settings, "otdiscovery_url", "http://127.0.0.1:9")
    service.invalidate()
    bstatus.reset_cache()
    yield s
    service.invalidate()
    bstatus.reset_cache()


class FakeStripe:
    """Records every request; answers like the bits of Stripe we call."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.meter_failures = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = dict(urllib.parse.parse_qsl(request.content.decode())) if request.content else {}
        form.update(dict(urllib.parse.parse_qsl(request.url.query.decode())))
        self.requests.append({
            "method": request.method, "path": request.url.path, "form": form,
            "headers": dict(request.headers),
        })
        p = request.url.path
        if p == "/v1/customers":
            return httpx.Response(200, json={"id": "cus_test_1"})
        if p == "/v1/checkout/sessions":
            return httpx.Response(200, json={"id": "cs_1", "url": "https://checkout.stripe.test/c/cs_1"})
        if p == "/v1/billing_portal/sessions":
            return httpx.Response(200, json={"id": "bps_1", "url": "https://billing.stripe.test/p/1"})
        if p == "/v1/billing/meter_events":
            if self.meter_failures > 0:
                self.meter_failures -= 1
                return httpx.Response(500, json={"error": {"message": "boom", "type": "api_error"}})
            return httpx.Response(200, json={"object": "billing.meter_event"})
        return httpx.Response(404, json={"error": {"message": "nope"}})

    def by_path(self, path: str) -> list[dict]:
        return [r for r in self.requests if r["path"] == path]


@pytest.fixture
def stripe_mock(app, billing):
    fake = FakeStripe()
    app.state.stripe_transport = httpx.MockTransport(fake)
    return fake


def sign(payload: bytes, *, secret: str = SECRET, when: float | None = None) -> str:
    t = int(time.time() if when is None else when)
    return f"t={t},v1={bstripe.compute_signature(secret, t, payload)}"


def make_event(etype: str, obj: dict, *, eid: str | None = None, created: datetime | None = None) -> dict:
    return {
        "id": eid or f"evt_{uuid.uuid4().hex[:14]}",
        "type": etype,
        "created": ts(created or datetime.now(timezone.utc)),
        "data": {"object": obj},
    }


async def post_event(client, event: dict, *, headers: dict | None = None, secret: str = SECRET,
                     when: float | None = None):
    body = json.dumps(event).encode()
    h = {"Stripe-Signature": sign(body, secret=secret, when=when), "Content-Type": "application/json"}
    h.update(headers or {})
    return await client.post("/v1/billing/webhook", content=body, headers=h)


def checkout_completed(customer="cus_1", sub="sub_1", plan="team", tenant=DEFAULT_TENANT, **kw):
    return make_event("checkout.session.completed", {
        "id": "cs_1", "mode": "subscription", "customer": customer, "subscription": sub,
        "client_reference_id": tenant, "payment_status": "paid", "metadata": {"plan": plan},
    }, **kw)


def sub_event(etype="customer.subscription.updated", *, customer="cus_1", sub="sub_1", status="active",
              price="price_team_placeholder", cancel=False, period_end=None, **kw):
    return make_event(etype, {
        "id": sub, "customer": customer, "status": status, "cancel_at_period_end": cancel,
        "current_period_end": ts(period_end or datetime.now(timezone.utc) + timedelta(days=30)),
        "items": {"data": [{"price": {"id": price}}]},
    }, **kw)


def invoice_event(etype, *, customer="cus_1", sub="sub_1", **kw):
    return make_event(etype, {"id": "in_1", "customer": customer, "subscription": sub}, **kw)


async def sub_row(db_pool, tenant=DEFAULT_TENANT):
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM billing_subscriptions WHERE tenant_id = $1::uuid", tenant)
    return dict(row) if row else None


async def age_tenant(db_pool, days: int, tenant=DEFAULT_TENANT):
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE tenants SET created_at = NOW() - make_interval(days => $2) WHERE id = $1::uuid",
            tenant, days,
        )


# --------------------------------------------------------------------------- #
# Webhook signature
# --------------------------------------------------------------------------- #

BODY = b'{"id":"evt_1","type":"invoice.paid"}'


def test_signature_good_roundtrip():
    t = 1_700_000_000
    header = f"t={t},v1={bstripe.compute_signature(SECRET, t, BODY)}"
    assert bstripe.verify_signature(BODY, header, [SECRET], now=t + 5) == t


def test_signature_matches_stripe_scheme():
    # HMAC-SHA256 over "<t>.<payload>", hex digest (independent re-computation).
    import hashlib
    import hmac

    t = 1_700_000_000
    want = hmac.new(SECRET.encode(), f"{t}.".encode() + BODY, hashlib.sha256).hexdigest()
    assert bstripe.compute_signature(SECRET, t, BODY) == want


@pytest.mark.parametrize("mutate", [
    lambda b: b + b" ",                      # body tampered
    lambda b: b.replace(b"paid", b"void"),   # body tampered
])
def test_signature_rejects_tampered_body(mutate):
    t = 1_700_000_000
    header = f"t={t},v1={bstripe.compute_signature(SECRET, t, BODY)}"
    with pytest.raises(bstripe.SignatureError) as e:
        bstripe.verify_signature(mutate(BODY), header, [SECRET], now=t)
    assert e.value.reason == "signature_mismatch"


def test_signature_rejects_wrong_secret_and_garbage():
    t = 1_700_000_000
    header = f"t={t},v1={bstripe.compute_signature('whsec_other', t, BODY)}"
    for h, reason in [
        (header, "signature_mismatch"),
        (None, "missing_signature_header"),
        ("", "missing_signature_header"),
        ("v1=abcd", "missing_timestamp"),
        (f"t={t}", "missing_v1_signature"),
        ("t=notanumber,v1=ab", "malformed_timestamp"),
        (f"t={t},v1=zz-not-hex-é", "signature_mismatch"),
    ]:
        with pytest.raises(bstripe.SignatureError) as e:
            bstripe.verify_signature(BODY, h, [SECRET], now=t)
        assert e.value.reason == reason


def test_signature_timestamp_tolerance_both_directions():
    t = 1_700_000_000
    header = f"t={t},v1={bstripe.compute_signature(SECRET, t, BODY)}"
    assert bstripe.verify_signature(BODY, header, [SECRET], tolerance_sec=300, now=t + 299)
    for skew in (301, -301, 86_400):
        with pytest.raises(bstripe.SignatureError) as e:
            bstripe.verify_signature(BODY, header, [SECRET], tolerance_sec=300, now=t + skew)
        assert e.value.reason == "timestamp_outside_tolerance"


def test_signature_secret_rotation_and_multiple_v1():
    t = 1_700_000_000
    old = bstripe.compute_signature("whsec_old", t, BODY)
    new = bstripe.compute_signature("whsec_new", t, BODY)
    # Stripe sends one v1 per active secret during rotation.
    assert bstripe.verify_signature(BODY, f"t={t},v1={old},v1={new}", ["whsec_new"], now=t)
    assert bstripe.verify_signature(BODY, f"t={t},v1={old}", ["whsec_new", "whsec_old"], now=t)
    with pytest.raises(bstripe.SignatureError):
        bstripe.verify_signature(BODY, f"t={t},v1={old}", ["whsec_new"], now=t)
    with pytest.raises(bstripe.SignatureError) as e:
        bstripe.verify_signature(BODY, f"t={t},v1={old}", [], now=t)
    assert e.value.reason == "no_webhook_secret_configured"


def test_encode_form_bracket_notation():
    got = bstripe.encode_form({
        "mode": "subscription", "line_items": [{"price": "p", "quantity": 1}],
        "metadata": {"a": "b"}, "flag": True, "skip": None,
    })
    assert ("line_items[0][price]", "p") in got
    assert ("line_items[0][quantity]", "1") in got
    assert ("metadata[a]", "b") in got and ("flag", "true") in got
    assert not any(k == "skip" for k, _ in got)


# --------------------------------------------------------------------------- #
# Webhook endpoint
# --------------------------------------------------------------------------- #

async def test_webhook_off_without_stripe_key(client):
    assert bcfg.settings.enabled is False
    r = await client.post("/v1/billing/webhook", content=b"{}", headers={"Stripe-Signature": "t=1,v1=aa"})
    assert r.status_code == 503 and r.json()["error"] == "billing_not_configured"


async def test_webhook_bad_signature_changes_nothing(client, billing, db_pool):
    ev = checkout_completed()
    r = await post_event(client, ev, secret="whsec_attacker")
    assert r.status_code == 400 and r.json() == {"error": "invalid_signature"}
    r = await client.post("/v1/billing/webhook", content=json.dumps(ev).encode())  # no header
    assert r.status_code == 400
    assert await sub_row(db_pool) is None
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM billing_events") == 0


async def test_webhook_stale_and_future_timestamps_rejected(client, billing, db_pool):
    ev = checkout_completed()
    assert (await post_event(client, ev, when=time.time() - 3600)).status_code == 400
    assert (await post_event(client, ev, when=time.time() + 3600)).status_code == 400
    assert await sub_row(db_pool) is None


async def test_webhook_replay_is_a_noop(client, billing, db_pool):
    ev = checkout_completed(eid="evt_replay_1")
    assert (await post_event(client, ev)).status_code == 200
    first = await sub_row(db_pool)
    assert first["status"] == "active" and first["plan"] == "team"
    # An attacker (or Stripe) re-sends the exact same signed event: 200, no re-run.
    # Tamper with state in between so a re-run would be visible.
    async with db_pool.acquire() as con:
        await con.execute("UPDATE billing_subscriptions SET status = 'canceled'")
    r = await post_event(client, ev)
    assert r.status_code == 200 and r.json()["duplicate"] is True
    assert (await sub_row(db_pool))["status"] == "canceled"
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM billing_events WHERE event_id = 'evt_replay_1'") == 1


async def test_webhook_failed_event_is_retried(client, billing, db_pool, monkeypatch):
    calls = {"n": 0}
    real = bevents.process_event

    async def flaky(app, pool, event, cfg=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return await real(app, pool, event, cfg)

    monkeypatch.setattr(bevents, "process_event", flaky)
    ev = checkout_completed(eid="evt_flaky")
    assert (await post_event(client, ev)).status_code == 500
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT status FROM billing_events WHERE event_id = 'evt_flaky'") == "failed"
    assert (await post_event(client, ev)).status_code == 200
    assert (await sub_row(db_pool))["status"] == "active"
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT status, attempts FROM billing_events WHERE event_id = 'evt_flaky'")
    assert row["status"] == "processed" and row["attempts"] == 2


async def test_webhook_inflight_duplicate_not_reprocessed(client, billing, db_pool):
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO billing_events (event_id, type) VALUES ('evt_busy', 'invoice.paid')")
    r = await post_event(client, make_event("invoice.paid", {"customer": "cus_1"}, eid="evt_busy"))
    assert r.status_code == 200 and r.json().get("duplicate") is True


async def test_webhook_unknown_customer_and_unhandled_type_are_ignored(client, billing, db_pool):
    r = await post_event(client, sub_event(customer="cus_stranger"))
    assert r.status_code == 200 and r.json()["status"] == "ignored"
    r = await post_event(client, make_event("charge.refunded", {"customer": "cus_1"}))
    assert r.status_code == 200 and r.json()["status"] == "ignored"
    assert await sub_row(db_pool) is None


async def test_webhook_malformed_payloads(client, billing):
    for body in (b"not json", b"[]", b'{"id": 5, "type": "x"}', b'{"type": "invoice.paid"}'):
        r = await client.post("/v1/billing/webhook", content=body,
                              headers={"Stripe-Signature": sign(body)})
        assert r.status_code == 400, body


async def test_webhook_oversized_body_refused(client, billing):
    body = b"x" * (bevents.MAX_BODY_BYTES + 1)
    r = await client.post("/v1/billing/webhook", content=body, headers={"Stripe-Signature": sign(body)})
    assert r.status_code == 413


async def test_webhook_cannot_repoint_a_linked_customer(client, billing, db_pool):
    """A signed event whose metadata names another tenant must not steal the
    customer: the existing customer -> tenant mapping wins."""
    other = "00000000-0000-0000-0000-0000000000c3"
    await tenancy.create_tenant(db_pool, slug="charlie", name="Charlie", tenant_id=other)
    assert (await post_event(client, checkout_completed(customer="cus_x", tenant=DEFAULT_TENANT))).status_code == 200
    r = await post_event(client, checkout_completed(customer="cus_x", sub="sub_2", tenant=other))
    assert r.status_code == 200
    assert await sub_row(db_pool, other) is None
    async with db_pool.acquire() as con:
        assert str(await con.fetchval(
            "SELECT owner_tenant FROM billing_customers WHERE stripe_customer_id = 'cus_x'")) == DEFAULT_TENANT


# --------------------------------------------------------------------------- #
# Every event transition (pure)
# --------------------------------------------------------------------------- #

C = bcfg.BillingSettings(
    stripe_secret_key="sk_test_x", stripe_price_team="price_team_placeholder",
    stripe_price_enterprise="price_ent_placeholder", billing_grace_days=7,
)


def step(cur, event):
    new, note = bevents.next_state(cur, event, C)
    return new, note


def test_checkout_completed_creates_active_subscription():
    new, note = step(None, checkout_completed(plan="enterprise"))
    assert note == "checkout_completed"
    assert (new["status"], new["plan"], new["stripe_subscription_id"], new["stripe_customer_id"]) == (
        "active", "enterprise", "sub_1", "cus_1")


def test_checkout_unpaid_stays_incomplete_and_non_subscription_ignored():
    ev = checkout_completed()
    ev["data"]["object"]["payment_status"] = "unpaid"
    assert step(None, ev)[0]["status"] == "incomplete"
    ev["data"]["object"]["mode"] = "payment"
    assert step(None, ev) == (None, "not_a_subscription_checkout")


def test_checkout_replay_for_same_subscription_does_not_reset_state():
    cur, _ = step(None, checkout_completed())
    cur["status"], cur["payment_failed_at"] = "past_due", NOW
    again, _ = step(cur, checkout_completed())
    assert again["status"] == "past_due" and again["payment_failed_at"] == NOW


def test_subscription_created_and_updated_set_plan_from_price():
    new, note = step(None, sub_event("customer.subscription.created", price="price_ent_placeholder"))
    assert (new["plan"], new["status"], note) == ("enterprise", "active", "subscription_active")
    up, _ = step(new, sub_event(price="price_team_placeholder", cancel=True))
    assert up["plan"] == "team" and up["cancel_at_period_end"] is True


def test_subscription_unknown_price_keeps_existing_plan():
    cur, _ = step(None, checkout_completed(plan="team"))
    new, _ = step(cur, sub_event(price="price_unknown"))
    assert new["plan"] == "team"


def test_subscription_trial_end_is_recorded():
    ev = sub_event(status="trialing")
    ev["data"]["object"]["trial_end"] = ts(NOW + timedelta(days=3))
    new, _ = step(None, ev)
    assert new["status"] == "trialing" and new["trial_end"] == NOW + timedelta(days=3)


def test_subscription_deleted_cancels():
    cur, _ = step(None, sub_event())
    new, note = step(cur, make_event("customer.subscription.deleted", {"id": "sub_1", "customer": "cus_1"}))
    assert (new["status"], note) == ("canceled", "subscription_deleted")


def test_deleted_event_for_an_old_subscription_is_ignored():
    cur, _ = step(None, sub_event(sub="sub_new"))
    assert step(cur, make_event("customer.subscription.deleted", {"id": "sub_old", "customer": "cus_1"})) == (
        None, "stale_subscription")


def test_invoice_payment_failed_enters_dunning_with_grace():
    cur, _ = step(None, sub_event())
    when = NOW
    new, note = step(cur, invoice_event("invoice.payment_failed", created=when))
    assert note == "payment_failed" and new["status"] == "past_due"
    assert new["payment_failed_at"] == when and new["grace_until"] == when + timedelta(days=7)


def test_dunning_retries_do_not_extend_grace():
    cur, _ = step(None, sub_event())
    first, _ = step(cur, invoice_event("invoice.payment_failed", created=NOW))
    retry, _ = step(first, invoice_event("invoice.payment_failed", created=NOW + timedelta(days=3)))
    assert retry["payment_failed_at"] == NOW and retry["grace_until"] == NOW + timedelta(days=7)
    upd, _ = step(retry, sub_event(status="past_due", created=NOW + timedelta(days=4)))
    assert upd["grace_until"] == NOW + timedelta(days=7)


def test_invoice_paid_clears_dunning_and_reactivates():
    cur, _ = step(None, sub_event())
    failed, _ = step(cur, invoice_event("invoice.payment_failed", created=NOW))
    paid, note = step(failed, invoice_event("invoice.paid", created=NOW + timedelta(days=2)))
    assert note == "invoice_paid"
    assert paid["status"] == "active" and paid["payment_failed_at"] is None and paid["grace_until"] is None


def test_invoice_for_unknown_or_other_subscription_is_ignored():
    assert step(None, invoice_event("invoice.paid"))[1] == "no_subscription_yet"
    cur, _ = step(None, sub_event(sub="sub_1"))
    assert step(cur, invoice_event("invoice.payment_failed", sub="sub_other"))[1] == "stale_subscription"


def test_payment_failure_on_a_dead_subscription_does_not_resurrect_it():
    cur, _ = step(None, sub_event())
    dead, _ = step(cur, make_event("customer.subscription.deleted", {"id": "sub_1", "customer": "cus_1"}))
    assert step(dead, invoice_event("invoice.payment_failed")) == (None, "not_dunnable")


def test_resubscribe_after_cancel_switches_subscription_and_clears_dunning():
    cur, _ = step(None, sub_event(sub="sub_1"))
    failed, _ = step(cur, invoice_event("invoice.payment_failed", created=NOW))
    dead, _ = step(failed, make_event("customer.subscription.deleted", {"id": "sub_1", "customer": "cus_1"}))
    new, _ = step(dead, sub_event("customer.subscription.created", sub="sub_2"))
    assert new["stripe_subscription_id"] == "sub_2" and new["status"] == "active"
    assert new["payment_failed_at"] is None and new["grace_until"] is None


def test_second_live_subscription_update_does_not_hijack():
    cur, _ = step(None, sub_event(sub="sub_1"))
    assert step(cur, sub_event(sub="sub_zombie"))[1] == "other_live_subscription"
    assert step(cur, sub_event(sub="sub_zombie", status="canceled"))[1] == "stale_subscription"


async def test_out_of_order_events_do_not_roll_state_back(client, billing, db_pool):
    t0 = datetime.now(timezone.utc) - timedelta(minutes=10)
    assert (await post_event(client, checkout_completed(created=t0))).status_code == 200
    # newer: payment failed; then an OLDER `updated(active)` arrives late.
    assert (await post_event(client, invoice_event("invoice.payment_failed", created=t0 + timedelta(minutes=5)))).status_code == 200
    assert (await post_event(client, sub_event(status="active", created=t0 + timedelta(minutes=2)))).status_code == 200
    row = await sub_row(db_pool)
    assert row["status"] == "past_due" and row["payment_failed_at"] is not None


async def test_full_lifecycle_through_the_api(client, billing, db_pool):
    now = datetime.now(timezone.utc)
    await post_event(client, checkout_completed(created=now - timedelta(minutes=9)))
    await post_event(client, sub_event("customer.subscription.created", created=now - timedelta(minutes=8)))
    assert (await sub_row(db_pool))["status"] == "active"
    await post_event(client, invoice_event("invoice.payment_failed", created=now - timedelta(minutes=7)))
    row = await sub_row(db_pool)
    assert row["status"] == "past_due" and row["grace_until"] is not None
    me = (await client.get("/v1/billing")).json()
    assert me["status"] == "past_due" and me["dunning"] is True and me["edition"] == "team"
    await post_event(client, invoice_event("invoice.paid", created=now - timedelta(minutes=6)))
    me = (await client.get("/v1/billing")).json()
    assert me["status"] == "active" and me["dunning"] is False
    await post_event(client, make_event("customer.subscription.deleted",
                                        {"id": "sub_1", "customer": "cus_1"}, created=now - timedelta(minutes=5)))
    me = (await client.get("/v1/billing")).json()
    assert me["status"] == "canceled" and me["edition"] == "community" and me["downgraded"] is True


# --------------------------------------------------------------------------- #
# Entitlements (pure): trial expiry, dunning, downgrade
# --------------------------------------------------------------------------- #

def sub(**kw):
    base = dict(status="active", plan="team", stripe_customer_id="cus_1", stripe_subscription_id="sub_1")
    base.update(kw)
    return ent.Subscription(**base)


def test_trial_active_then_expires():
    created = NOW - timedelta(days=13, hours=23)
    e = ent.compute_entitlements(None, created, NOW, C)
    assert (e.edition, e.status, e.source) == ("team", "trialing", "trial")
    assert e.trial_ends_at == created + timedelta(days=14)
    assert e.has("sso_saml") and not e.has("scim")
    assert e.trial_days_left(NOW) == 1
    later = ent.compute_entitlements(None, created, NOW + timedelta(hours=2), C)
    assert (later.edition, later.status, later.downgraded) == ("community", "trial_expired", True)
    assert not later.features and later.assets == bcfg.community_limits(C)["assets"]


def test_trial_length_is_configurable_and_zero_disables():
    c0 = bcfg.BillingSettings(billing_trial_days=0)
    assert ent.compute_entitlements(None, NOW, NOW, c0).status == "trial_expired"
    c30 = bcfg.BillingSettings(billing_trial_days=30)
    assert ent.compute_entitlements(None, NOW - timedelta(days=29), NOW, c30).status == "trialing"


def test_paying_subscription_never_gets_a_second_trial():
    e = ent.compute_entitlements(sub(status="canceled"), NOW, NOW, C)  # tenant created "now"
    assert e.edition == "community" and e.status == "canceled"


def test_active_plans_map_to_editions_and_limits():
    team = ent.compute_entitlements(sub(), NOW - timedelta(days=90), NOW, C)
    assert (team.edition, team.has("sso_saml"), team.has("scim")) == ("team", True, False)
    assert team.assets == C.billing_team_assets and team.sites == C.billing_team_sites
    big = ent.compute_entitlements(sub(plan="enterprise"), NOW - timedelta(days=90), NOW, C)
    assert big.edition == "enterprise" and big.has("scim") and big.has("compliance_packs")
    assert (big.seats, big.sites, big.assets) == (None, None, None)


def test_dunning_keeps_access_inside_grace_then_downgrades():
    failed = NOW - timedelta(days=3)
    s = sub(status="past_due", payment_failed_at=failed, grace_until=failed + timedelta(days=7))
    inside = ent.compute_entitlements(s, NOW - timedelta(days=90), NOW, C)
    assert inside.edition == "team" and inside.dunning and inside.status == "past_due"
    assert inside.grace_ends_at == failed + timedelta(days=7)
    after = ent.compute_entitlements(s, NOW - timedelta(days=90), NOW + timedelta(days=5), C)
    assert (after.edition, after.status, after.downgraded, after.dunning) == ("community", "payment_failed", True, False)


def test_past_due_without_grace_until_falls_back_to_failure_time():
    s = sub(status="past_due", payment_failed_at=NOW - timedelta(days=8))
    assert ent.compute_entitlements(s, NOW, NOW, C).status == "payment_failed"
    s2 = sub(status="past_due", payment_failed_at=NOW - timedelta(days=1))
    assert ent.compute_entitlements(s2, NOW, NOW, C).dunning is True
    # no timestamps at all: no grace to give
    assert ent.compute_entitlements(sub(status="past_due"), NOW, NOW, C).status == "payment_failed"


@pytest.mark.parametrize("status", ["canceled", "unpaid", "incomplete", "incomplete_expired", "paused"])
def test_dead_states_are_community(status):
    e = ent.compute_entitlements(sub(status=status), NOW - timedelta(days=90), NOW, C)
    assert e.edition == "community" and e.downgraded and not e.features


def test_stripe_trialing_is_cut_off_after_trial_end_plus_slack():
    s = sub(status="trialing", trial_end=NOW - timedelta(hours=1))
    assert ent.compute_entitlements(s, NOW, NOW, C).edition == "team"  # webhook lag allowance
    s2 = sub(status="trialing", trial_end=NOW - timedelta(days=2))
    assert ent.compute_entitlements(s2, NOW, NOW, C).status == "trial_expired"


def test_missed_deleted_webhook_cannot_keep_paid_access_forever():
    s = sub(cancel_at_period_end=True, current_period_end=NOW - timedelta(days=3))
    assert ent.compute_entitlements(s, NOW, NOW, C).edition == "community"
    ok = sub(cancel_at_period_end=True, current_period_end=NOW + timedelta(days=3))
    assert ent.compute_entitlements(ok, NOW, NOW, C).edition == "team"


def test_license_merge_best_edition_wins():
    from app import licensing as lic

    team = ent.compute_entitlements(sub(), NOW - timedelta(days=90), NOW, C)
    key_lic = lic.License(edition="enterprise", status="active", source="env",
                          features=lic.edition_features("enterprise"), seats=50)
    assert ent.merge_with_license(team, key_lic).edition == "enterprise"
    expired = lic.License(edition="community", status="expired")
    assert ent.merge_with_license(team, expired) is team


# --------------------------------------------------------------------------- #
# GET /v1/billing, Checkout, Portal
# --------------------------------------------------------------------------- #

async def test_billing_off_reports_disabled_and_posts_503(client):
    r = await client.get("/v1/billing")
    assert r.status_code == 200
    j = r.json()
    assert j["enabled"] is False and j["enforcement"] is False and j["edition"] == "community"
    assert (await client.post("/v1/billing/checkout", json={"plan": "team"})).status_code == 503
    assert (await client.post("/v1/billing/portal")).status_code == 503


async def test_get_billing_shows_trial_countdown_and_plans(client, billing, db_pool):
    await age_tenant(db_pool, 4)
    j = (await client.get("/v1/billing")).json()
    assert j["enabled"] and j["enforcement"]
    assert j["status"] == "trialing" and j["edition"] == "team" and j["source"] == "trial"
    assert j["trial_days_left"] == 10
    assert {p["key"] for p in j["plans"]} == {"team", "enterprise"} and all(p["purchasable"] for p in j["plans"])
    assert set(j["usage"]) == {"seats", "sites", "assets"} and j["can_manage"] is False


async def test_checkout_creates_customer_session_and_links_tenant(client, stripe_mock, db_pool):
    r = await client.post("/v1/billing/checkout", json={"plan": "enterprise"})
    assert r.status_code == 200 and r.json()["url"] == "https://checkout.stripe.test/c/cs_1"
    cust = stripe_mock.by_path("/v1/customers")[0]
    assert cust["form"]["metadata[paddock_tenant_id]"] == DEFAULT_TENANT
    assert cust["headers"]["idempotency-key"] == f"paddock-customer-{DEFAULT_TENANT}"
    assert cust["headers"]["authorization"] == "Bearer sk_test_not_a_real_key"
    sess = stripe_mock.by_path("/v1/checkout/sessions")[0]["form"]
    assert sess["mode"] == "subscription" and sess["customer"] == "cus_test_1"
    assert sess["line_items[0][price]"] == "price_ent_placeholder"
    assert sess["client_reference_id"] == DEFAULT_TENANT
    assert sess["success_url"] == "https://app.example.test/settings/billing?checkout=success"
    assert sess["subscription_data[metadata][plan]"] == "enterprise"
    async with db_pool.acquire() as con:
        assert str(await con.fetchval("SELECT owner_tenant FROM billing_customers")) == DEFAULT_TENANT
    # a second checkout reuses the customer
    await client.post("/v1/billing/checkout", json={"plan": "team"})
    assert len(stripe_mock.by_path("/v1/customers")) == 1


async def test_checkout_validation_and_misconfiguration(client, stripe_mock, billing, monkeypatch):
    assert (await client.post("/v1/billing/checkout", json={"plan": "free"})).status_code == 422
    monkeypatch.setattr(billing, "stripe_price_team", None)
    r = await client.post("/v1/billing/checkout", json={"plan": "team"})
    assert r.status_code == 503 and r.json()["detail"]["error"] == "plan_not_configured"
    monkeypatch.setattr(billing, "stripe_price_team", "price_team_placeholder")
    monkeypatch.setattr(billing, "billing_public_url", "")
    r = await client.post("/v1/billing/checkout", json={"plan": "team"})
    assert r.status_code == 503 and r.json()["detail"]["error"] == "billing_public_url_not_set"
    assert stripe_mock.requests == []  # nothing reached Stripe


async def test_checkout_refused_when_already_subscribed(client, stripe_mock, billing):
    await post_event(client, checkout_completed())
    r = await client.post("/v1/billing/checkout", json={"plan": "enterprise"})
    assert r.status_code == 409 and r.json()["detail"]["use"] == "portal"
    assert stripe_mock.by_path("/v1/checkout/sessions") == []


async def test_stripe_failure_is_a_502_without_leaking_the_key(client, app, billing):
    app.state.stripe_transport = httpx.MockTransport(
        lambda req: httpx.Response(401, json={"error": {"message": "Invalid API Key provided"}}))
    r = await client.post("/v1/billing/checkout", json={"plan": "team"})
    assert r.status_code == 502 and "sk_test_not_a_real_key" not in r.text


async def test_portal_requires_a_customer_then_opens(client, stripe_mock, billing):
    r = await client.post("/v1/billing/portal")
    assert r.status_code == 409 and r.json()["detail"]["use"] == "checkout"
    await post_event(client, checkout_completed())
    r = await client.post("/v1/billing/portal")
    assert r.status_code == 200 and r.json()["url"] == "https://billing.stripe.test/p/1"
    form = stripe_mock.by_path("/v1/billing_portal/sessions")[0]["form"]
    assert form["customer"] == "cus_1" and form["return_url"] == "https://app.example.test/settings/billing"


async def test_billing_endpoints_need_the_right_role(client, billing, db_pool, enforce_auth):
    from .test_governance import _hdr, _seed_user_with_key

    _, viewer = await _seed_user_with_key(db_pool, "vera", "viewer", "public")
    assert (await client.get("/v1/billing")).status_code == 401
    assert (await client.get("/v1/billing", headers=_hdr(viewer))).status_code == 200
    assert (await client.post("/v1/billing/checkout", json={"plan": "team"}, headers=_hdr(viewer))).status_code == 403
    assert (await client.post("/v1/billing/portal", headers=_hdr(viewer))).status_code == 403
    # the webhook is public (signature-authenticated) even in enforce mode
    r = await client.post("/v1/billing/webhook", content=b"{}", headers={"Stripe-Signature": "t=1,v1=aa"})
    assert r.status_code == 400


@pytest.fixture
def enforce_auth():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


# --------------------------------------------------------------------------- #
# 402 feature gating
# --------------------------------------------------------------------------- #

async def test_gates_are_open_when_billing_is_off(client):
    """Self-hosted Community keeps everything that exists in the tree."""
    assert (await client.get("/v1/reports/compliance")).status_code == 200
    r = await client.post("/v1/auth/sso/admin/scim-tokens", json={"name": "okta"})
    assert r.status_code == 201


async def test_gate_402_body_for_compliance_packs(client, billing, db_pool):
    await age_tenant(db_pool, 60)  # trial over -> Community limits
    r = await client.get("/v1/reports/compliance")
    assert r.status_code == 402
    body = r.json()
    assert body["feature"] == "compliance_packs" and body["required_edition"] == "enterprise"
    assert body["upgrade_url"] == "https://app.example.test/settings/billing?feature=compliance_packs&plan=enterprise"
    assert body["error"] == "payment_required" and body["detail"]["feature"] == "compliance_packs"
    assert body["current_edition"] == "community" and body["reason"] == "trial_expired"
    # other reports stay free
    assert (await client.get("/v1/reports/executive")).status_code == 200


async def test_gate_trial_includes_team_features_but_not_enterprise(client, billing):
    # Fresh tenant = inside the trial: Team features yes...
    r = await client.post("/v1/auth/sso/admin/providers", json={
        "slug": "corp-saml", "kind": "saml", "preset": "generic", "display_name": "Corp",
        "saml": {"idp_entity_id": "https://idp.example", "idp_sso_url": "https://idp.example/sso",
                 "idp_x509_cert": "A" * 100}})
    assert r.status_code != 402  # allowed through the gate (may fail validation later)
    # ...Enterprise features no.
    assert (await client.post("/v1/auth/sso/admin/scim-tokens", json={"name": "okta"})).status_code == 402
    assert (await client.get("/v1/reports/compliance")).status_code == 402
    assert (await client.post("/v1/audit/anchor")).status_code == 402


async def test_gate_saml_blocked_after_trial_but_oidc_and_deletes_allowed(client, billing, db_pool):
    await age_tenant(db_pool, 60)
    r = await client.post("/v1/auth/sso/admin/providers", json={
        "slug": "corp-saml", "kind": "saml", "preset": "generic", "display_name": "Corp",
        "saml": {"idp_entity_id": "https://idp.example", "idp_sso_url": "https://idp.example/sso",
                 "idp_x509_cert": "A" * 100}})
    assert r.status_code == 402 and r.json()["feature"] == "sso_saml" and r.json()["required_edition"] == "team"
    # deleting / listing is never a paid action: a downgraded tenant can clean up
    assert (await client.get("/v1/auth/sso/admin/providers")).status_code == 200


async def test_gate_unlocks_with_subscription_and_relocks_on_cancel(client, billing, db_pool):
    await age_tenant(db_pool, 60)
    assert (await client.get("/v1/reports/compliance")).status_code == 402
    now = datetime.now(timezone.utc)
    await post_event(client, checkout_completed(plan="enterprise", created=now - timedelta(minutes=3)))
    await post_event(client, sub_event(price="price_ent_placeholder", created=now - timedelta(minutes=2)))
    assert (await client.get("/v1/reports/compliance")).status_code == 200
    await post_event(client, make_event("customer.subscription.deleted", {"id": "sub_1", "customer": "cus_1"},
                                        created=now - timedelta(minutes=1)))
    r = await client.get("/v1/reports/compliance")
    assert r.status_code == 402 and r.json()["reason"] == "canceled"


async def test_gate_scim_endpoints_answer_402_in_scim_shape(client, db_pool, billing, monkeypatch):
    # mint a SCIM token while gates are open, then enforce.
    monkeypatch.setattr(billing, "enforce_editions", "off")
    tok = (await client.post("/v1/auth/sso/admin/scim-tokens", json={"name": "okta"})).json()["token"]
    monkeypatch.setattr(billing, "enforce_editions", "on")
    await age_tenant(db_pool, 60)
    r = await client.get("/scim/v2/Users", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 402
    assert r.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


async def test_enforcement_modes(client, billing, db_pool, monkeypatch):
    await age_tenant(db_pool, 60)
    monkeypatch.setattr(billing, "enforce_editions", "off")
    assert (await client.get("/v1/reports/compliance")).status_code == 200
    monkeypatch.setattr(billing, "enforce_editions", "auto")
    assert (await client.get("/v1/reports/compliance")).status_code == 402


async def test_self_hosted_opt_in_enforcement_honours_license_file(client, monkeypatch, app):
    """Billing off, PADDOCK_ENFORCE_EDITIONS=on: only the signed license counts."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from app import licensing as lic

    monkeypatch.setattr(bcfg.settings, "enforce_editions", "on")
    monkeypatch.setattr(lic.license_settings, "license_cache_ttl_sec", 0.0)
    service.invalidate()
    assert (await client.get("/v1/reports/compliance")).status_code == 402
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(lic.license_settings, "license_public_keys", base64.b64encode(pub).decode())
    token = lic.sign_license({
        "v": 1, "license_id": "L-1", "edition": "enterprise",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }, key)
    monkeypatch.setattr(lic.license_settings, "license_key", token)
    lic.invalidate_cache(app)
    assert (await client.get("/v1/reports/compliance")).status_code == 200


def test_gate_factories_reject_unknown_names():
    with pytest.raises(ValueError):
        bgate.require_paid("not_a_feature")
    with pytest.raises(ValueError):
        bgate.require_quota("bananas")
    assert all(f in FEATURES for f in ("scim", "sso_saml", "compliance_packs", "audit_anchoring"))


# --------------------------------------------------------------------------- #
# Quota enforcement (read-only over quota, never deletes)
# --------------------------------------------------------------------------- #

_seed_counter = iter(range(10_000))


async def _seed_assets(db_pool, n: int, *, last_seen_days_ago: int = 0):
    tag = f"b{next(_seed_counter)}"
    async with db_pool.acquire() as con:
        await con.execute(
            """
            INSERT INTO assets (kind, value, canonical, source, last_seen)
            SELECT 'domain', $3 || '-' || g || '.example', $3 || '-' || g || '.example', 'test',
                   NOW() - make_interval(days => $2)
              FROM generate_series(1, $1) g
            """,
            n, last_seen_days_ago, tag,
        )


async def test_over_asset_quota_blocks_new_scans_but_keeps_reads(client, billing, db_pool, monkeypatch):
    monkeypatch.setattr(billing, "billing_community_assets", 3)
    await age_tenant(db_pool, 60)
    await client.post("/v1/scope", json={"kind": "domain", "value": "example.com", "added_by": "t"})
    await _seed_assets(db_pool, 3)
    ok = await client.post("/v1/scans", json={"kind": "passive_subdomains", "target": "example.com"})
    assert ok.status_code == 201  # at the limit, not over it
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO assets (kind, value, canonical, source) VALUES ('domain','x.example','x.example','t')")
    r = await client.post("/v1/scans", json={"kind": "passive_subdomains", "target": "example.com"})
    assert r.status_code == 402
    b = r.json()
    assert b["error"] == "quota_exceeded" and b["feature"] == "assets"
    assert (b["used"], b["limit"], b["required_edition"]) == (4, 3, "team")
    assert b["upgrade_url"].endswith("/settings/billing?feature=assets&plan=team")
    # nothing was deleted and every read still works
    assert (await client.get("/v1/assets")).status_code == 200
    j = (await client.get("/v1/billing")).json()
    assert j["read_only"] is True and j["usage"]["assets"] == {"used": 4, "limit": 3, "over": True}
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM assets") == 4


async def test_quota_ignores_stale_assets_and_unlimited_plans(client, billing, db_pool, monkeypatch):
    monkeypatch.setattr(billing, "billing_community_assets", 2)
    await age_tenant(db_pool, 60)
    await client.post("/v1/scope", json={"kind": "domain", "value": "example.com", "added_by": "t"})
    await _seed_assets(db_pool, 10, last_seen_days_ago=45)  # outside the 30-day window
    assert (await client.post("/v1/scans", json={"kind": "passive_subdomains", "target": "example.com"})).status_code == 201
    await _seed_assets(db_pool, 5)
    assert (await client.post("/v1/scans", json={"kind": "passive_subdomains", "target": "example.com"})).status_code != 201
    # Enterprise is unlimited
    await post_event(client, checkout_completed(plan="enterprise"))
    assert (await client.post("/v1/scans", json={"kind": "passive_subdomains", "target": "example.com"})).status_code == 201


async def test_quota_not_enforced_when_billing_off(client, db_pool):
    await client.post("/v1/scope", json={"kind": "domain", "value": "example.com", "added_by": "t"})
    await _seed_assets(db_pool, 50)
    assert (await client.post("/v1/scans", json={"kind": "passive_subdomains", "target": "example.com"})).status_code == 201


async def test_seat_quota_dependency(client, app, billing, db_pool, monkeypatch):
    from .test_governance import _seed_user_with_key

    @app.get("/__test/seat")
    async def _seat(_=Depends(bgate.require_quota("seats", 1))):
        return {"ok": True}

    monkeypatch.setattr(billing, "billing_community_seats", 3)
    await age_tenant(db_pool, 60)
    await _seed_user_with_key(db_pool, "u1", "viewer", "public")
    # the seeded `admin` + u1 = 2 seats; adding one more (the 3rd) fits
    assert (await client.get("/__test/seat")).status_code == 200
    await _seed_user_with_key(db_pool, "u2", "viewer", "public")
    r = await client.get("/__test/seat")
    assert r.status_code == 402 and r.json()["feature"] == "seats" and r.json()["limit"] == 3


async def test_scheduler_skips_schedules_when_over_asset_quota(app, billing, db_pool, monkeypatch):
    monkeypatch.setattr(billing, "billing_community_assets", 1)
    await age_tenant(db_pool, 60)
    assert await bgate.scans_allowed(app.state.pool) is True
    await _seed_assets(db_pool, 3)
    assert await bgate.scans_allowed(app.state.pool) is False
    monkeypatch.setattr(billing, "enforce_editions", "off")
    assert await bgate.scans_allowed(app.state.pool) is True


# --------------------------------------------------------------------------- #
# Usage metering to Stripe
# --------------------------------------------------------------------------- #

async def _subscribed(client, db_pool, monkeypatch, assets=1001, sites=2):
    from app.routers import licensing as usage_router

    async def fake_sites():
        return sites, sites, None

    monkeypatch.setattr(usage_router, "_otdiscovery_sites", fake_sites)
    await post_event(client, checkout_completed())
    await _seed_assets(db_pool, assets)


async def test_metering_sends_both_dimensions_with_deterministic_identifiers(client, app, stripe_mock, db_pool, monkeypatch):
    await _subscribed(client, db_pool, monkeypatch, assets=1001, sites=2)
    out = await metering.tick(app, now=NOW)
    assert out[DEFAULT_TENANT] == {"sites": "sent", "assets_k": "sent"}
    sent = {r["form"]["event_name"]: r for r in stripe_mock.by_path("/v1/billing/meter_events")}
    sites, assets = sent["paddock_sites"], sent["paddock_assets_k"]
    assert sites["form"]["payload[value]"] == "2" and assets["form"]["payload[value]"] == "2"  # ceil(1001/1000)
    assert sites["form"]["payload[stripe_customer_id]"] == "cus_1"
    assert sites["form"]["identifier"] == f"paddock-{DEFAULT_TENANT}-sites-2026-06-01"
    assert sites["headers"]["idempotency-key"] == sites["form"]["identifier"]
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT dimension, status, value FROM billing_usage_reports ORDER BY dimension")
    assert [(r["dimension"], r["status"], r["value"]) for r in rows] == [("assets_k", "sent", 2), ("sites", "sent", 2)]


async def test_metering_is_idempotent_across_ticks_and_usage_changes(client, app, stripe_mock, db_pool, monkeypatch):
    await _subscribed(client, db_pool, monkeypatch)
    await metering.tick(app, now=NOW)
    n = len(stripe_mock.by_path("/v1/billing/meter_events"))
    assert n == 2
    await _seed_assets(db_pool, 5000)  # usage grows after the day was reported
    again = await metering.tick(app, now=NOW + timedelta(hours=3))
    assert again[DEFAULT_TENANT] == {"sites": "already_sent", "assets_k": "already_sent"}
    assert len(stripe_mock.by_path("/v1/billing/meter_events")) == n
    # next UTC day: a fresh report with the new level
    nxt = await metering.tick(app, now=NOW + timedelta(days=1))
    assert nxt[DEFAULT_TENANT]["assets_k"] == "sent"
    last = stripe_mock.by_path("/v1/billing/meter_events")[-1]["form"]
    assert last["identifier"].endswith("2026-06-02")


async def test_metering_retries_failures_with_the_same_identifier(client, app, stripe_mock, db_pool, monkeypatch):
    await _subscribed(client, db_pool, monkeypatch)
    stripe_mock.meter_failures = 1
    first = await metering.tick(app, now=NOW)
    assert sorted(first[DEFAULT_TENANT].values()) == ["failed", "sent"]
    async with db_pool.acquire() as con:
        failed = await con.fetchrow("SELECT dimension, attempts, last_error FROM billing_usage_reports WHERE status='failed'")
    assert failed["attempts"] == 1 and "boom" in failed["last_error"]
    second = await metering.tick(app, now=NOW + timedelta(minutes=5))
    assert sorted(second[DEFAULT_TENANT].values()) == ["already_sent", "sent"]
    ids = [r["form"]["identifier"] for r in stripe_mock.by_path("/v1/billing/meter_events")]
    assert len(ids) == 3 and len(set(ids)) == 2  # the retry re-used the failed event's identifier


async def test_metering_skips_unsubscribed_unknown_sites_and_billing_off(client, app, stripe_mock, db_pool, monkeypatch):
    from app.routers import licensing as usage_router

    # no subscription -> nothing sent
    out = await metering.tick(app, now=NOW)
    assert out[DEFAULT_TENANT] == {"sites": "skipped", "assets_k": "skipped"}
    # unknown site count (otdiscovery down) is never invented
    async def down():
        return None, None, "down"

    monkeypatch.setattr(usage_router, "_otdiscovery_sites", down)
    await post_event(client, checkout_completed())
    out = await metering.tick(app, now=NOW)
    assert out[DEFAULT_TENANT]["sites"] == "skipped" and out[DEFAULT_TENANT]["assets_k"] == "sent"
    assert len(stripe_mock.by_path("/v1/billing/meter_events")) == 1
    # canceled customers are not metered
    await post_event(client, make_event("customer.subscription.deleted", {"id": "sub_1", "customer": "cus_1"}))
    assert (await metering.tick(app, now=NOW + timedelta(days=2)))[DEFAULT_TENANT]["assets_k"] == "skipped"
    # billing off -> no-op
    monkeypatch.setattr(bcfg.settings, "stripe_secret_key", None)
    assert await metering.tick(app, now=NOW + timedelta(days=3)) == {}


def test_meter_value_rounding():
    assert [metering.to_meter_value("assets_k", n) for n in (0, 1, 1000, 1001, 2500)] == [0, 1, 1, 2, 3]
    assert metering.to_meter_value("sites", 3) == 3 and metering.to_meter_value("sites", -1) == 0


# --------------------------------------------------------------------------- #
# Tenant isolation (RLS)
# --------------------------------------------------------------------------- #

async def test_subscription_state_is_per_tenant(app, app_pool, db_pool, client, billing, enforce_auth):
    from .test_tenancy import TENANT_B, _h, _seed_admin

    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo Corp", tenant_id=TENANT_B)
    key_a = await _seed_admin(db_pool, DEFAULT_TENANT, "alice-admin")
    key_b = await _seed_admin(db_pool, TENANT_B, "bob-admin")
    await age_tenant(db_pool, 60, DEFAULT_TENANT)
    await age_tenant(db_pool, 60, TENANT_B)
    # Stripe tells us tenant B subscribed (customer id mapped via the signed hint).
    await post_event(client, checkout_completed(customer="cus_b", sub="sub_b", plan="enterprise", tenant=TENANT_B))
    a = (await client.get("/v1/billing", headers=_h(key_a))).json()
    b = (await client.get("/v1/billing", headers=_h(key_b))).json()
    assert (a["edition"], a["status"]) == ("community", "trial_expired")
    assert (b["edition"], b["status"], b["can_manage"]) == ("enterprise", "active", True)
    assert (await client.get("/v1/reports/compliance", headers=_h(key_a))).status_code == 402
    assert (await client.get("/v1/reports/compliance", headers=_h(key_b))).status_code == 200
    assert await sub_row(db_pool, DEFAULT_TENANT) is None and (await sub_row(db_pool, TENANT_B))["plan"] == "enterprise"
    # A's portal cannot reach B's customer
    stripe_calls = []
    app.state.stripe_transport = httpx.MockTransport(lambda r: stripe_calls.append(r) or httpx.Response(200, json={"url": "https://x.test"}))
    assert (await client.post("/v1/billing/portal", headers=_h(key_a))).status_code == 409
    assert stripe_calls == []


# --------------------------------------------------------------------------- #
# Public /status
# --------------------------------------------------------------------------- #

async def test_status_is_public_minimal_and_cached(client, app, billing, enforce_auth):
    r = await client.get("/status")  # no credentials, enforce mode
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "operational"
    assert {c["name"] for c in j["components"]} >= {"api", "database", "queue"}
    assert all(set(c) == {"name", "status"} and c["status"] in {"up", "degraded"} for c in j["components"])
    assert set(j) == {"status", "components", "updated_at"}
    assert "max-age" in r.headers["cache-control"]
    # cached: breaking Redis is not visible until the cache expires
    class Broken:
        async def ping(self):
            raise RuntimeError("secret internal detail redis://10.0.0.5")

    good_redis = app.state.redis
    app.state.redis = Broken()
    assert (await client.get("/status")).json() == j
    bstatus.reset_cache()
    degraded = await client.get("/status")
    app.state.redis = good_redis
    d = degraded.json()
    assert d["status"] == "degraded"
    assert next(c for c in d["components"] if c["name"] == "queue")["status"] == "degraded"
    assert "10.0.0.5" not in degraded.text and "secret" not in degraded.text
    assert [c["status"] for c in d["components"] if c["name"] == "database"] == ["up"]


async def test_status_reports_database_down_without_detail(app, client, monkeypatch):
    bstatus.reset_cache()

    class DeadPool:
        def acquire(self):
            raise ConnectionError("password authentication failed for user asm_prod")

    real = app.state.pool
    app.state.pool = DeadPool()
    try:
        r = await client.get("/status")
    finally:
        app.state.pool = real
        bstatus.reset_cache()
    assert r.status_code == 200 and r.json()["status"] == "degraded"
    assert "asm_prod" not in r.text
