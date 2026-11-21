# Billing (hosted edition)

> **Status:** implemented and covered by tests, **not yet run against live Stripe**.
> Price ids, plan limits and trial/grace lengths are placeholders you configure.
> Nothing here changes a self-hosted install: billing is **off** unless
> `STRIPE_SECRET_KEY` is set, and self-hosted Paddock keeps using signed license
> files ([Editions & licensing](EDITIONS.md)).

The hosted edition sells **Team** and **Enterprise** subscriptions through Stripe
Checkout, lets customers manage them in the Stripe Customer Portal, and meters the
two pricing dimensions from [EDITIONS.md](EDITIONS.md) (sites, monitored assets per
1,000). Paddock never sees card data: Checkout and the Portal are Stripe-hosted.

Code: `orchestrator/app/billing/` · schema: `schema/028_billing.sql` · UI:
**Settings → Billing**.

## Turning it on

| Variable | Purpose |
|---|---|
| `STRIPE_SECRET_KEY` | **Enables billing.** `sk_live_…` / `sk_test_…`. Read from the environment only. |
| `STRIPE_WEBHOOK_SECRET` | `whsec_…` for the webhook endpoint. Comma-separate two to rotate. |
| `STRIPE_PRICE_TEAM`, `STRIPE_PRICE_ENTERPRISE` | Recurring price ids (`price_…`) of each plan. Unset = plan not purchasable. |
| `STRIPE_METER_SITES_EVENT`, `STRIPE_METER_ASSETS_EVENT` | Billing Meter `event_name`s (defaults `paddock_sites`, `paddock_assets_k`). |
| `BILLING_PUBLIC_URL` | Dashboard base URL (`https://app.example.com`): Checkout/Portal return URLs and `upgrade_url`. Required for Checkout. |
| `BILLING_TRIAL_DAYS` | Team trial on signup, default `14` (`0` = no trial). |
| `BILLING_GRACE_DAYS` | Dunning grace period, default `7`. |
| `BILLING_WEBHOOK_TOLERANCE_SEC` | Signature timestamp window, default `300`. |
| `PADDOCK_ENFORCE_EDITIONS` | `auto` (default: enforce gates iff billing is on), `on`, `off`. See [Enforcement](#enforcement-who-gets-a-402). |
| `BILLING_TEAM_SEATS` / `_SITES` / `_ASSETS` | Team allowances (defaults 10 / 3 / 5000; `-1` = unlimited). Enterprise is unlimited and metered. |
| `BILLING_COMMUNITY_SEATS` / `_SITES` / `_ASSETS` | Allowances once downgraded (defaults 3 / 0 / 250). |
| `STRIPE_API_BASE` | Only for tests / Stripe-compatible mocks. |

Stripe-side setup (test mode first):

1. Create two recurring **Prices** (Team, Enterprise) and put their ids in the variables above.
2. Create two **Billing Meters**: event names matching `STRIPE_METER_*_EVENT`,
   aggregation **`last`** (or `max`: every event carries the day's *level*, not a delta),
   customer mapping `stripe_customer_id`. Attach a metered price for each to the
   subscription as you see fit.
3. Add a **webhook endpoint** `https://<your-api>/v1/billing/webhook` subscribed to:
   `checkout.session.completed`, `customer.subscription.created`,
   `customer.subscription.updated`, `customer.subscription.deleted`,
   `invoice.paid`, `invoice.payment_failed`. Copy its signing secret into `STRIPE_WEBHOOK_SECRET`.
4. Enable the **Customer Portal** (payment methods, invoices, plan change, cancel).

## API

| Route | Who | |
|---|---|---|
| `GET /v1/billing` | read | Plan, status, entitlements, usage vs quota, trial/grace dates, plan catalogue. Works with billing off (`enabled: false`). |
| `POST /v1/billing/checkout` `{"plan":"team"\|"enterprise"}` | admin | Creates (or reuses) the tenant's Stripe customer and returns a Checkout Session `url`. `409 already_subscribed` if a live subscription exists (change plans in the Portal: a second Checkout would double-bill). |
| `POST /v1/billing/portal` | admin | Customer Portal `url`; `409 no_customer` before the first Checkout. |
| `POST /v1/billing/webhook` | public, signature | Stripe → Paddock. |
| `GET /status` | public | See [Public status](#public-status). |

Billing off: the POSTs answer `503 billing_not_configured`.

## Webhook handling

Stripe's `Stripe-Signature` header is the only authentication of the webhook route.

* **Signature:** HMAC-SHA256 over `"<t>.<raw body>"`, compared in constant time against
  every `v1` value (so key rotation works). Timestamp must be within the tolerance
  window in *both* directions. Bad/missing/stale → `400 invalid_signature`, nothing is
  read or written. The reason is logged, never returned.
* **Replay protection:** the Stripe event id is the primary key of `billing_events`.
  A processed (or in-flight) id is answered `200 {"duplicate": true}` and not run again.
  A *failed* attempt (we answered 5xx) and a claim older than 5 minutes are retried.
* **Ordering:** Stripe may deliver out of order. Each subscription row keeps the
  `created` time of the newest event applied; older events are dropped, so a late
  `updated(active)` cannot undo a newer `payment_failed`.
* **Routing to a tenant:** the webhook is unauthenticated, so a customer id must be
  mapped to a tenant first. Checkout stores `customer → tenant` in `billing_customers`
  (a **global** table, writable only from the platform tenant). A customer is never
  re-pointed to another tenant; metadata in an event is only used to *establish* a
  mapping that does not exist yet. Unknown customers are `200 ignored`.
* Body is capped at 1 MB.

### Event → state

| Event | Effect |
|---|---|
| `checkout.session.completed` | Link customer ↔ tenant; record subscription id and plan; `active` if paid. Replays for the same subscription never reset state. |
| `customer.subscription.created` / `updated` | Status, plan (from the price id, then metadata), period end, trial end, cancel-at-period-end. `past_due` starts the grace clock if it is not running. |
| `customer.subscription.deleted` | `canceled`. |
| `invoice.paid` | Clears dunning; `past_due`/`incomplete` → `active`. |
| `invoice.payment_failed` | `past_due`, `payment_failed_at` = **first** failure, `grace_until` = that + grace days. Retries never extend the grace. |

Events for an old subscription id, or invoices for a subscription we do not hold, are ignored.

## Trials, dunning, downgrade

| State | Access |
|---|---|
| No subscription, within `BILLING_TRIAL_DAYS` of `tenants.created_at` | **Team** (`trialing`). The trial is computed, not stored, and cannot restart. |
| No subscription, trial over | Community limits (`trial_expired`) |
| `active` / `trialing` (Stripe) | The plan's edition and allowances |
| `past_due` inside the grace period | Plan stays on; dashboard shows a payment banner (`dunning`) |
| `past_due` after grace, `unpaid`, `canceled`, `incomplete*`, `paused` | Community limits |

A 24-hour allowance covers webhook lag before a trial or a "cancel at period end"
subscription is cut off locally, so a missed `deleted` webhook cannot keep paid access forever.

**Downgrade never deletes data.** Community limits mean: paid features answer `402`
(reads of everything else keep working) and *growth* past the Community allowance is
refused (below). `read_only` in `GET /v1/billing` is true while downgraded **and** over a limit.

## Entitlements and quotas

`entitlements.compute_entitlements` is a pure function from the subscription row,
the tenant's creation time and `now` to `{edition, features, seats, sites, assets, …}`.
An installed license file is merged in (the higher edition wins), so a hosted tenant
with an operator-installed key is honoured.

Quota enforcement (`gate.require_quota`) refuses *growth* with
`402 {"error":"quota_exceeded","feature":"assets","used":…,"limit":…}` once usage is
strictly over the limit:

* **Assets:** `POST /v1/scans` is refused (including the follow-up scans workers
  spawn) and the scheduler skips that tenant's due schedules. Scans already running,
  ingestion of their results, findings, alerts and every read keep working.
* **Seats:** the `require_quota("seats", 1)` dependency exists and is tested; it is not
  attached to a route yet because the OSS tree has no user-creation API (users come from
  the CLI, SSO JIT and SCIM; SCIM is Enterprise = unlimited seats).
* **Sites** are counted by the `otdiscovery` service; an unreachable service means
  "unknown", and unknown usage never blocks anyone.

## Feature gating (HTTP 402)

One mechanism: `billing.gate.require_paid("<feature>")` (a FastAPI dependency) or
`await gate.ensure_feature(request, "<feature>")` for checks that depend on request data.
Feature names come from `licensing.FEATURES`; an unknown name fails at import time.

```json
HTTP/1.1 402 Payment Required
{
  "error": "payment_required",
  "feature": "scim",
  "required_edition": "enterprise",
  "upgrade_url": "https://app.example.com/settings/billing?feature=scim&plan=enterprise",
  "description": "SCIM 2.0 user/group provisioning",
  "current_edition": "community",
  "reason": "trial_expired",
  "detail": { "…same object…": "for clients that read FastAPI's `detail`" }
}
```

Applied today (only where the feature already has an API surface):

| Feature | Route(s) |
|---|---|
| `sso_saml` | creating a SAML provider; changing a SAML provider's IdP settings. (Listing, disabling, deleting and **SAML sign-in itself** are never gated: a downgraded tenant must not be locked out.) |
| `scim` | the whole `/scim/v2/*` router (402 in SCIM error shape) and creating SCIM tokens |
| `compliance_packs` | `GET /v1/reports/compliance`, `GET /v1/reports/compliance/{framework}` |
| `audit_anchoring` | `POST /v1/audit/anchor` |

Not gated because there is no API surface to gate yet: `multi_tenant` (tenants are
created with `python -m app.tenancy`), `digest_branding`, `hosted_sites`, `audit_export`.
Add `Depends(billing_gate.require_paid("…"))` when they get one.

### Enforcement: who gets a 402?

Gates only bite when **enforcement is active**:

| `PADDOCK_ENFORCE_EDITIONS` | Behaviour |
|---|---|
| `auto` (default) | Enforced **iff billing is on** (`STRIPE_SECRET_KEY`). |
| `on` | Always enforced. On a self-hosted install, entitlements then come from the signed license file only. |
| `off` | Never enforced (even with billing on; for staging). |

This is how the "everything in the open-source tree is free, forever" promise in
[EDITIONS.md](EDITIONS.md) survives gating SSO/SCIM/compliance packs, which already
exist in the tree: a default self-hosted install enforces nothing and every existing
test and workflow is unchanged. Self-hosters who want procurement-grade license
enforcement can opt in with `on`.

## Usage metering

The scheduler (every tick, per tenant) reports to Stripe's `POST /v1/billing/meter_events`
for tenants with a live subscription:

* `sites`: distinct Sentry sites; `assets_k`: monitored assets in thousands, **rounded up**.
* **At most one report per tenant × dimension × UTC day** (`billing_usage_reports`).
* **Idempotent:** local unique key, plus a deterministic Stripe `identifier`
  (`paddock-<tenant>-<dimension>-<YYYY-MM-DD>`, also sent as `Idempotency-Key`).
  A failed send is retried on the next tick with the same identifier.
* An unknown value (sensor service down) is skipped, never guessed.

## Tenancy and security notes

* `billing_subscriptions` and `billing_usage_reports` are per-tenant with RLS like every
  other table. `billing_customers` and `billing_events` are global, hold opaque ids only,
  and are writable only from the platform (default) tenant.
* The secret key is only read from the environment, only sent to `STRIPE_API_BASE`, never
  logged and never echoed into errors (`502 stripe_error` carries Stripe's message only).
* Checkout/Portal return URLs come from `BILLING_PUBLIC_URL`, never from request headers.
* Checkout and Portal are admin-only and audited like any other mutation.

## Public status

`GET /status` is unauthenticated and cached. See [Running a status page](STATUS_PAGE.md).

## Vendor key ceremony (license signing key)

Self-hosted licenses (and hosted tenants with an installed key) are verified against
the vendor **public** key compiled into official builds (`licensing.VENDOR_PUBLIC_KEYS`).
The open-source tree ships it empty on purpose, and **no real key is generated or
committed by this repository**. Do this once, offline:

1. **Prepare.** An air-gapped (or at least network-disabled) machine, two custodians, an
   encrypted removable drive *outside any git checkout*, and a passphrase of 16+ characters
   (use a diceware phrase; each custodian holds half, or use a password manager vault).
2. **Generate.**
   ```bash
   PADDOCK_VENDOR_KEY_PASSPHRASE='…' \
     python scripts/vendor_key_ceremony.py generate --out-dir /mnt/usb/paddock-vendor-2027
   ```
   It refuses a path inside the repository, refuses to overwrite, refuses an empty or short
   passphrase, writes the PKCS#8 private key **encrypted** with mode `0600`, proves the pair by
   signing and verifying a probe license, and writes `paddock-vendor.pub` plus a
   `ceremony-record.txt` (public key + fingerprint, no secrets).
3. **Back up** the `.pem` to a second offline medium in a different location; store the
   passphrase separately. Losing it means re-issuing every license under a new key.
4. **Hand over only the public key.** Copy `paddock-vendor.pub` to the release pipeline
   (it is not secret). Read the fingerprint aloud / compare on two channels.
5. **Embed at release time**, in the pipeline's throwaway checkout, never committed:
   ```bash
   python scripts/vendor_key_ceremony.py embed --public-key-file paddock-vendor.pub \
       --i-am-in-a-release-checkout
   python scripts/vendor_key_ceremony.py check --public-key-file paddock-vendor.pub --exact
   ```
   Pass several `--public-key-file` flags to trust old and new keys during **rotation**;
   `--replace` drops the previous ones once every license signed with them has expired.
   (Alternatively set `PADDOCK_LICENSE_PUBLIC_KEYS` on a deployment without rebuilding.)
6. **Issue licenses** from a machine that can reach the private key:
   `python scripts/issue_license.py issue --private-key … --license-id … --edition team …`
   (see [EDITIONS.md](EDITIONS.md)). Keep the private key in an HSM/KMS or offline vault, not on the release server.
7. **Verify the artifact** (`check`, then verify a freshly issued license against it with
   `issue_license.py verify`) before publishing.

Compromise: generate a new pair, ship a build trusting both, re-issue licenses, then remove
the old key with `embed --replace`. CI has a guard test that fails if a private key or an
embedded vendor key appears in the tracked tree.

## Known gaps

* Not exercised against live Stripe; request shapes follow Stripe's documented form encoding
  and API version `2025-04-30.basil` and are verified against `httpx.MockTransport` only.
* Plan changes (upgrade/downgrade between Team and Enterprise) happen in the Customer Portal;
  Paddock follows the resulting `customer.subscription.updated`.
* One subscription per tenant is modelled. Tax, invoices and dunning emails are Stripe's.
* Metering is a daily level, not intra-day; the first tick of the UTC day wins.
