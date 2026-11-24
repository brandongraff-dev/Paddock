# Editions, licensing and pricing

> **Status:** the licensing mechanism (signed keys, `/v1/license`, `/v1/usage`,
> the `require_feature` gate) ships in this repository. **Prices below are
> placeholders** for planning and will change before any commercial launch.

## The promise

**Everything that exists in the open-source tree today is free, forever, in
the Community edition** — attack-path graph, discovery and probing, CVE/KEV
correlation, SCA/SAST, threat intel, ML risk, fleet agents, Sentry sensors,
RBAC/ABAC and the hash-chained audit log. Running without a license is
Community; nothing degrades, nothing phones home, and there are **no usage
caps** on a self-hosted Community install.

Paid editions add *new* capabilities that larger organisations need, plus
hosting and support. A feature is only ever gated if it is new **and** listed
in the catalogue below; existing features are never moved behind a license.

## Editions

| | **Community** | **Team** | **Enterprise** | **Edge** |
|---|---|---|---|---|
| For | self-hosters, open source | hosted, small security teams | large orgs, MSPs | air-gapped / OT / sovereign |
| Deployment | self-hosted | hosted (or self-hosted with key) | hosted or self-hosted | self-hosted, offline |
| Everything in the open-source tree | ✅ | ✅ | ✅ | ✅ |
| API, SDKs, `paddockctl`, Terraform | ✅ | ✅ | ✅ | ✅ |
| Built-in integrations (webhooks, Slack/Teams, Jira…) | ✅ | ✅ | ✅ | ✅ |
| SAML SSO (`sso_saml`) | — | ✅ | ✅ | ✅ |
| Branded digests & exec reports (`digest_branding`) | — | ✅ | ✅ | ✅ |
| Hosted Sentry site management (`hosted_sites`) | — | ✅ 1–3 sites | ✅ | ✅ |
| Provable containment: invariants, reach graph, continuous evaluation (`assurance`) | — | ✅ | ✅ | ✅ |
| SCIM provisioning (`scim`) | — | — | ✅ | ✅ |
| Multi-tenant / MSP workspaces (`multi_tenant`) | — | — | ✅ | ✅ |
| Anchored audit chain (`audit_anchoring`) + SIEM audit export (`audit_export`) | — | — | ✅ | ✅ |
| Compliance evidence packs (`compliance_packs`) | — | — | ✅ | ✅ |
| Contractual support SLA (`support_sla`) | community support | business hours | 24×7 option | 24×7 option |
| Air-gapped bundles (`air_gapped`), federation (`federation`), deep OT protocols (`ot_deep_protocols`) | — | — | — | ✅ |

The authoritative feature list is `FEATURES` in
[`orchestrator/app/licensing.py`](https://github.com/brandongraff-dev/paddock/blob/main/orchestrator/app/licensing.py);
`GET /v1/license` returns it with an `enabled` flag per feature.

## Pricing metric

Priced on two things that are easy to predict and grow with the customer:

1. **Sites** — a physical location with one or more Paddock Sentry sensors.
2. **Monitored assets, per 1,000** — domains, subdomains, IPs, cloud
   resources, repositories and IoT/OT devices seen in the last 30 days
   (ports, services, technologies and certificates are facets of an asset
   and are not counted). `GET /v1/usage` shows the exact number.

| | Community | Team | Enterprise | Edge |
|---|---|---|---|---|
| Per site / month | free (self-hosted) | **$TBD** *(placeholder)* | **$TBD** *(placeholder)* | quote |
| Per 1,000 monitored assets / month | free (self-hosted) | **$TBD** *(placeholder)* | **$TBD** *(placeholder)* | quote |
| Seats | unlimited | included (soft limit in key) | included | included |

Limits in a license key are **soft**: `/v1/usage` reports `over: true` and the
dashboard can nudge, but scans, ingestion and alerts are never blocked. A
true-up uses the daily usage snapshots.

On the **hosted edition** (billing on, see [Billing](BILLING.md)) the plan's
allowances are enforced instead, gently: once a tenant is *over* an allowance,
new scans and scheduled scans pause and paid features answer `402`, but data is
never deleted and everything that already exists stays readable. Usage is also
reported to Stripe from the same metered dimensions (sites, per-1,000 assets).

## How licensing works

- **Keys are offline-verifiable.** A key is `PDK1.<payload>.<signature>`: a
  JSON payload (`license_id`, `licensee`, `edition`, `seats`, `sites`,
  `assets`, `issued_at`, `expires_at`, extra `features`) signed with the
  vendor's **Ed25519** private key. The orchestrator verifies it with the
  vendor public key; no network call, so it works air-gapped.
- **Install a key:** `POST /v1/license {"key": "PDK1..."}` (admin), or
  `paddockctl license upload paddock.lic`, or set `PADDOCK_LICENSE_KEY` /
  `PADDOCK_LICENSE_FILE`. An uploaded key wins over env/file.
  `DELETE /v1/license` returns to Community.
- **Expiry:** features keep working for a grace period
  (`PADDOCK_LICENSE_GRACE_DAYS`, default 14) and then the instance quietly
  becomes Community again. Data is never touched.
- **Vendor side:** `scripts/issue_license.py keygen | pubkey | issue | verify`.
  The private key is never committed (the script refuses to write it inside
  the repository); tests generate throwaway keys.
- **Trust anchors:** official builds embed the vendor public key
  (`licensing.VENDOR_PUBLIC_KEYS`); `PADDOCK_LICENSE_PUBLIC_KEYS` adds more
  (e.g. for a reseller or a test lab).
- **Hosted billing:** the hosted edition derives entitlements from a Stripe
  subscription (14-day Team trial on signup, grace period on failed payments,
  then Community limits) instead of a key; both can coexist and the higher
  edition wins. See [Billing](BILLING.md). The signing-key ceremony (generating
  the vendor key offline and embedding only its public half in a release) is
  documented there too.
- **Honesty:** Paddock is AGPL-3.0. Anyone may modify their copy, including
  these checks. The license is how paying customers get the commercial
  features, support and a clean audit trail for procurement — not DRM.

## For contributors: gating a new feature

```python
from fastapi import Depends
from ..licensing import require_feature

@router.post("/v1/scim/v2/Users", dependencies=[Depends(require_feature("scim"))])
async def scim_create_user(...): ...
```

The dependency returns **402** with
`{"error": "feature_not_licensed", "feature": "scim", "required_edition": "enterprise", ...}`.
For code that should degrade rather than refuse, use
`await licensing.feature_enabled(request, "scim")`. To develop a gated feature
locally, create a throwaway keypair with `scripts/issue_license.py keygen`,
trust it via `PADDOCK_LICENSE_PUBLIC_KEYS`, and issue yourself a key.

For features that already ship in the tree and are listed as paid above (SAML
SSO, SCIM, compliance packs, anchoring), use the billing gate instead:
`Depends(billing_gate.require_paid("scim"))` (`orchestrator/app/billing/gate.py`).
It returns the same 402 plus an `upgrade_url`, but **only enforces when billing
is on or `PADDOCK_ENFORCE_EDITIONS=on`**, so a default self-hosted install keeps
every feature that exists in the open-source tree, as promised above.

New gateable features must be added to `FEATURES` (unknown names raise at
import time) and to the table above, and must not gate anything that already
exists in Community (existing paid-listed features are only gated when
enforcement is on, see above).

## Usage metering

- `GET /v1/usage` — monitored assets (and by kind), sites and sensors (from
  the `otdiscovery` service; `null` when it is unreachable), fleet agents,
  active users, scans this month, enabled integrations, and each license limit
  with `used` / `limit` / `over`.
- `POST /v1/usage/snapshot` (admin) — records today's snapshot (cron it
  daily); `GET /v1/usage` also records the day's first snapshot lazily.
- `GET /v1/usage/snapshots?days=90` — history for billing and true-ups
  (`usage_snapshots` table, `schema/024_licensing_usage.sql`).

Usage data stays in your database. Nothing is sent to the vendor; a hosted
edition reads the same endpoint.
