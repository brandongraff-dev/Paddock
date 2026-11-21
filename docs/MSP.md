# MSP console (managed service providers)

One MSP sale is many small-business customers. The MSP console lets a provider
run a fleet of customer tenants from one place: see every customer's health,
step into a customer to work, provision and suspend customers, push standard
configuration to many at once, and bill from per-customer usage.

Code: `schema/033_msp.sql`, `orchestrator/app/msp/`, `orchestrator/app/routers/msp.py`,
dashboard `pages/MspConsole.tsx`. Tests: `orchestrator/tests/test_msp.py`,
`dashboard/tests/msp.test.tsx`.

**Tenant isolation is unchanged.** Postgres row-level security still scopes every
query to `tenant_id = paddock_current_tenant()` (see
[Tenancy](trust/TENANCY.md)). Nothing in the MSP feature disables or loosens RLS,
and no request ever runs with more than one tenant in context.

## Model

| Concept | Where it lives | Notes |
|---|---|---|
| MSP organisation | a normal tenant with a row in `msp_orgs` | Promoted by an **operator** (`python -m app.msp enable <slug>`); the app role cannot write `msp_orgs`. |
| Customer (child tenant) | a normal tenant + a row in `msp_children` owned by the **MSP's** tenant | There is no `parent_tenant_id` on the global `tenants` table, so a customer's users have nothing to read that points at the MSP or at siblings. |
| MSP user | an ordinary `app_users` row in the MSP tenant | Has a normal role there (viewer / analyst / auditor / admin). |
| Access grant | `msp_grants` (MSP tenant): user, customer (or *all customers*), role `viewer`/`analyst`/`admin`, clearance | The only thing that lets an MSP user into a customer. A per-customer grant overrides the "all customers" grant, so a wildcard admin can be carved down to viewer for one sensitive customer. Revoking = deleting the row. |

A customer can belong to exactly one MSP (`msp_children.child_tenant_id` is
unique). A tenant can only become a customer through
`msp_create_child_tenant()`, so an MSP admin can never "adopt" an existing tenant
by guessing its UUID. `msp_orgs` and `msp_children` cannot be written directly by
the app role (trigger-enforced); promotion and creation are an operator action
and a narrow `SECURITY DEFINER` function respectively.

### Roles, in two places

* **In the MSP:** the MSP user's own role gates the console. Anything that
  mutates (create customer, suspend, grants, templates, usage export) needs the
  `admin` capability; switching and the customer list need `read`.
* **In a customer:** the **grant** role applies, independent of the MSP role. An
  MSP *analyst* with an `admin` grant on customer A is an admin inside A.
  Inside a customer the clearance is `min(user clearance, grant clearance)`
  (default grant clearance: `internal`).

Management actions that touch a customer (suspend, reactivate, new invite,
apply template) additionally require an **admin grant on that customer**: being
an MSP admin does not by itself give access to every customer.

## Switching: token exchange, not a header

Two designs were considered for "act inside a customer":

1. **A request header** (e.g. `X-Paddock-Tenant: <customer>`) on the MSP user's
   normal credential. Simple, but it makes every MSP session (and every API key
   or script) a standing cross-tenant credential: one forgotten header, proxy
   rewrite, or SSRF-style request forgery away from acting in the wrong
   customer, and the audit trail cannot tell "browsing MSP console" from "acting
   in customer".
2. **A token exchange** (implemented). `POST /v1/msp/customers/{id}/switch`
   checks the grant and returns a **short-lived JWT scoped to that one
   customer**. The dashboard uses it *instead of* the MSP token while inside the
   customer and drops it to go back.

Why the exchange is safer:

* **One concrete tenant per credential.** The token's `tid` is the customer; the
  request then runs through the ordinary `tenant_context` / RLS path. There is
  no credential that is valid in two tenants, and no code path with "no tenant"
  context.
* **Explicit, auditable act.** Entering a customer is a distinct event
  (`msp.switch`) recorded in both audit trails.
* **Short-lived** (15 min by default, `MSP_SWITCH_TTL_SEC`, clamped 60-3600 s).
* **The token is only an introduction, never the authority.** On **every**
  request the server re-reads the MSP user (active, session not revoked), the
  MSP tenant (active), the `msp_children` membership, the live grant (role and
  clearance come from the database, not the token) and the customer's status.
  So **revoking a grant, suspending the customer, deactivating the MSP user, or
  suspending the MSP takes effect on the very next request** of any outstanding
  token. A validly signed token for a customer the user has no grant on is
  refused (tested).
* **Not an access token.** `typ=msp_switch`; `verify_jwt` rejects it, and an
  ordinary access token is not accepted as a switch token.
* **Narrowed surface.** A delegated session cannot call `/v1/msp/*` (no
  nesting/pivoting), cannot create or revoke API keys, ingest tokens, sensor
  enrollment tokens or trust links, and cannot configure SSO or SCIM: nothing
  it creates can outlive its grant. It also cannot change the customer's own
  billing (Stripe checkout/portal) or licence; reading the licence is allowed.
  To deploy a sensor or a CI integration for a customer, have the customer's
  admin create the token, or create it as a user in the customer's tenant.
* Only an interactive MSP **user session** can switch (not an API key, whose
  scopes the child token could not honour).

The principal inside a customer is `msp:<msp-slug>/<username>` with
`kind=msp`; `GET /v1/auth/me` and `GET /v1/msp/me` show it.

## Audit: both trails, every request

Every request made through a switch token, **reads included**, is written
**write-ahead (fail-closed)** and again as an outcome record, to **both** chains
(each tenant has its own hash chain):

| Trail | Row |
|---|---|
| Customer | the normal record; `actor = msp:<msp>/<user>`, `details.msp = {msp, msp_user, msp_user_id, grant_role, msp_tenant_id}` |
| MSP | `action = msp.act`, `actor = <user>`, `resource_id = <customer id>`, `details = {child, customer_action, ...}` |

Lifecycle events are explicit in both: `msp.switch`, `msp.customer_created`,
`msp.customer_suspended` / `_reactivated`, `msp.invite_created` / `_redeemed`,
`msp.grant_set` / `_revoked` (customer side when the grant is per-customer),
`msp.template_applied`. Refusals are in the MSP trail: `msp.switch_denied`
(grant missing / customer suspended) and `msp.switch_refused` (an outstanding
token stopped working). The MSP row is written first: if it cannot be appended,
the request is refused (503) before anything happens in the customer. A customer
can therefore always see exactly which MSP user looked at or changed what.

## Rollup (the dashboard's customer list)

`GET /v1/msp/customers?q=&sort=&order=&limit=&offset=` returns, for the
customers **the caller holds a grant on** (never the MSP's other customers, never
another MSP's):

| Field | Definition |
|---|---|
| `grade` | A-F from the exposure index, capped by criticals: index <=10 A, <=40 B, <=100 C, <=250 D, else F; any open critical caps at C, five or more at D |
| `exposure_index` | sum over open/triaged findings of critical 10, high 5, medium 2, low 1 (same formula as Overview and [Reports](REPORTS.md)) |
| `open_criticals`, `open_findings` | open or triaged findings |
| `sla_breaches` | open findings past their due time (ticket `sla_due`, else `first_seen` + SLA policy hours) |
| `verified_fixes` | fixed in the last 30 days, asset re-observed more than 60 s after the fix and the finding not (same rule as Reports) |
| `last_scan_at` | newest completed scan |
| licence usage | `seats_used/seats_limit`, `monitored_assets/assets_limit` from that customer's licence |

**How the cross-tenant read works.** It is an explicit loop over the caller's
granted customer ids. For each customer the numbers are computed inside its own
`tenancy.tenant_context(customer)` on its own connection, then written to a
cache table (`msp_child_health`) under the MSP's context. RLS is never
disabled, no query spans tenants, and each query also repeats `tenant_id = $1`
(belt and braces). One failing customer keeps its previous cache row and does
not hide the others.

The cache has a TTL (`MSP_HEALTH_TTL_SEC`, 300 s). Name/created ordering only
refreshes the visible page; ordering by a metric refreshes every stale
candidate (bounded by `MSP_ROLLUP_MAX_CHILDREN`, 500, per request).
`?refresh=true` forces a recompute. Search escapes LIKE wildcards; sort keys
are an allow-list. `GET /v1/msp/summary` gives fleet totals.

## Lifecycle

* **Create a customer:** `POST /v1/msp/customers {slug, name}` (MSP admin). Calls
  `msp_create_child_tenant()` (a `SECURITY DEFINER` function that acts only on
  the session's own MSP tenant, enforces the optional `max_children` limit), gives
  the creator an admin grant on the new customer, and issues the **onboarding
  invite**: a one-time token `<customer id>.<secret>` (only its SHA-256 is
  stored; 72 h by default). The MSP hands it to the customer admin, who redeems
  it at the **public** `POST /v1/msp/invites/redeem {token, username, password}`
  and becomes that customer's first `admin` (single use; refused when expired or
  the customer is suspended). `POST /v1/msp/customers/{id}/invites` issues
  another.
* **Suspend / reactivate:** `POST /v1/msp/customers/{id}/suspend|reactivate`
  (MSP admin **and** an admin grant on that customer), via
  `msp_set_child_status()`. A suspended tenant fails authentication for its own
  users (existing behaviour) and for every MSP token (immediately).
* **Grants:** `GET/POST /v1/msp/grants`, `DELETE /v1/msp/grants/{id}` (MSP admin).
  The user must belong to the MSP tenant and the customer must be one of its
  own; anything else is a 404.
* **Templates:** `POST /v1/msp/templates` (+ `PUT`, `DELETE`, `GET`), then
  `POST /v1/msp/templates/{id}/apply {customer_ids:[...]}` (up to 200 per call).
  A template holds:
    * `alert_rules`: same shape and validation as `/v1/alert-rules`;
    * `integrations`: same shape and validation as `/v1/integrations`, e.g. the
      MSP's own Slack or PSA webhook. Secrets are stored **encrypted**
      (`PADDOCK_SECRET_KEY`, AES-GCM), returned only as `********`, and written
      into each customer through the normal integration code path
      (SSRF/netsafety checks included);
    * `scope_suggestions`: stored in each customer **inactive**
      (`added_by = msp-template:<name>`). A template can never widen a customer's
      authorisation to scan; the customer activates a suggestion (and, where
      `REQUIRE_SCOPE_PROOF` is on, proves control) like any other entry.

  Applying is idempotent (existing names are skipped), runs per customer under
  that customer's tenant context after a **live admin-grant check**, records the
  outcome per customer (`msp_template_applications`) and is audited in both
  trails. One customer failing does not stop the batch; customers without an
  admin grant come back as `failed` and nothing is written there.

## Usage for MSP billing

`GET /v1/msp/usage?month=YYYY-MM` (MSP admin) returns one row per customer you
hold a grant on: monitored assets (same definition as `/v1/usage`: billable
asset kinds seen in the last 30 days), peak and average monitored assets over the
month's snapshots, total assets, active users, scans this month, enabled
integrations, fleet agents, edition and licence limits. `&format=csv` downloads
it (cells starting with `= + - @` are quoted to defuse spreadsheet formula
injection).
`POST /v1/msp/usage/snapshot` records today's per-customer figures into
`msp_usage_snapshots` (idempotent per day; cron it daily so peak/average are
meaningful). The current month is live; a past month uses its last snapshot (or
live, flagged `source`, when none exists).

> The existing `usage_snapshots` table has a global primary key on `day`, so it
> cannot hold per-tenant daily rows; `msp_usage_snapshots` is keyed
> `(child_tenant_id, day)` and owned by the MSP tenant. The per-customer
> counters reuse the definitions in `routers/licensing.py` (minus the otdiscovery
> sites probe, which is not tenant-aware).

## Dashboard

*Govern -> Customers* (`/msp`), shown only to MSP users. Health grade, exposure,
open criticals, SLA breaches, verified fixes, last scan and licence use per
customer; search; sort; paging. **Open** performs the switch and lands on the
customer's Overview. While inside a customer the topbar shows
`Acting in <customer> · <role>  [Back to MSP]` next to the (unchanged)
classification pill, the MSP nav entry is hidden, role-gated controls follow the
grant role, and the React Query cache is cleared on every enter/exit so nothing
of one tenant is ever shown in another. The customer token lives in
`sessionStorage` (per tab); on expiry, revoked grant or suspension the first 401
leaves the customer and keeps the MSP session. Admins can also create, suspend
and reactivate customers and export the usage CSV from the page. (Grants and
templates are API-only for now.)

## Operating it

```bash
# promote an existing tenant to an MSP (operator, schema owner)
OWNER_DATABASE_URL=postgresql://asm:...@postgres:5432/asm python -m app.msp enable acme-msp --name "Acme MSP" --max-customers 200
python -m app.msp list
# then, as an admin of that tenant: create customers, grant yourself/your team access
```

Settings (env, all optional): `MSP_SWITCH_TTL_SEC` (900), `MSP_HEALTH_TTL_SEC`
(300), `MSP_ROLLUP_MAX_CHILDREN` (500), `MSP_INVITE_TTL_HOURS` (72),
`MSP_MAX_APPLY_BATCH` (200).

## Threat model and limits

* **Compromised MSP admin.** They can grant themselves access to every customer
  of that MSP. That is inherent to the MSP trust relationship; the controls are
  the audit trail in *both* chains (a customer sees every MSP read and write),
  short-lived tokens, immediate revocation, and the inability to mint durable
  credentials (API keys, SSO, SCIM) inside a customer. Use SSO + MFA for MSP
  staff.
* **Cross-MSP.** Grants, customers and templates are RLS-scoped to the MSP's own
  tenant; another MSP's ids resolve to "not found / no grant" with the same
  answer as a random UUID, so tenant ids cannot be probed.
* **The app process can set any tenant** (see Tenancy limit 5): code execution in
  the orchestrator defeats RLS and therefore this feature too.
* Audit of delegated **reads** doubles the audit volume for MSP sessions.
* The shared limits of [Tenancy](trust/TENANCY.md) apply: compute services that
  are not tenant-aware (brain, graphsync, ...) must not be enabled for
  multi-tenant installs, and workers do not yet echo `tenant_id`, so scans for a
  non-default customer are not end-to-end until those land.
* Onboarding invites are returned in the API response, not e-mailed (there is no
  mail transport in the orchestrator); deliver them through your own channel.
* `schema/033` is applied before `099_tenancy.sql`; on a database where 099
  already ran it applies the same tenant default / FK / RLS to its own tables
  immediately, but re-apply 099 after upgrading as usual.
