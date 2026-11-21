-- 028: Stripe billing for the hosted edition (orchestrator/app/billing/,
-- docs/BILLING.md). Billing is OFF unless STRIPE_SECRET_KEY is set; these
-- tables stay empty on a self-hosted install, which keeps using signed
-- license files (024).
--
-- Tenancy (099 re-adds / re-points tenant_id + RLS for every table here):
--   * billing_subscriptions / billing_usage_reports are PER TENANT: a tenant
--     only ever sees its own plan and usage reports.
--   * billing_customers / billing_events are GLOBAL: Stripe's webhook arrives
--     unauthenticated and carries only a customer id, so it must be mapped to
--     a tenant before any tenant context exists. They hold opaque ids only
--     (no card data, no secrets) and are writable only from the platform
--     (default) tenant, i.e. by the webhook / checkout code paths.
--
-- tenant_id is declared here (with the default tenant as a literal default)
-- so UNIQUE (tenant_id) can exist; 099 then swaps the default for the
-- session-tenant expression and adds the tenants FK + RLS policy.

-- Stripe customer -> tenant. One tenant may have several customers over time
-- (re-created in Stripe); a customer maps to exactly one tenant.
CREATE TABLE IF NOT EXISTS billing_customers (
  stripe_customer_id  TEXT PRIMARY KEY,
  owner_tenant        UUID NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_billing_customers_tenant ON billing_customers (owner_tenant);
COMMENT ON TABLE billing_customers IS '@paddock:global Stripe customer id -> tenant (webhook routing)';

-- Webhook replay protection + audit trail of what Stripe told us. The event
-- id is the primary key: a second delivery of the same id is a no-op.
CREATE TABLE IF NOT EXISTS billing_events (
  event_id       TEXT PRIMARY KEY,
  type           TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'processing'
                 CHECK (status IN ('processing','processed','failed','ignored')),
  owner_tenant   UUID,
  event_created  TIMESTAMPTZ,                 -- Stripe's own timestamp
  received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at   TIMESTAMPTZ,
  attempts       INT NOT NULL DEFAULT 1,
  error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_billing_events_received ON billing_events (received_at DESC);
COMMENT ON TABLE billing_events IS '@paddock:global Stripe webhook event ids (replay protection)';

-- Subscription state, one row per tenant. No row = never subscribed: the
-- tenant is on the signup trial (anchored on tenants.created_at) or, once the
-- trial is over, on Community limits.
CREATE TABLE IF NOT EXISTS billing_subscriptions (
  id                      BIGSERIAL PRIMARY KEY,
  tenant_id               UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'
                          UNIQUE,
  stripe_customer_id      TEXT,
  stripe_subscription_id  TEXT,
  plan                    TEXT CHECK (plan IN ('team','enterprise')),
  status                  TEXT NOT NULL DEFAULT 'incomplete'
                          CHECK (status IN ('incomplete','incomplete_expired','trialing','active',
                                            'past_due','canceled','unpaid','paused')),
  cancel_at_period_end    BOOLEAN NOT NULL DEFAULT FALSE,
  current_period_end      TIMESTAMPTZ,
  trial_end               TIMESTAMPTZ,
  payment_failed_at       TIMESTAMPTZ,        -- FIRST failure of the current dunning run
  grace_until             TIMESTAMPTZ,        -- features stay on until then
  last_event_at           TIMESTAMPTZ,        -- Stripe `created` of the newest applied event
  last_event_id           TEXT,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_billing_subs_customer ON billing_subscriptions (stripe_customer_id);

-- One usage report per (tenant, dimension, UTC day) sent to Stripe as a meter
-- event. The unique key + a deterministic Stripe `identifier` make the
-- scheduler's reporting idempotent across retries, restarts and replicas.
CREATE TABLE IF NOT EXISTS billing_usage_reports (
  id            BIGSERIAL PRIMARY KEY,
  tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  dimension     TEXT NOT NULL CHECK (dimension IN ('sites','assets_k')),
  day           DATE NOT NULL,
  value         BIGINT NOT NULL,
  identifier    TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
  attempts      INT NOT NULL DEFAULT 0,
  last_error    TEXT,
  reported_at   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, dimension, day)
);
