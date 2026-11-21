-- 036: isolation fixes found by the multi-tenancy stress sweep
-- (orchestrator/tests/test_isolation_sweep.py, test_tenancy_stress.py).
--
-- RLS hides another tenant's rows but does NOT stop a GLOBALLY unique key from
-- colliding with one. These tables kept a global PK / UNIQUE although every
-- tenant needs its own row, so a second tenant could never create its own
-- (and `ON CONFLICT (...) DO NOTHING` silently dropped the write):
--
--   onboarding        PK (id) with id = 1      -> wizard state of tenant != default never saved
--   identity_settings PK (id) with id = TRUE   -> SSO/SCIM policy of tenant != default never saved
--   usage_snapshots   PK (day)                 -> metering row of the 2nd tenant per day dropped
--   asset_snapshots   PK (snapshot_date, kind)
--   scim_groups       UNIQUE (display_name)    -> two tenants could not both have group "Admins"
--   report_digests    UNIQUE (workspace, kind, period_end) WHERE weekly
--                                              -> only ONE tenant got its weekly digest per slot
--
-- tenant_id is declared here with the default-tenant literal (as 028/032 do)
-- because this file runs BEFORE 099; 099 then swaps in the session-tenant
-- default, adds the FK + RLS policy. Everything is idempotent.

ALTER TABLE onboarding        ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE identity_settings ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE usage_snapshots   ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE asset_snapshots   ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE scim_groups       ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE report_digests    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

DO $$
BEGIN
  -- onboarding: PK (tenant_id, id)
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'onboarding'::regclass
                  AND contype = 'p' AND conname = 'onboarding_tenant_pk') THEN
    ALTER TABLE onboarding DROP CONSTRAINT IF EXISTS onboarding_pkey;
    ALTER TABLE onboarding ADD CONSTRAINT onboarding_tenant_pk PRIMARY KEY (tenant_id, id);
  END IF;
  -- identity_settings: PK (tenant_id, id)
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'identity_settings'::regclass
                  AND contype = 'p' AND conname = 'identity_settings_tenant_pk') THEN
    ALTER TABLE identity_settings DROP CONSTRAINT IF EXISTS identity_settings_pkey;
    ALTER TABLE identity_settings ADD CONSTRAINT identity_settings_tenant_pk PRIMARY KEY (tenant_id, id);
  END IF;
  -- usage_snapshots: PK (tenant_id, day)
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'usage_snapshots'::regclass
                  AND contype = 'p' AND conname = 'usage_snapshots_tenant_pk') THEN
    ALTER TABLE usage_snapshots DROP CONSTRAINT IF EXISTS usage_snapshots_pkey;
    ALTER TABLE usage_snapshots ADD CONSTRAINT usage_snapshots_tenant_pk PRIMARY KEY (tenant_id, day);
  END IF;
  -- asset_snapshots: PK (tenant_id, snapshot_date, kind)
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'asset_snapshots'::regclass
                  AND contype = 'p' AND conname = 'asset_snapshots_tenant_pk') THEN
    ALTER TABLE asset_snapshots DROP CONSTRAINT IF EXISTS asset_snapshots_pkey;
    ALTER TABLE asset_snapshots ADD CONSTRAINT asset_snapshots_tenant_pk PRIMARY KEY (tenant_id, snapshot_date, kind);
  END IF;
  -- scim_groups: UNIQUE (tenant_id, display_name)
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'scim_groups'::regclass
                  AND conname = 'scim_groups_tenant_display_name_key') THEN
    ALTER TABLE scim_groups DROP CONSTRAINT IF EXISTS scim_groups_display_name_key;
    ALTER TABLE scim_groups ADD CONSTRAINT scim_groups_tenant_display_name_key UNIQUE (tenant_id, display_name);
  END IF;
END $$;

-- report_digests: one weekly digest per (tenant, workspace, slot)
DROP INDEX IF EXISTS uq_report_digests_slot;
CREATE UNIQUE INDEX IF NOT EXISTS uq_report_digests_slot_tenant
  ON report_digests (tenant_id, workspace, kind, period_end) WHERE kind = 'weekly';

-- SCIM bearer tokens: the tenant is unknown until the token row is read, so
-- (like api_keys, sensors) a SELECT-only policy opens the table inside
-- `tenancy.auth_lookup()` and nowhere else. Without it the token lookup ran in
-- the default tenant and SCIM was unusable for every other tenant.
ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_token_auth_lookup ON scim_tokens;
CREATE POLICY scim_token_auth_lookup ON scim_tokens FOR SELECT
  USING (current_setting('app.auth_lookup', true) = 'on');

-- ---------------------------------------------------------------------------
-- Tenant-leading indexes for the hot list queries (hardening/tenant_load_test.py).
-- Every pre-tenancy index is single-column ("last_seen DESC", "status, last_seen
-- DESC", ...). With RLS the planner walks such an index across ALL tenants and
-- throws rows away on `tenant_id = current tenant`: 55 rows read per row kept
-- with 5 tenants, ~N per row with N tenants, unbounded for a selective filter
-- (exploitability, kev) on a small tenant. Leading with tenant_id makes the
-- ordered scan tenant-local. (Existing indexes are kept: unfiltered
-- single-tenant installs and the services that connect without a tenant still
-- use them.)
-- ---------------------------------------------------------------------------
-- (tenant_id is declared here, with the default-tenant literal, because this file
-- runs before 099; 099 swaps in the session-tenant default and adds FK + RLS.)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_findings_tenant_last_seen
  ON findings (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status_last_seen
  ON findings (tenant_id, status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_sev_status_last_seen
  ON findings (tenant_id, severity, status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_exploitability
  ON findings (tenant_id, exploitability, last_seen DESC) WHERE exploitability <> 'unverified';
-- kev filter: per-finding EXISTS over cve_matches by asset (was a seq scan per finding)
CREATE INDEX IF NOT EXISTS idx_cve_matches_asset ON cve_matches (asset_id);
-- duplicate-finding lookup on every ingested/bulk row (lifecycle.DUPLICATE_LOOKUP_SQL)
CREATE INDEX IF NOT EXISTS idx_findings_tenant_asset_fp
  ON findings (tenant_id, asset_key, fingerprint) WHERE duplicate_of IS NULL;
