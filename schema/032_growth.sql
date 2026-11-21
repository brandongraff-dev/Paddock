-- 032: growth features built on PASSIVE data only (DNS / CT logs / public data).
--
--   1. exposure_reports + exposure_leads  -- the free public exposure report
--      (POST /v1/public/exposure-report). Platform-owned: rows live in the
--      DEFAULT tenant, so no customer tenant can read them under RLS.
--   2. trust_links                        -- shareable, revocable, signed trust
--      pages. Tenant-scoped; the public lookup by token hash is the ONE
--      cross-tenant read and is limited to exactly one row by a policy keyed
--      on two transaction-local GUCs (see trust_public_lookup below).
--   3. suppliers + supplier_assessments   -- third-party monitoring.
--
-- Nothing here stores a target-probing result: every column is derived from
-- DNS answers or certificate-transparency rows.

-- ---------------------------------------------------------------------------
-- 1. Free exposure report
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exposure_reports (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain        TEXT NOT NULL,                      -- registrable domain, punycode
  status        TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'done', 'failed')),
  grade         TEXT CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
  score         INTEGER CHECK (score BETWEEN 0 AND 100),
  summary       JSONB NOT NULL DEFAULT '{}'::jsonb, -- public-safe aggregates
  findings      JSONB NOT NULL DEFAULT '[]'::jsonb, -- full detail (never served publicly)
  error         TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  ip_hash       TEXT,                               -- salted hash, never the address
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at    TIMESTAMPTZ,
  finished_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_exposure_reports_domain ON exposure_reports (domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_reports_queue  ON exposure_reports (status, created_at)
  WHERE status IN ('queued', 'running');

CREATE TABLE IF NOT EXISTS exposure_leads (
  id            BIGSERIAL PRIMARY KEY,
  report_id     UUID REFERENCES exposure_reports(id) ON DELETE SET NULL,
  domain        TEXT NOT NULL,
  email         TEXT NOT NULL,
  consent       BOOLEAN NOT NULL,
  consent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  consent_text  TEXT NOT NULL DEFAULT 'v1',
  ip_hash       TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (email, domain)
);

-- ---------------------------------------------------------------------------
-- 2. Shareable trust / posture pages
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS trust_links (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  label          TEXT NOT NULL,
  token_hash     TEXT NOT NULL UNIQUE,              -- sha256 of the token; the token itself is never stored
  token_hint     TEXT NOT NULL,                     -- last 4 chars of the hash, to tell links apart in the UI
  sections       TEXT[] NOT NULL,
  period_days    INTEGER NOT NULL DEFAULT 30 CHECK (period_days BETWEEN 1 AND 365),
  expires_at     TIMESTAMPTZ NOT NULL,
  revoked_at     TIMESTAMPTZ,
  password_hash  TEXT,                              -- bcrypt, optional
  view_count     INTEGER NOT NULL DEFAULT 0,
  last_viewed_at TIMESTAMPTZ,
  created_by     TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_trust_links_created ON trust_links (created_at DESC);

-- Public token lookup. The viewer has no tenant, so the tenant_isolation
-- policy (added by 099) hides every row. This extra PERMISSIVE policy lets a
-- transaction that has set BOTH `app.trust_lookup = on` and `app.trust_hash`
-- read exactly the row whose hash matches -- nothing can enumerate the table.
-- 099 only drops/recreates `tenant_isolation`, so this policy survives re-runs.
ALTER TABLE trust_links ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS trust_public_lookup ON trust_links;
CREATE POLICY trust_public_lookup ON trust_links FOR SELECT
  USING (current_setting('app.trust_lookup', true) = 'on'
         AND token_hash = current_setting('app.trust_hash', true));

-- ---------------------------------------------------------------------------
-- 3. Supplier (third-party) monitoring
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suppliers (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- declared here (099 re-defaults it) so the per-tenant UNIQUE below exists
  tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  domain              TEXT NOT NULL,
  name                TEXT NOT NULL,
  criticality         TEXT NOT NULL DEFAULT 'medium'
                      CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
  notes               TEXT,
  enabled             BOOLEAN NOT NULL DEFAULT TRUE,
  interval_hours      INTEGER NOT NULL DEFAULT 168 CHECK (interval_hours BETWEEN 1 AND 8760),
  next_run_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_assessed_at    TIMESTAMPTZ,
  last_grade          TEXT,
  last_score          INTEGER,
  last_assessment_id  UUID,
  last_error          TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_by          TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_suppliers_due ON suppliers (next_run_at) WHERE enabled;

CREATE TABLE IF NOT EXISTS supplier_assessments (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  supplier_id  UUID NOT NULL REFERENCES suppliers(id) ON DELETE CASCADE,
  domain       TEXT NOT NULL,
  grade        TEXT NOT NULL,
  score        INTEGER NOT NULL,
  summary      JSONB NOT NULL DEFAULT '{}'::jsonb,
  findings     JSONB NOT NULL DEFAULT '[]'::jsonb,
  changes      JSONB NOT NULL DEFAULT '{}'::jsonb,  -- diff against the previous assessment
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_supplier_assessments_sup ON supplier_assessments (supplier_id, created_at DESC);
