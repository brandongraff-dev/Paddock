-- Wargame: persisted assessment runs and their artifacts.
-- An assessment is one backward-search-from-crown-jewels run over the
-- modelled environment. Computed by the correlation service (which writes
-- these tables); read by the orchestrator API (routers/wargame.py).
-- tenant_id + RLS: 099_tenancy.sql retrofits every table (applied last), and
-- the block at the end of this file applies the same policy NOW via
-- paddock_enable_tenant_rls (029), so the tables are tenant-safe on their own
-- and the correlation service role (a least-privilege, NOBYPASSRLS login role)
-- gets explicit grants -- 029's allow-list cannot know these tables.
-- =====================================================================

-- One assessment run, with its headline scorecard numbers.
CREATE TABLE IF NOT EXISTS wargame_assessments (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  label                TEXT NOT NULL DEFAULT '',
  -- Crown-Jewel Closure, always stored alongside coverage (never one alone).
  crownjewel_total     INTEGER NOT NULL DEFAULT 0,
  crownjewel_open      INTEGER NOT NULL DEFAULT 0,
  crownjewel_closed    INTEGER NOT NULL DEFAULT 0,
  crownjewel_conditional INTEGER NOT NULL DEFAULT 0,
  closure_pct          NUMERIC(5,2) NOT NULL DEFAULT 0,
  coverage_pct         NUMERIC(5,2),            -- NULL = coverage not measured
  false_closed_rate    NUMERIC(6,4),            -- from the eval ranges, if run
  board_line           TEXT NOT NULL DEFAULT '',
  blind_spots          JSONB NOT NULL DEFAULT '[]'::jsonb,
  computed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata             JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wargame_assess_computed
  ON wargame_assessments(computed_at DESC);

-- Open routes to a crown jewel found in an assessment.
CREATE TABLE IF NOT EXISTS wargame_routes (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id   UUID NOT NULL REFERENCES wargame_assessments(id) ON DELETE CASCADE,
  entry           TEXT NOT NULL,
  jewel           TEXT NOT NULL,
  length          SMALLINT NOT NULL DEFAULT 0,
  weakest_label   TEXT NOT NULL DEFAULT 'unknown',
  -- ordered hops: [{src, dst, labels:[], port, rule_ref, fix_candidate_ids:[]}]
  hops            JSONB NOT NULL DEFAULT '[]'::jsonb,
  fingerprint     TEXT NOT NULL DEFAULT '',
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wargame_routes_assess ON wargame_routes(assessment_id);
CREATE INDEX IF NOT EXISTS idx_wargame_routes_jewel ON wargame_routes(jewel);

-- Per-boundary three-way agreement verdicts.
CREATE TABLE IF NOT EXISTS wargame_boundaries (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id   UUID NOT NULL REFERENCES wargame_assessments(id) ON DELETE CASCADE,
  boundary_src    TEXT NOT NULL,
  boundary_dst    TEXT NOT NULL,
  port            TEXT NOT NULL DEFAULT '',
  verdict         TEXT NOT NULL CHECK (verdict IN ('pass','fail_open','conditional','insufficient')),
  disagreements   JSONB NOT NULL DEFAULT '[]'::jsonb,
  note            TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_wargame_bound_assess ON wargame_boundaries(assessment_id);

-- Signed closed-boundary certificates.
CREATE TABLE IF NOT EXISTS wargame_certificates (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id   UUID NOT NULL REFERENCES wargame_assessments(id) ON DELETE CASCADE,
  boundary_src    TEXT NOT NULL,
  boundary_dst    TEXT NOT NULL,
  port            TEXT NOT NULL DEFAULT '',
  claim           TEXT NOT NULL DEFAULT '',
  assumptions     JSONB NOT NULL DEFAULT '[]'::jsonb,
  config_hashes   JSONB NOT NULL DEFAULT '[]'::jsonb,
  status          TEXT NOT NULL DEFAULT 'valid'
                    CHECK (status IN ('valid','expired','contradicted')),
  issued_at       TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ,
  fingerprint     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_wargame_cert_assess ON wargame_certificates(assessment_id);
CREATE INDEX IF NOT EXISTS idx_wargame_cert_fp ON wargame_certificates(fingerprint);

-- The minimum-cost fix set that cuts every open route.
CREATE TABLE IF NOT EXISTS wargame_fix_sets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id   UUID NOT NULL REFERENCES wargame_assessments(id) ON DELETE CASCADE,
  total_cost      NUMERIC(10,2) NOT NULL DEFAULT 0,
  optimality      TEXT NOT NULL DEFAULT 'exact' CHECK (optimality IN ('exact','greedy')),
  cuts_all        BOOLEAN NOT NULL DEFAULT FALSE,
  -- selected: [{id, kind, cost_class, description, cost}]
  selected        JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wargame_fix_assess ON wargame_fix_sets(assessment_id);

-- Hash-chained auditor evidence items (PCI / CIP).
CREATE TABLE IF NOT EXISTS wargame_evidence (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id   UUID NOT NULL REFERENCES wargame_assessments(id) ON DELETE CASCADE,
  framework       TEXT NOT NULL DEFAULT '',
  control_id      TEXT NOT NULL DEFAULT '',
  status          TEXT NOT NULL DEFAULT 'not_assessed'
                    CHECK (status IN ('met','exception','not_assessed')),
  statement       TEXT NOT NULL DEFAULT '',
  evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
  item_hash       TEXT NOT NULL DEFAULT '',
  ordinal         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_wargame_evid_assess ON wargame_evidence(assessment_id);
CREATE INDEX IF NOT EXISTS idx_wargame_evid_fw ON wargame_evidence(framework, control_id);

-- ---------------------------------------------------------------------------
-- Tenancy: tenant_id + FORCEd RLS on every wargame table (idempotent; 099 does
-- the same later), and per-tenant grants for the correlation service role.
-- ---------------------------------------------------------------------------
-- (029 defines paddock_enable_tenant_rls; if it has not been applied yet, 099
-- retrofits the same policy to these tables when it runs.)
DO $$
DECLARE t text;
BEGIN
  IF to_regprocedure('paddock_enable_tenant_rls(regclass)') IS NOT NULL THEN
    FOREACH t IN ARRAY ARRAY[
    'wargame_assessments', 'wargame_routes', 'wargame_boundaries',
    'wargame_certificates', 'wargame_fix_sets', 'wargame_evidence'
  ] LOOP
      PERFORM paddock_enable_tenant_rls(t::regclass);
    END LOOP;
  END IF;
END $$;
