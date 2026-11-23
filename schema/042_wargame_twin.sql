-- Wargame twin: the persisted, rule-aware model an assessment runs over.
-- Parsed firewall/cloud rule sets + the declared topology (segments and
-- edges) are stored here by the correlation service when config is
-- ingested; /compute-wargame loads them into an Environment so routes are
-- proved by config, not merely inferred from the asset graph.
-- tenant_id + RLS: 099_tenancy.sql retrofits every table (applied last) and
-- the block at the end of this file applies the same policy NOW, so a tenant
-- only ever sees and replaces its own twin. Natural keys are UNIQUE per
-- tenant (tenant_id leads), never globally: two tenants may both own an
-- "sg-db" rule set.
-- =====================================================================

-- A vendor-neutral rule set (a firewall, security-group set, NACL, ...).
CREATE TABLE IF NOT EXISTS wargame_rulesets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ruleset_key     TEXT NOT NULL,                 -- logical id, e.g. "sg-db"
  vendor          TEXT NOT NULL DEFAULT '',
  default_action  TEXT NOT NULL DEFAULT 'deny' CHECK (default_action IN ('allow','deny')),
  name            TEXT NOT NULL DEFAULT '',
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb   -- {"source": <config source>}
);
CREATE INDEX IF NOT EXISTS idx_wg_rulesets_key ON wargame_rulesets(ruleset_key);

-- One rule inside a rule set.
CREATE TABLE IF NOT EXISTS wargame_rules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ruleset_key     TEXT NOT NULL,
  rule_id         TEXT NOT NULL,
  ord             INTEGER NOT NULL DEFAULT 0,     -- evaluation order (lower first)
  action          TEXT NOT NULL CHECK (action IN ('allow','deny')),
  src_cidrs       JSONB NOT NULL DEFAULT '[]'::jsonb,
  dst_cidrs       JSONB NOT NULL DEFAULT '[]'::jsonb,
  -- ports: [{proto, low, high}]
  ports           JSONB NOT NULL DEFAULT '[]'::jsonb,
  conditional     BOOLEAN NOT NULL DEFAULT FALSE,
  vendor          TEXT NOT NULL DEFAULT '',
  raw_ref         TEXT NOT NULL DEFAULT '',
  cost_class      TEXT NOT NULL DEFAULT 'network_rule'
);
CREATE INDEX IF NOT EXISTS idx_wg_rules_rs ON wargame_rules(ruleset_key, ord);

-- A segment / host / identity node of the topology.
CREATE TABLE IF NOT EXISTS wargame_segments (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seg_key         TEXT NOT NULL,
  cidrs           JSONB NOT NULL DEFAULT '[]'::jsonb,
  role            TEXT NOT NULL DEFAULT 'intermediate'
                    CHECK (role IN ('entry','crown_jewel','intermediate')),
  reason          TEXT NOT NULL DEFAULT '',
  jewel_kind      TEXT NOT NULL DEFAULT '',
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wg_segments_key ON wargame_segments(seg_key);

-- A directed adjacency, optionally gated by a rule set.
CREATE TABLE IF NOT EXISTS wargame_edges (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  src             TEXT NOT NULL,
  dst             TEXT NOT NULL,
  rule_set_id     TEXT,                           -- NULL = ungoverned adjacency
  -- port: {proto, low, high} or NULL
  port            JSONB,
  base_labels     JSONB NOT NULL DEFAULT '[]'::jsonb,
  fix_candidate_id TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wg_edges_src ON wargame_edges(src);
CREATE INDEX IF NOT EXISTS idx_wg_edges_dst ON wargame_edges(dst);

-- Config snapshots behind the twin, for certificate provenance (the exact
-- bytes a "closed" proof was computed against).
CREATE TABLE IF NOT EXISTS wargame_config_snapshots (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor          TEXT NOT NULL DEFAULT '',
  source          TEXT NOT NULL DEFAULT '',       -- file path / connector id
  sha256          TEXT NOT NULL,
  ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wg_snap_sha ON wargame_config_snapshots(sha256);

-- ---------------------------------------------------------------------------
-- Tenancy + grants for the twin tables and the 041 assessment tables.
-- ---------------------------------------------------------------------------
-- (029 defines paddock_enable_tenant_rls; if it has not been applied yet, 099
-- retrofits the same policy to these tables when it runs.)
DO $$
DECLARE t text;
BEGIN
  IF to_regprocedure('paddock_enable_tenant_rls(regclass)') IS NOT NULL THEN
    FOREACH t IN ARRAY ARRAY[
    'wargame_rulesets', 'wargame_rules', 'wargame_segments', 'wargame_edges',
    'wargame_config_snapshots'
  ] LOOP
      PERFORM paddock_enable_tenant_rls(t::regclass);
    END LOOP;
  END IF;
END $$;

-- Per-tenant natural keys: a rule set / segment key exists once per tenant.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_name = 'wargame_rulesets' AND column_name = 'tenant_id') THEN
    RETURN;       -- tenant_id arrives with 099 (029 not applied yet)
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'wargame_rulesets_tenant_ruleset_key_key') THEN
    ALTER TABLE wargame_rulesets
      ADD CONSTRAINT wargame_rulesets_tenant_ruleset_key_key UNIQUE (tenant_id, ruleset_key);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'wargame_segments_tenant_seg_key_key') THEN
    ALTER TABLE wargame_segments
      ADD CONSTRAINT wargame_segments_tenant_seg_key_key UNIQUE (tenant_id, seg_key);
  END IF;
END $$;

-- The correlation service connects as paddock_svc_correlation (029), which has
-- no privilege on a table until it is on 029's explicit allow-list. 029 is
-- already applied (its checksum is recorded), so extend the allow-list here by
-- re-creating paddock_apply_service_grants() with the wargame tables added to
-- correlation's WRITE set, then re-deriving the grants. If 029's text ever
-- changes shape so the patch no longer applies, fall back to direct GRANTs
-- (a later paddock_apply_service_grants() run would then revoke them: keep
-- the allow-list in 029 in sync).
DO $$
DECLARE
  def  text;
  patched text;
  needle CONSTANT text :=
    'ARRAY[''attack_paths'',''attack_path_ledger'',''finding_chains'',''finding_techniques'']';
  extra CONSTANT text :=
    'ARRAY[''attack_paths'',''attack_path_ledger'',''finding_chains'',''finding_techniques'','
    '''wargame_assessments'',''wargame_routes'',''wargame_boundaries'','
    '''wargame_certificates'',''wargame_fix_sets'',''wargame_evidence'','
    '''wargame_rulesets'',''wargame_rules'',''wargame_segments'','
    '''wargame_edges'',''wargame_config_snapshots'']';
  t text;
BEGIN
  IF to_regprocedure('paddock_apply_service_grants()') IS NULL THEN
    RETURN;       -- 029 not applied yet: nothing to extend
  END IF;
  SELECT pg_get_functiondef('paddock_apply_service_grants()'::regprocedure) INTO def;
  IF position('wargame_assessments' IN def) > 0 THEN
    NULL;                                    -- already extended
  ELSIF position(needle IN def) > 0 THEN
    patched := replace(def, needle, extra);
    EXECUTE patched;
  ELSE
    RAISE NOTICE '042: paddock_apply_service_grants() has an unexpected shape; granting directly';
  END IF;
  PERFORM paddock_apply_service_grants();
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_svc_correlation') THEN
    FOREACH t IN ARRAY ARRAY[
      'wargame_assessments', 'wargame_routes', 'wargame_boundaries',
      'wargame_certificates', 'wargame_fix_sets', 'wargame_evidence',
      'wargame_rulesets', 'wargame_rules', 'wargame_segments',
      'wargame_edges', 'wargame_config_snapshots']
    LOOP
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO paddock_svc_correlation', t);
    END LOOP;
  END IF;
END $$;
