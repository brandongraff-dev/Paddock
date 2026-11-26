-- 044: Provable Containment P2.1, section A: vulnerability advisories and the persisted package list.
-- See docs/ASSURANCE_P2_1.md 1.3 (and D3, D4, D7, D8, D14).
--
-- GLOBAL tables (public vendor and CISA data, no tenant_id). Each carries the `@paddock:global` marker, so 099 gives it
-- RLS with `global_read` (everyone reads) and `global_platform_write` (only the platform tenant writes): a tenant
-- cannot write an advisory row (attack 8.4 #9). The intel service is the only writer (as the platform tenant); the
-- orchestrator only SELECTs them. The four are listed in GLOBAL_ALLOWLIST of orchestrator/tests/test_isolation_sweep.py.
--
--   kev_entries         the CISA KEV catalogue, canonical for assurance and independent of the NVD-gated `cves` (D4)
--   advisory_scopes     the closed list of distro scopes we claim to judge (upserted by intel from code)
--   advisory_snapshots  one row per accepted or rejected feed fetch; one `current` per (source, scope): the staleness
--                       clock and the sha256 a later attestation can name (D14)
--   advisory_fixes      only advisory rows whose CVE is in kev_entries at filter time, guarded by kev_ids_sha (D7)
--
-- TENANT tables (the marker must NEVER appear on these: 099 would drop their tenant_id and RLS). tenant_id is declared so
-- the UNIQUEs name it, every NOT NULL column has a default (the generic isolation-sweep row generator needs it), no
-- global UNIQUE, and application SQL never names tenant_id (the 041 sweep rules):
--
--   agent_manifests       content addressed PER TENANT: clones share one row, two tenants never share one (D8)
--   agent_manifest_refs   the agent's CURRENT list and the envelope that carried it
--
-- Runs BEFORE 099_tenancy.sql, which adds the tenant_id default / FK / RLS / policy (and is re-applied by the runner).
-- The contract text says "six global tables"; it defines four global and two tenant tables, and that is what is built.
-- Deviations from the contract SQL, all tightening or additive: the two sha columns accept exactly 64 lowercase hex (or
-- the empty default), the gz size has a lower bound, and four plain indexes serve the retention sweeps of retention.py.

CREATE TABLE IF NOT EXISTS kev_entries (               -- canonical for assurance; independent of the NVD-gated `cves`
  cve_id TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,10}$'),
  vendor TEXT NOT NULL DEFAULT '' CHECK (length(vendor) <= 200),
  product TEXT NOT NULL DEFAULT '' CHECK (length(product) <= 200),
  name TEXT NOT NULL DEFAULT '' CHECK (length(name) <= 400),
  date_added DATE NOT NULL,                            -- no parseable dateAdded => rejected, never defaulted to NOW()
  due_date DATE,
  ransomware BOOLEAN NOT NULL DEFAULT FALSE,
  required_action TEXT NOT NULL DEFAULT '' CHECK (length(required_action) <= 1000),
  sources TEXT[] NOT NULL DEFAULT '{}',                -- 'cisa','cisagov-kev-data'
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  absent_fetches INTEGER NOT NULL DEFAULT 0,
  removed_at TIMESTAMPTZ);
COMMENT ON TABLE kev_entries IS '@paddock:global CISA KEV catalogue (public); written by the intel service as the platform tenant only';

CREATE TABLE IF NOT EXISTS advisory_scopes (           -- the closed list of scopes we claim to judge (upserted by intel from code)
  scope TEXT PRIMARY KEY CHECK (scope ~ '^[a-z0-9_.:-]{3,40}$'),
  family TEXT NOT NULL CHECK (family IN ('deb','rpm')),
  vendor TEXT NOT NULL,
  release TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('supported','extended','eol')),
  support_until DATE,                                  -- eol or past => UNKNOWN release_eol
  primary_source TEXT NOT NULL,
  dating_sources TEXT[] NOT NULL DEFAULT '{}',
  max_staleness_s INTEGER NOT NULL DEFAULT 172800,
  key_ids TEXT[] NOT NULL DEFAULT '{}');               -- rpm distro key ids
COMMENT ON TABLE advisory_scopes IS '@paddock:global closed list of distro scopes (public, code-defined); written by the intel service as the platform tenant only';

CREATE TABLE IF NOT EXISTS advisory_snapshots (        -- one row per accepted or rejected fetch; one 'current' per (source, scope)
  id BIGSERIAL PRIMARY KEY,
  source TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  fetched_at TIMESTAMPTZ NOT NULL,
  generated_at TIMESTAMPTZ,                            -- the feed's own timestamp; shown, never used to shorten freshness
  etag TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  bytes BIGINT NOT NULL,
  rows_total INTEGER NOT NULL DEFAULT 0,
  rows_kev INTEGER NOT NULL DEFAULT 0,
  rows_dropped INTEGER NOT NULL DEFAULT 0,
  kev_ids_sha TEXT NOT NULL DEFAULT '',                -- sha256 of the sorted KEV id set this snapshot was filtered with
  status TEXT NOT NULL CHECK (status IN ('current','superseded','rejected')),
  reject_reason TEXT NOT NULL DEFAULT '',
  parser_version INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS uq_advisory_snapshot_current ON advisory_snapshots (source, scope) WHERE status = 'current';
CREATE INDEX IF NOT EXISTS idx_advisory_snapshots_feed ON advisory_snapshots (source, scope, fetched_at DESC);
COMMENT ON TABLE advisory_snapshots IS '@paddock:global vendor feed snapshot ledger (public); written by the intel service as the platform tenant only';

CREATE TABLE IF NOT EXISTS advisory_fixes (            -- only rows whose CVE is in kev_entries at filter time
  id BIGSERIAL PRIMARY KEY,
  scope TEXT NOT NULL REFERENCES advisory_scopes(scope),
  cve_id TEXT NOT NULL,
  pkg TEXT NOT NULL,
  pkg_kind TEXT NOT NULL CHECK (pkg_kind IN ('source','binary')),
  state TEXT NOT NULL CHECK (state IN ('fixed','open','not_affected','undetermined','esm_only')),
  fixed_evr TEXT NOT NULL DEFAULT '',
  advisory_id TEXT NOT NULL DEFAULT '',
  fixed_at TIMESTAMPTZ,                                -- advisory publication, start of its UTC day; NULL = undated
  urgency TEXT NOT NULL DEFAULT '',
  stream TEXT NOT NULL DEFAULT '',
  modular BOOLEAN NOT NULL DEFAULT FALSE,
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_snapshot BIGINT NOT NULL REFERENCES advisory_snapshots(id),
  removed_at TIMESTAMPTZ,
  UNIQUE (scope, cve_id, pkg, state, fixed_evr, advisory_id));
CREATE INDEX IF NOT EXISTS idx_advisory_fixes_lookup ON advisory_fixes (scope, pkg) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_advisory_fixes_snapshot ON advisory_fixes (last_seen_snapshot);
CREATE INDEX IF NOT EXISTS idx_advisory_fixes_removed ON advisory_fixes (removed_at) WHERE removed_at IS NOT NULL;
COMMENT ON TABLE advisory_fixes IS '@paddock:global vendor advisory rows filtered to the KEV id set (public); written by the intel service as the platform tenant only';

-- ---------------------------------------------------------------------------
-- Tenant tables
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_manifests (           -- content addressed per tenant: clones share one row
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  sha256 TEXT NOT NULL DEFAULT '' CHECK (sha256 ~ '^([0-9a-f]{64})?$'),
  mgr TEXT NOT NULL DEFAULT 'dpkg' CHECK (mgr IN ('dpkg','rpm')),
  pkg_count INTEGER NOT NULL DEFAULT 0,
  src_names TEXT[] NOT NULL DEFAULT '{}',              -- GIN index: which hosts a KEV delta can touch
  packages_gz BYTEA NOT NULL DEFAULT '',
  size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes BETWEEN 0 AND 1048576),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_ref_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, sha256));
CREATE INDEX IF NOT EXISTS idx_agent_manifests_src ON agent_manifests USING GIN (src_names);

-- `id` primary key plus UNIQUE (tenant_id, agent_id) instead of agent_id as the key, so it passes the isolation-key sweep
-- without a special case.
CREATE TABLE IF NOT EXISTS agent_manifest_refs (       -- the agent's CURRENT list and the envelope that carried it
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  manifest_sha TEXT NOT NULL DEFAULT '' CHECK (manifest_sha ~ '^([0-9a-f]{64})?$'),
  key_id TEXT NOT NULL DEFAULT '',
  seq BIGINT NOT NULL DEFAULT 0,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, agent_id));
CREATE INDEX IF NOT EXISTS idx_agent_manifest_refs_sha ON agent_manifest_refs (tenant_id, manifest_sha);

-- ---------------------------------------------------------------------------
-- Service grants: the intel service appends the four global tables (029 defines the function with
-- ['cves','intel_cursors'] for intel). Re-stated whole, since CREATE OR REPLACE cannot patch it; the only changes from 029
-- are the longer intel append list and the sequence grants for append tables (an INSERT into a BIGSERIAL table needs
-- USAGE on its sequence, which 029 granted to `writes` tables only). Everything else is byte for byte the 029 body.
-- Re-applying 029 after this file would restore the old list: run `SELECT paddock_apply_service_grants();` after 044.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION paddock_apply_service_grants() RETURNS void
LANGUAGE plpgsql AS $fn$
DECLARE
  svc record;
  r text;
  t text;
  seq record;
BEGIN
  FOR svc IN
    SELECT * FROM (VALUES
      ('intel',       ARRAY[]::text[],
                      ARRAY['cve_matches'],
                      ARRAY['cves', 'intel_cursors',
                            'kev_entries', 'advisory_scopes', 'advisory_snapshots', 'advisory_fixes']),
      ('correlation', ARRAY['assets','asset_edges','findings','sbom_components','sbom_component_vulns','sca_projects','scope_entries'],
                      ARRAY['attack_paths','attack_path_ledger','finding_chains','finding_techniques'],  -- ledger: trigger on attack_paths
                      ARRAY['attack_technique_map']),
      ('mlrisk',      ARRAY['asset_edges','assets','attack_paths','cves','findings','ml_training_labels','sbom_component_vulns','surface_changes','tickets'],
                      ARRAY['anomalies','ml_models','ml_risk_scores'],
                      ARRAY[]::text[]),
      ('triage',      ARRAY['asset_owners','assets','findings','sla_policies'],
                      ARRAY['tickets'],
                      ARRAY[]::text[]),
      ('ontology',    ARRAY['asset_edges','assets','attack_paths','findings','sbom_components','sca_projects','tickets'],
                      ARRAY['ontology_links','ontology_objects'],
                      ARRAY['ontology_object_types','ontology_link_types']),
      ('threatintel', ARRAY['assets','findings'],
                      ARRAY['ti_matches','ti_feeds','ti_indicators'],
                      ARRAY[]::text[]),
      ('otdiscovery', ARRAY['cves'],
                      ARRAY[]::text[],
                      ARRAY[]::text[]),
      ('changewatch', ARRAY['asset_edges','assets','findings'],
                      ARRAY['alert_deliveries','alert_rules','surface_changes','service_cursors'],
                      ARRAY[]::text[]),
      ('brain',       ARRAY['assets','findings','attack_paths','ask_assets','ask_findings','ask_attack_paths'],
                      ARRAY['finding_clusters','nl_queries'],
                      ARRAY[]::text[]),
      ('remediation', ARRAY['assets','findings','sbom_component_vulns','sbom_components','sca_projects'],
                      ARRAY['remediations'],
                      ARRAY[]::text[]),
      ('sca',         ARRAY[]::text[],
                      ARRAY['sbom_component_vulns','sbom_components','sca_projects','supply_chain_risks'],
                      ARRAY[]::text[]),
      ('codeanalysis',ARRAY['sbom_components','sca_projects'],
                      ARRAY['code_findings','sbom_component_vulns'],
                      ARRAY[]::text[]),
      ('graphsync',   ARRAY['assets','asset_edges','findings'],
                      ARRAY['service_cursors'],
                      ARRAY[]::text[])
    ) AS v(name, reads, writes, append)
  LOOP
    r := 'paddock_svc_' || svc.name;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE '
                     'NOREPLICATION NOINHERIT', r);
    END IF;
    -- NO role-level default tenant (unlike paddock_app): an unscoped session
    -- sees nothing. The service stamps the tenant per transaction.
    EXECUTE format('ALTER ROLE %I NOSUPERUSER NOBYPASSRLS', r);

    -- Re-derive the grant set from scratch so removing a table here revokes it.
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', r);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', r);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
    EXECUTE format('GRANT SELECT ON tenants TO %I', r);

    FOREACH t IN ARRAY svc.reads LOOP
      IF to_regclass('public.' || quote_ident(t)) IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON public.%I TO %I', t, r);
      END IF;
    END LOOP;
    FOREACH t IN ARRAY svc.append LOOP
      IF to_regclass('public.' || quote_ident(t)) IS NOT NULL THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON public.%I TO %I', t, r);
        -- P2.1: an INSERT into a table with a serial id needs its sequence (advisory_snapshots, advisory_fixes);
        -- 029 granted sequences to the `writes` tables only, which no append table needed until now.
        FOR seq IN
          SELECT s.oid::regclass AS sname
            FROM pg_class s
            JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
           WHERE s.relkind = 'S' AND d.refobjid = to_regclass('public.' || quote_ident(t))
        LOOP
          EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO %I', seq.sname, r);
        END LOOP;
      END IF;
    END LOOP;
    FOREACH t IN ARRAY svc.writes LOOP
      IF to_regclass('public.' || quote_ident(t)) IS NOT NULL THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO %I', t, r);
        -- serial / identity sequences owned by a writable table
        FOR seq IN
          SELECT s.oid::regclass AS sname
            FROM pg_class s
            JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
           WHERE s.relkind = 'S' AND d.refobjid = to_regclass('public.' || quote_ident(t))
        LOOP
          EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO %I', seq.sname, r);
        END LOOP;
      END IF;
    END LOOP;
  END LOOP;
END $fn$;

-- 029 is self-sufficient (it bootstraps `tenants`), so in every real order the table exists here; the guard only keeps a
-- contrived order (029 applied AFTER 099, see test_service_tenancy) from failing on the grant of SELECT ON tenants.
DO $$
BEGIN
  IF to_regclass('public.tenants') IS NOT NULL THEN
    PERFORM paddock_apply_service_grants();
  END IF;
END $$;

REVOKE ALL ON FUNCTION paddock_apply_service_grants() FROM PUBLIC;
