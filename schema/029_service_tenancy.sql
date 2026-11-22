-- 029: tenancy for the compute services (docs/trust/TENANCY.md, "Compute
-- services and workers").
--
-- 099_tenancy.sql gave the ORCHESTRATOR a non-superuser role + RLS. The compute
-- services (intel, correlation, mlrisk, triage, ontology, threatintel,
-- otdiscovery, changewatch, brain, remediation, sca, codeanalysis, graphsync)
-- still connected as the schema owner and bypassed it. This file gives each of
-- them:
--
--   1. its own LEAST-PRIVILEGE login role `paddock_svc_<name>`: NOSUPERUSER,
--      NOBYPASSRLS, NOLOGIN here (100/101 scripts or the operator grant LOGIN +
--      password), SELECT/DML only on the tables that service actually touches,
--      nothing on audit_log / credentials / identity tables. Row-level security
--      from 099 then pins every statement to the tenant the service sets per
--      transaction (set_config('app.tenant_id', ..., true)).
--   2. a tenant-scoped `service_cursors` table, so per-tenant sync state
--      (changewatch, graphsync) stops living in the global `intel_cursors`
--      (a @paddock:global catalogue: a tenant's cursor must never land there).
--   3. per-tenant natural keys for the tables non-orchestrator services upsert
--      on (sca_projects.name, attack_paths.fingerprint, ml_models(kind,version),
--      anomalies(subject_type,subject_label,detected_at)), so two tenants
--      cannot collide on -- or learn the existence of -- each other's rows.
--
-- ORDER-INDEPENDENT. This file sorts BEFORE 099 on a fresh database, but is
-- applied AFTER it on a database that already ran 099. Everything below is
-- idempotent and self-sufficient: it bootstraps the tenants catalogue and the
-- two GUC helper functions (byte-identical to 099's, CREATE OR REPLACE) and
-- applies tenant_id + FORCEd RLS to the objects it touches itself.
--
-- After adding tables in later migrations, re-run  SELECT paddock_apply_service_grants();
-- (grants are an explicit allow-list: a new table is invisible to every
-- service role until it is added to the list below).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Bootstrap (same definitions as 099; harmless when 099 already ran)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  data_region  TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tenants (id, slug, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default tenant')
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION paddock_default_tenant() RETURNS uuid
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  AS $$ SELECT '00000000-0000-0000-0000-000000000001'::uuid $$;

CREATE OR REPLACE FUNCTION paddock_current_tenant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

-- ---------------------------------------------------------------------------
-- paddock_enable_tenant_rls(tbl): the per-table body of 099's DO-block, so a
-- migration can make its own tables tenant-safe without waiting for 099.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION paddock_enable_tenant_rls(tbl regclass) RETURNS void
LANGUAGE plpgsql AS $fn$
DECLARE
  rel text := (SELECT relname FROM pg_class WHERE oid = tbl);
BEGIN
  EXECUTE format(
    'ALTER TABLE %s ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL '
    'DEFAULT COALESCE(paddock_current_tenant(), paddock_default_tenant())', tbl);
  EXECUTE format('ALTER TABLE %s ALTER COLUMN tenant_id SET DEFAULT '
                 'COALESCE(paddock_current_tenant(), paddock_default_tenant())', tbl);
  EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s (tenant_id)', left('tnt_' || rel, 63), tbl);
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = tbl AND conname = left(rel || '_tenant_fk', 63)) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES tenants(id)',
                   tbl, left(rel || '_tenant_fk', 63));
  END IF;
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
  EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %s', tbl);
  EXECUTE format(
    'CREATE POLICY tenant_isolation ON %s '
    'USING (tenant_id = paddock_current_tenant()) '
    'WITH CHECK (tenant_id = paddock_current_tenant())', tbl);
END $fn$;

-- ---------------------------------------------------------------------------
-- Per-tenant sync cursors (replaces service use of the global intel_cursors)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS service_cursors (
  id           BIGSERIAL PRIMARY KEY,
  service      TEXT NOT NULL,                  -- 'changewatch', 'graphsync', ...
  key          TEXT NOT NULL,                  -- cursor name within the service
  last_synced  TIMESTAMPTZ,
  last_cursor  TEXT,
  stats        JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE service_cursors IS
  'Tenant-scoped sync state of compute services. NOT global: one row per (tenant, service, key).';
SELECT paddock_enable_tenant_rls('service_cursors'::regclass);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'service_cursors_tenant_service_key_key') THEN
    ALTER TABLE service_cursors
      ADD CONSTRAINT service_cursors_tenant_service_key_key UNIQUE (tenant_id, service, key);
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Per-tenant natural keys for tables services upsert on
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION paddock_tenantize_key(tbl text, cols text[]) RETURNS void
LANGUAGE plpgsql AS $fn$
DECLARE
  c record;
  want text := left(tbl || '_tenant_' || array_to_string(cols, '_') || '_key', 63);
  oid_ regclass := to_regclass('public.' || quote_ident(tbl));
BEGIN
  IF oid_ IS NULL THEN
    RETURN;                                    -- table absent in this deployment
  END IF;
  PERFORM paddock_enable_tenant_rls(oid_);     -- tenant_id must exist first
  FOR c IN
    SELECT con.conname
      FROM pg_constraint con
     WHERE con.conrelid = oid_ AND con.contype = 'u'
       AND (SELECT array_agg(a.attname::text ORDER BY a.attname)
              FROM unnest(con.conkey) k JOIN pg_attribute a
                ON a.attrelid = con.conrelid AND a.attnum = k)
           = (SELECT array_agg(x ORDER BY x) FROM unnest(cols) x)
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', oid_, c.conname);
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = oid_ AND conname = want) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I UNIQUE (tenant_id, %s)',
                   oid_, want, (SELECT string_agg(quote_ident(x), ', ') FROM unnest(cols) x));
  END IF;
END $fn$;

SELECT paddock_tenantize_key('sca_projects', ARRAY['name']);
SELECT paddock_tenantize_key('attack_paths', ARRAY['fingerprint']);
SELECT paddock_tenantize_key('ml_models',    ARRAY['kind', 'version']);
SELECT paddock_tenantize_key('anomalies',    ARRAY['subject_type', 'subject_label', 'detected_at']);

-- The attack-path ledger (023) keeps one OPEN episode per fingerprint through a
-- partial unique index that ignores the tenant: make it per tenant.
DO $$
BEGIN
  IF to_regclass('public.attack_path_ledger') IS NOT NULL THEN
    PERFORM paddock_enable_tenant_rls('public.attack_path_ledger'::regclass);
    DROP INDEX IF EXISTS uq_apl_open;
    CREATE UNIQUE INDEX IF NOT EXISTS uq_apl_open_tenant
      ON attack_path_ledger (tenant_id, fingerprint) WHERE closed_at IS NULL;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Service roles: an explicit allow-list per service
-- ---------------------------------------------------------------------------
--   reads   SELECT
--   writes  SELECT, INSERT, UPDATE, DELETE
--   append  SELECT, INSERT, UPDATE        (global catalogues: RLS additionally
--                                          limits writes to the platform tenant)
-- Anything not listed -- audit_log, app_users, api_keys, integrations, scim_*,
-- identity_*, scope_proofs, fleet_* ... -- is unreachable to the service role.
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
                      ARRAY['cves', 'intel_cursors']),
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

SELECT paddock_apply_service_grants();

-- Helper functions are operator tools, not application surface.
REVOKE ALL ON FUNCTION paddock_enable_tenant_rls(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION paddock_tenantize_key(text, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION paddock_apply_service_grants() FROM PUBLIC;
