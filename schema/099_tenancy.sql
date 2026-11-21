-- 099: multi-tenancy via Postgres row-level security. RUNS LAST.
--
-- Design (docs/trust/TENANCY.md has the long form):
--   * `tenants` catalogue + a fixed DEFAULT tenant that every pre-existing row
--     (and every single-tenant install) belongs to.
--   * A dynamic DO-block walks EVERY table in schema `public` -- including the
--     ones other migrations (015..098) add later -- and, idempotently:
--       - adds `tenant_id UUID NOT NULL DEFAULT <session tenant | default>`,
--       - indexes it,
--       - ENABLEs + FORCEs row-level security,
--       - (re)creates policy `tenant_isolation`:
--             USING / WITH CHECK  tenant_id = paddock_current_tenant()
--     Global catalogues are skipped: the explicit allow-list below, plus any
--     table whose COMMENT contains the marker  @paddock:global
--     (so a new feed table can opt out without editing this file).
--   * Natural-key UNIQUE constraints that must be per-tenant are rebuilt with
--     tenant_id as the leading column (see the explicit list).
--   * A NON-superuser application role `paddock_app` (NOLOGIN here; the
--     password / LOGIN is granted by 100_app_role.sh or by the operator) with
--     DML on tenant tables, read-only on global catalogues and `tenants`, and
--     INSERT/SELECT only on audit_log.
--
-- The orchestrator sets `app.tenant_id` on every pooled connection from the
-- request's principal (orchestrator/app/tenancy.py). Superusers and BYPASSRLS
-- roles are NOT subject to RLS; migrations keep running as the owner.
--
-- Re-run this file after adding tables (it is idempotent); the test harness and
-- docker-entrypoint-initdb.d both apply it after every other *.sql file.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Tenants
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  data_region  TEXT,                          -- informational (EU/US residency)
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tenants (id, slug, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default tenant')
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION paddock_default_tenant() RETURNS uuid
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  AS $$ SELECT '00000000-0000-0000-0000-000000000001'::uuid $$;

-- The session's tenant, or NULL when unset/empty. ('' happens after RESET ALL
-- once the placeholder GUC exists, and is what strict mode sets explicitly.)
CREATE OR REPLACE FUNCTION paddock_current_tenant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

-- ---------------------------------------------------------------------------
-- Non-superuser application role (cluster-wide object; created once)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_app') THEN
    CREATE ROLE paddock_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
EXCEPTION WHEN duplicate_object THEN NULL;  -- concurrent creation
END $$;

-- Connections that never set a tenant (single-tenant services connecting as
-- the app role) land in the default tenant. The orchestrator always overrides
-- this per acquire; TENANCY_STRICT=true overrides it with "no tenant".
DO $$
BEGIN
  EXECUTE 'ALTER ROLE paddock_app SET app.tenant_id = ''00000000-0000-0000-0000-000000000001''';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'could not set paddock_app default tenant (needs superuser); set app.tenant_id per connection';
END $$;

-- ---------------------------------------------------------------------------
-- tenant_id + RLS on every tenant-scoped table
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  -- Global catalogues: shared by all tenants, readable by everyone, writable
  -- only from the default ("platform") tenant or by the owner.
  global_tables CONSTANT text[] := ARRAY[
    'tenants', 'schema_migrations',
    'cves', 'intel_cursors',                     -- NVD/EPSS/KEV feeds + cursors
    'attack_technique_map',                      -- MITRE ATT&CK catalogue
    'ontology_object_types', 'ontology_link_types',
    'ti_feeds', 'ti_indicators',                 -- threat-intel feeds/IOCs
    'sla_policies'                               -- platform-wide SLA (PK severity)
  ];
  -- Identity tables: readable across tenants ONLY during credential lookup.
  identity_tables CONSTANT text[] := ARRAY['app_users', 'api_keys'];
  r record;
  is_global boolean;
BEGIN
  FOR r IN
    SELECT c.oid, c.relname,
           COALESCE(obj_description(c.oid, 'pg_class'), '') AS cmt
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND NOT c.relispartition
     ORDER BY c.relname
  LOOP
    is_global := r.relname = ANY (global_tables) OR r.cmt LIKE '%@paddock:global%';

    IF is_global THEN
      IF r.relname = 'tenants' THEN
        CONTINUE;  -- handled explicitly below
      END IF;
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', r.relname);
      EXECUTE format('DROP POLICY IF EXISTS global_read ON public.%I', r.relname);
      EXECUTE format('CREATE POLICY global_read ON public.%I FOR SELECT USING (true)', r.relname);
      EXECUTE format('DROP POLICY IF EXISTS global_platform_write ON public.%I', r.relname);
      EXECUTE format(
        'CREATE POLICY global_platform_write ON public.%I FOR ALL '
        'USING (paddock_current_tenant() = paddock_default_tenant()) '
        'WITH CHECK (paddock_current_tenant() = paddock_default_tenant())', r.relname);
      CONTINUE;
    END IF;

    EXECUTE format(
      'ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL '
      'DEFAULT COALESCE(paddock_current_tenant(), paddock_default_tenant())', r.relname);
    EXECUTE format('ALTER TABLE public.%I ALTER COLUMN tenant_id SET DEFAULT '
                   'COALESCE(paddock_current_tenant(), paddock_default_tenant())', r.relname);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON public.%I (tenant_id)',
                   left('tnt_' || r.relname, 63), r.relname);
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint
       WHERE conrelid = r.oid AND conname = left(r.relname || '_tenant_fk', 63)
    ) THEN
      EXECUTE format(
        'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)',
        r.relname, left(r.relname || '_tenant_fk', 63));
    END IF;
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', r.relname);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', r.relname);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I', r.relname);
    IF r.relname = ANY (identity_tables) THEN
      EXECUTE format(
        'CREATE POLICY tenant_isolation ON public.%I '
        'USING (tenant_id = paddock_current_tenant() '
        '       OR current_setting(''app.auth_lookup'', true) = ''on'') '
        'WITH CHECK (tenant_id = paddock_current_tenant() '
        '       OR current_setting(''app.auth_lookup'', true) = ''on'')', r.relname);
    ELSE
      EXECUTE format(
        'CREATE POLICY tenant_isolation ON public.%I '
        'USING (tenant_id = paddock_current_tenant()) '
        'WITH CHECK (tenant_id = paddock_current_tenant())', r.relname);
    END IF;
  END LOOP;
END $$;

-- tenants: the app may read the catalogue (background loops enumerate tenants,
-- the service principal resolves X-Paddock-Tenant) but never write it.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenants_read ON tenants;
CREATE POLICY tenants_read ON tenants FOR SELECT USING (true);

-- ---------------------------------------------------------------------------
-- Per-tenant natural keys. A UNIQUE (cols) constraint is replaced by
-- UNIQUE (tenant_id, cols) so two tenants can hold the same scope value /
-- asset / integration name. NOTE: an `ON CONFLICT (cols)` must then name
-- `(tenant_id, cols)` -- the orchestrator's upserts on these tables do.
-- Tables upserted by non-orchestrator services (sca_projects, attack_paths,
-- anomalies, ml_models, ...) keep their global keys for now; see TENANCY.md.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pg_temp.paddock_tenantize_unique(tbl text, cols text[])
RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE
  c record;
  want text := left(tbl || '_tenant_' || array_to_string(cols, '_') || '_key', 63);
BEGIN
  IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
    RETURN;  -- table not present in this deployment
  END IF;
  FOR c IN
    SELECT con.conname
      FROM pg_constraint con
     WHERE con.conrelid = ('public.' || quote_ident(tbl))::regclass
       AND con.contype = 'u'
       AND (SELECT array_agg(a.attname::text ORDER BY a.attname)
              FROM unnest(con.conkey) k JOIN pg_attribute a
                ON a.attrelid = con.conrelid AND a.attnum = k)
           = (SELECT array_agg(x ORDER BY x) FROM unnest(cols) x)
  LOOP
    EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', tbl, c.conname);
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = ('public.' || quote_ident(tbl))::regclass AND conname = want) THEN
    EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I UNIQUE (tenant_id, %s)',
                   tbl, want,
                   (SELECT string_agg(quote_ident(x), ', ') FROM unnest(cols) x));
  END IF;
END $fn$;

SELECT pg_temp.paddock_tenantize_unique('scope_entries', ARRAY['kind', 'value']);
SELECT pg_temp.paddock_tenantize_unique('assets',        ARRAY['kind', 'canonical']);
SELECT pg_temp.paddock_tenantize_unique('integrations',  ARRAY['kind', 'name']);
SELECT pg_temp.paddock_tenantize_unique('fleet_agents',  ARRAY['hostname']);

-- Audit chains are per tenant: the head lookup + verify walk use this.
DO $$
BEGIN
  IF to_regclass('public.audit_log') IS NOT NULL THEN
    CREATE INDEX IF NOT EXISTS idx_audit_tenant_id ON audit_log (tenant_id, id);
  END IF;
END $$;

-- Views must evaluate RLS as the *caller*, not as their (owner) creator.
DO $$
DECLARE v record;
BEGIN
  FOR v IN
    SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'v'
  LOOP
    EXECUTE format('ALTER VIEW public.%I SET (security_invoker = true)', v.relname);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Grants for the app role. It owns nothing; it cannot create objects, cannot
-- rewrite history (audit_log is INSERT/SELECT only) and cannot add tenants.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO paddock_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO paddock_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO paddock_app;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM paddock_app;
REVOKE INSERT, UPDATE, DELETE ON tenants FROM paddock_app;
DO $$
BEGIN
  IF to_regclass('public.audit_log') IS NOT NULL THEN
    REVOKE UPDATE, DELETE ON audit_log FROM paddock_app;
  END IF;
END $$;
-- Objects the migration role creates later are usable by the app role too
-- (RLS for them arrives when this file is re-applied).
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO paddock_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO paddock_app;
