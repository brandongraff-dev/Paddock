-- 033: MSP (managed service provider) console. See docs/MSP.md.
--
-- An MSP is an ordinary tenant that has a row in `msp_orgs`. It manages child
-- tenants (`msp_children`) and its users act inside a child only through an
-- explicit grant (`msp_grants`, per child or "all children") plus a short-lived
-- child-scoped token (orchestrator/app/msp). Nothing here weakens RLS:
--
--   * Every table below is tenant-scoped like any other. The relationship data
--     (children, grants, templates, cached health, usage) belongs to the MSP's
--     tenant, so a customer's users can never read the parent or a sibling.
--     There is deliberately NO parent_tenant_id on the global `tenants` table.
--   * The two things the app role may not do (create / suspend a tenant: it
--     cannot write `tenants`) go through two narrow SECURITY DEFINER functions.
--     They act ONLY on the session's current tenant, only if it is an MSP, and
--     only for its own children.
--   * `msp_orgs` / `msp_children` cannot be written by the app role directly
--     (a trigger refuses it): promoting a tenant to an MSP is an operator
--     action (python -m app.msp enable ...), and a child can only be added by
--     msp_create_child_tenant(), so an MSP admin can never "adopt" an existing
--     tenant by guessing its UUID.
--
-- Runs BEFORE 099_tenancy.sql, which adds the tenant_id default / FK / RLS to
-- every table here; the DO block at the end applies the same policy early when
-- 099 has already run (upgrade path), so there is no window without RLS.
-- tenant_id is declared (no default) so UNIQUE constraints can name it.

-- ---------------------------------------------------------------------------
-- The MSP organisation marker (one row per MSP tenant)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msp_orgs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  max_children  INT CHECK (max_children IS NULL OR max_children > 0),
  created_by    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The customers an MSP manages. Rows live in the MSP's tenant.
CREATE TABLE IF NOT EXISTS msp_children (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL,                 -- the MSP
  child_tenant_id  UUID NOT NULL UNIQUE,          -- the customer (one MSP per customer)
  slug             TEXT NOT NULL,
  name             TEXT NOT NULL,
  created_by       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_msp_children_tenant ON msp_children (tenant_id, name);

-- Delegated access: which MSP user may act in which customer, with which role.
-- child_tenant_id NULL = every current and future customer of this MSP; a
-- per-customer row always wins over the wildcard (so a wildcard admin can be
-- carved down to viewer for one sensitive customer). Revoking = deleting the
-- row; the next request of any outstanding token fails.
CREATE TABLE IF NOT EXISTS msp_grants (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL,                 -- the MSP
  user_id          UUID NOT NULL,                 -- app_users.id in the MSP tenant
  child_tenant_id  UUID,
  role             TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
  -- highest classification the delegated session may read in the customer
  clearance        TEXT NOT NULL DEFAULT 'internal'
                   CHECK (clearance IN ('public', 'internal', 'confidential', 'restricted')),
  granted_by       TEXT,
  granted_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_msp_grants_child
  ON msp_grants (user_id, child_tenant_id) WHERE child_tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_msp_grants_all
  ON msp_grants (user_id) WHERE child_tenant_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_msp_grants_tenant ON msp_grants (tenant_id, child_tenant_id);

-- ---------------------------------------------------------------------------
-- Templates (alert rules, integrations, suggested scope) applied to many children
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msp_templates (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL,
  name         TEXT NOT NULL,
  description  TEXT,
  spec         JSONB NOT NULL DEFAULT '{}'::jsonb,   -- NON-secret parts
  secrets      TEXT,                                  -- AES-GCM blob (integration secrets)
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS msp_template_applications (
  id               BIGSERIAL PRIMARY KEY,
  tenant_id        UUID NOT NULL,
  template_id      UUID NOT NULL,
  child_tenant_id  UUID NOT NULL,
  status           TEXT NOT NULL CHECK (status IN ('applied', 'partial', 'failed', 'skipped')),
  detail           JSONB NOT NULL DEFAULT '{}'::jsonb,
  applied_by       TEXT,
  applied_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_msp_tpl_apps ON msp_template_applications (tenant_id, template_id, applied_at DESC);

-- ---------------------------------------------------------------------------
-- Rollup cache + billing usage (both owned by the MSP tenant)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msp_child_health (
  child_tenant_id   UUID PRIMARY KEY,
  tenant_id         UUID NOT NULL,                 -- the MSP
  grade             TEXT NOT NULL,
  exposure_index    INT NOT NULL DEFAULT 0,
  open_findings     INT NOT NULL DEFAULT 0,
  open_criticals    INT NOT NULL DEFAULT 0,
  sla_breaches      INT NOT NULL DEFAULT 0,
  verified_fixes    INT NOT NULL DEFAULT 0,        -- last 30 days
  last_scan_at      TIMESTAMPTZ,
  monitored_assets  INT NOT NULL DEFAULT 0,
  seats_used        INT NOT NULL DEFAULT 0,
  seats_limit       INT,
  assets_limit      INT,
  computed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_msp_child_health_tenant ON msp_child_health (tenant_id);

CREATE TABLE IF NOT EXISTS msp_usage_snapshots (
  child_tenant_id   UUID NOT NULL,
  day               DATE NOT NULL,
  tenant_id         UUID NOT NULL,                 -- the MSP
  monitored_assets  INT NOT NULL DEFAULT 0,
  total_assets      INT NOT NULL DEFAULT 0,
  users             INT NOT NULL DEFAULT 0,
  scans_month       INT NOT NULL DEFAULT 0,
  integrations      INT NOT NULL DEFAULT 0,
  fleet_agents      INT NOT NULL DEFAULT 0,
  edition           TEXT NOT NULL DEFAULT 'community',
  taken_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (child_tenant_id, day)
);
CREATE INDEX IF NOT EXISTS idx_msp_usage_tenant ON msp_usage_snapshots (tenant_id, day);

-- ---------------------------------------------------------------------------
-- Onboarding invites for a customer's first admin. Rows live in the CUSTOMER's
-- tenant; the token is "<customer tenant id>.<secret>", only its sha256 is
-- stored, and it is single use.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msp_invites (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,                       -- the customer
  msp_tenant_id UUID,                              -- the MSP that issued it (audit mirror)
  token_hash  TEXT NOT NULL UNIQUE,
  label       TEXT,
  created_by  TEXT NOT NULL,                       -- e.g. msp:acme-msp/alice
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  used_by     TEXT
);
CREATE INDEX IF NOT EXISTS idx_msp_invites_tenant ON msp_invites (tenant_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- The app role may not write msp_orgs / msp_children directly.
-- current_user (not session_user) so the SECURITY DEFINER functions below,
-- which run as the owner, are allowed through.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION msp_guard_privileged_write() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  -- (a superuser is implicitly a member of every role, hence the rolsuper test)
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_app')
     AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper)
     AND pg_has_role(current_user, 'paddock_app', 'MEMBER') THEN
    RAISE EXCEPTION 'msp_orgs / msp_children are written by operator tooling or msp_* functions only'
      USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_msp_orgs_guard ON msp_orgs;
CREATE TRIGGER trg_msp_orgs_guard BEFORE INSERT OR UPDATE OR DELETE ON msp_orgs
  FOR EACH ROW EXECUTE FUNCTION msp_guard_privileged_write();
DROP TRIGGER IF EXISTS trg_msp_children_guard ON msp_children;
CREATE TRIGGER trg_msp_children_guard BEFORE INSERT OR UPDATE OR DELETE ON msp_children
  FOR EACH ROW EXECUTE FUNCTION msp_guard_privileged_write();

-- ---------------------------------------------------------------------------
-- Create / suspend a child tenant. SECURITY DEFINER because the app role may
-- not write `tenants`. Both act on paddock_current_tenant() only: a caller can
-- never name another MSP.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION msp_create_child_tenant(p_slug text, p_name text, p_created_by text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_msp   uuid := paddock_current_tenant();
  v_org   msp_orgs%ROWTYPE;
  v_child uuid;
  v_n     int;
BEGIN
  IF v_msp IS NULL THEN
    RAISE EXCEPTION 'no tenant context' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO v_org FROM msp_orgs WHERE tenant_id = v_msp;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant is not an MSP' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = v_msp AND status = 'active') THEN
    RAISE EXCEPTION 'MSP tenant is not active' USING ERRCODE = '42501';
  END IF;
  IF v_org.max_children IS NOT NULL THEN
    SELECT COUNT(*) INTO v_n FROM msp_children WHERE tenant_id = v_msp;
    IF v_n >= v_org.max_children THEN
      RAISE EXCEPTION 'customer limit reached (%)', v_org.max_children USING ERRCODE = '53400';
    END IF;
  END IF;
  IF p_slug = 'default' THEN
    RAISE EXCEPTION 'reserved slug' USING ERRCODE = '23505';
  END IF;
  INSERT INTO tenants (slug, name) VALUES (p_slug, p_name) RETURNING id INTO v_child;
  INSERT INTO msp_children (tenant_id, child_tenant_id, slug, name, created_by)
  VALUES (v_msp, v_child, p_slug, p_name, p_created_by);
  RETURN v_child;
END $$;

CREATE OR REPLACE FUNCTION msp_set_child_status(p_child uuid, p_status text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_msp uuid := paddock_current_tenant();
BEGIN
  IF v_msp IS NULL THEN
    RAISE EXCEPTION 'no tenant context' USING ERRCODE = '42501';
  END IF;
  IF p_status NOT IN ('active', 'suspended') THEN
    RAISE EXCEPTION 'invalid status' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM msp_orgs WHERE tenant_id = v_msp) THEN
    RAISE EXCEPTION 'tenant is not an MSP' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM msp_children WHERE tenant_id = v_msp AND child_tenant_id = p_child) THEN
    RAISE EXCEPTION 'not a customer of this MSP' USING ERRCODE = '42501';
  END IF;
  UPDATE tenants SET status = p_status WHERE id = p_child;
  RETURN p_status;
END $$;

-- ---------------------------------------------------------------------------
-- Upgrade path: if 099 already ran on this database, give the new tables the
-- same tenant default / FK / RLS now (099 does it again, identically, later).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  t text;
BEGIN
  IF to_regprocedure('paddock_current_tenant()') IS NULL OR to_regclass('public.tenants') IS NULL THEN
    RETURN;  -- fresh database: 099 runs next and covers these tables
  END IF;
  FOREACH t IN ARRAY ARRAY['msp_orgs', 'msp_children', 'msp_grants', 'msp_templates',
                           'msp_template_applications', 'msp_child_health',
                           'msp_usage_snapshots', 'msp_invites']
  LOOP
    EXECUTE format('ALTER TABLE public.%I ALTER COLUMN tenant_id SET DEFAULT '
                   'COALESCE(paddock_current_tenant(), paddock_default_tenant())', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON public.%I (tenant_id)', left('tnt_' || t, 63), t);
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = ('public.' || t)::regclass AND conname = left(t || '_tenant_fk', 63)) THEN
      EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)',
                     t, left(t || '_tenant_fk', 63));
    END IF;
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON public.%I '
                   'USING (tenant_id = paddock_current_tenant()) '
                   'WITH CHECK (tenant_id = paddock_current_tenant())', t);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_app') THEN
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO paddock_app', t);
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_app') THEN
    GRANT USAGE, SELECT, UPDATE ON SEQUENCE msp_template_applications_id_seq TO paddock_app;
  END IF;
END $$;
