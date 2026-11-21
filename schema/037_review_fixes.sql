-- 037_review_fixes.sql: security-review follow-ups.
--
-- 1. msp_create_child_tenant / msp_set_child_status are SECURITY DEFINER and
--    authorise through paddock_current_tenant(), a GUC any session can set. A
--    function is executable by PUBLIC unless revoked, so a compromised
--    paddock_svc_* login could suspend any MSP's customers or mint tenants.
--    Only the application role may call them.
-- 2. Their two membership errors are now one identical message so the call is
--    not an oracle for "is this tenant an MSP / is that tenant its customer".
--
-- Idempotent; safe to re-run.

-- paddock_app is normally created by 099_tenancy.sql (which runs later). Create
-- it here with the same attributes so the GRANT below works on a fresh database;
-- 099 skips creation when it already exists.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_app') THEN
    CREATE ROLE paddock_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

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
    RAISE EXCEPTION 'not permitted' USING ERRCODE = '42501';
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
  -- one message for "not an MSP" and "not your customer"
  IF NOT EXISTS (SELECT 1 FROM msp_orgs WHERE tenant_id = v_msp)
     OR NOT EXISTS (SELECT 1 FROM msp_children WHERE tenant_id = v_msp AND child_tenant_id = p_child) THEN
    RAISE EXCEPTION 'not permitted' USING ERRCODE = '42501';
  END IF;
  UPDATE tenants SET status = p_status WHERE id = p_child;
  RETURN p_status;
END $$;

REVOKE ALL ON FUNCTION msp_create_child_tenant(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION msp_set_child_status(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION msp_create_child_tenant(text, text, text) TO paddock_app;
GRANT EXECUTE ON FUNCTION msp_set_child_status(uuid, text) TO paddock_app;
