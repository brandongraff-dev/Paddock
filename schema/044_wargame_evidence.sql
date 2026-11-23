-- Wargame twin evidence: observed flows and recorded probe results.
--
-- 042 stores config + topology, which can only prove a pair closed on paper
-- ('proved_config'). These two tables hold the other two sources of the
-- three-way boundary agreement (docs/WARGAME.md §2.2):
--
--   * wargame_observed_flows  - flows parsed from the customer's own firewall /
--     Zeek / generic logs (correlation POST /ingest-flows). A REAL flow across
--     a config-closed pair makes it 'fail_open'; one across a still-valid
--     certificate raises an impossible-traffic alert.
--   * wargame_probe_results   - RECORDED probe results submitted by the
--     customer's probe or scanner (correlation POST /ingest-probes): did a
--     connect from src_segment reach dst_segment on proto/port? Paddock sends
--     no packets for this; it stores what it is told.
--
-- Bounded (enforced by correlation app/engine/wargame/evidence.py on every
-- ingest, RLS-scoped to the tenant):
--   flows : rolling 30-day window by observed_at, at most 100,000 rows per
--           tenant (newest kept);
--   probes: 30 days of history, at most 50,000 rows per tenant; only results
--           younger than the certificate TTL (24 h) count in an assessment.
--
-- tenant_id + RLS and the correlation service grants follow 042 exactly.
-- =====================================================================

CREATE TABLE IF NOT EXISTS wargame_observed_flows (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  src_ip                 TEXT NOT NULL,
  dst_ip                 TEXT NOT NULL,
  proto                  TEXT NOT NULL CHECK (proto IN ('tcp','udp','icmp','any')),
  dst_port               INTEGER NOT NULL CHECK (dst_port BETWEEN 0 AND 65535),
  handshake_completed    BOOLEAN NOT NULL DEFAULT FALSE,
  dst_side_observed      BOOLEAN NOT NULL DEFAULT FALSE,
  firewall_allow_logged  BOOLEAN NOT NULL DEFAULT FALSE,
  is_broadcast           BOOLEAN NOT NULL DEFAULT FALSE,
  kind                   TEXT NOT NULL DEFAULT '',
  ts                     TEXT NOT NULL DEFAULT '',          -- the sensor's own timestamp, verbatim
  observed_at            TIMESTAMPTZ NOT NULL,              -- parsed ts, else the ingest time
  source                 TEXT NOT NULL DEFAULT '',          -- log file / sensor id
  ingested_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wg_flows_observed ON wargame_observed_flows(observed_at DESC);

CREATE TABLE IF NOT EXISTS wargame_probe_results (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  src_segment            TEXT NOT NULL,                     -- twin segment the probe ran FROM
  dst_segment            TEXT NOT NULL,                     -- twin segment it tried to reach
  proto                  TEXT NOT NULL DEFAULT 'tcp' CHECK (proto IN ('tcp','udp','icmp')),
  port                   INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
  result                 TEXT NOT NULL CHECK (result IN ('crossed','blocked','error')),
  observed_at            TIMESTAMPTZ NOT NULL,              -- when the probe ran
  source                 TEXT NOT NULL DEFAULT '',          -- probe / scanner id
  ingested_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wg_probes_pair
  ON wargame_probe_results(src_segment, dst_segment, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_wg_probes_observed ON wargame_probe_results(observed_at DESC);

-- ---------------------------------------------------------------------------
-- Tenancy (as 042): tenant_id + FORCEd RLS now, so a tenant only ever sees
-- and prunes its own evidence. (099 retrofits the same policy when it runs.)
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  IF to_regprocedure('paddock_enable_tenant_rls(regclass)') IS NOT NULL THEN
    FOREACH t IN ARRAY ARRAY['wargame_observed_flows', 'wargame_probe_results'] LOOP
      PERFORM paddock_enable_tenant_rls(t::regclass);
    END LOOP;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Grants (as 042): extend paddock_apply_service_grants()'s correlation WRITE
-- allow-list (as 042 left it) with the two evidence tables, re-derive the
-- grants, and grant directly too. If the function has an unexpected shape the
-- direct GRANTs still apply (a later paddock_apply_service_grants() run would
-- then revoke them: keep the allow-list in sync).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  def  text;
  patched text;
  needle CONSTANT text :=
    '''wargame_edges'',''wargame_config_snapshots'']';
  extra CONSTANT text :=
    '''wargame_edges'',''wargame_config_snapshots'','
    '''wargame_observed_flows'',''wargame_probe_results'']';
  t text;
BEGIN
  IF to_regprocedure('paddock_apply_service_grants()') IS NULL THEN
    RETURN;       -- 029 not applied yet: nothing to extend
  END IF;
  SELECT pg_get_functiondef('paddock_apply_service_grants()'::regprocedure) INTO def;
  IF position('wargame_observed_flows' IN def) > 0 THEN
    NULL;                                    -- already extended
  ELSIF position(needle IN def) > 0 THEN
    patched := replace(def, needle, extra);
    EXECUTE patched;
  ELSE
    RAISE NOTICE '044: paddock_apply_service_grants() has an unexpected shape; granting directly';
  END IF;
  PERFORM paddock_apply_service_grants();
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_svc_correlation') THEN
    FOREACH t IN ARRAY ARRAY['wargame_observed_flows', 'wargame_probe_results'] LOOP
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO paddock_svc_correlation', t);
    END LOOP;
  END IF;
END $$;
