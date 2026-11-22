-- Wargame: honest verdict vocabulary + certificate signing key ids.
--
-- 1. wargame_boundaries.verdict gains 'proved_config': the configuration
--    proves the boundary closed, but no active probe has tested it. 'pass' is
--    now reserved for configuration AND a real probe agreeing (earlier
--    versions labelled config-only closure 'pass' by feeding the model's own
--    reachability back in as the "probe"). Widening a CHECK is compatible:
--    every existing row still satisfies it.
-- 2. wargame_certificates.key_id records which key made the fingerprint:
--    'wg1-<16 hex>' = a per-tenant key derived from WARGAME_SIGNING_KEY;
--    'unsigned-dev' = the public development key (NOT a signature). Existing
--    rows default to '' = legacy, which were all fingerprinted with the
--    public demo key, so readers must treat '' as unsigned too.
-- 3. wargame_certificates.corroboration stores the signed corroboration
--    fields ({observed_flows, window_days, sensor_on_protected_side,
--    probe_tested}) so a stored certificate can be re-verified and an auditor
--    can see whether an active probe stood behind it. '{}' on legacy rows.
--
-- Idempotent (DROP ... IF EXISTS / ADD COLUMN IF NOT EXISTS), like 025.
-- 041 is not edited: applied files are immutable (orchestrator/app/migrate.py).
-- =====================================================================

ALTER TABLE wargame_boundaries DROP CONSTRAINT IF EXISTS wargame_boundaries_verdict_check;
ALTER TABLE wargame_boundaries ADD CONSTRAINT wargame_boundaries_verdict_check CHECK (
  verdict IN ('pass','proved_config','fail_open','conditional','insufficient')
);

ALTER TABLE wargame_certificates
  ADD COLUMN IF NOT EXISTS key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE wargame_certificates
  ADD COLUMN IF NOT EXISTS corroboration JSONB NOT NULL DEFAULT '{}'::jsonb;
