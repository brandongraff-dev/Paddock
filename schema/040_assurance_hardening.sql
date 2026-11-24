-- 040: hardening found by the P1 adversarial review (docs/ASSURANCE_P1.md section 12).
--
--   sensor_scopes            WHICH networks a Sentry sensor can actually see. Coverage may only
--                            be asserted for nodes inside a declared scope: a sensor that saw one
--                            flow to a cloud host does not see that host's other traffic.
--   assurance_state          + last_eval_doc_sha: hash of the graph document last evaluated, so a
--                            change that does not move graph_version (zone CIDRs, node attrs, asset
--                            metadata feeding labels) still triggers a re-evaluation.
--
-- Runs BEFORE 099_tenancy.sql (tenant_id/RLS added there). tenant_id declared so UNIQUE can name it.

CREATE TABLE IF NOT EXISTS sensor_scopes (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  sensor_id     UUID NOT NULL DEFAULT gen_random_uuid(),   -- sensors.id (no FK: sensors can be revoked/deleted)
  cidrs         TEXT[] NOT NULL DEFAULT '{}',
  set_by        TEXT,
  justification TEXT NOT NULL DEFAULT '',
  set_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, sensor_id)
);

ALTER TABLE assurance_state ADD COLUMN IF NOT EXISTS last_eval_doc_sha TEXT;
