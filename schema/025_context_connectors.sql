-- 025: context SOURCE connectors (AWS, Defender/Intune, CrowdStrike, ServiceNow
-- CMDB) + network ACTION connectors (UniFi, Meraki) for Sentry quarantine.
-- Applied after 015_integrations.sql. Purely additive.

-- =====================================================================
-- SOURCE sync bookkeeping: one row per scheduled/manual pull. Drives the
-- "last sync" column on the Integrations page and the scheduler's interval.
-- =====================================================================
CREATE TABLE IF NOT EXISTS integration_sync_runs (
  id              BIGSERIAL PRIMARY KEY,
  integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  trigger         TEXT NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule','manual')),
  status          TEXT NOT NULL DEFAULT 'running'
                  CHECK (status IN ('running','ok','error','abandoned')),
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at     TIMESTAMPTZ,
  counts          JSONB NOT NULL DEFAULT '{}'::jsonb,   -- assets/edges/findings/owners/merged
  detail          TEXT                                  -- NEVER contains secrets
);
CREATE INDEX IF NOT EXISTS idx_integration_sync_runs_recent
  ON integration_sync_runs (integration_id, started_at DESC);
-- At most one in-flight sync per integration (multi-replica safe claim).
CREATE UNIQUE INDEX IF NOT EXISTS uq_integration_sync_running
  ON integration_sync_runs (integration_id) WHERE status = 'running';

-- =====================================================================
-- Network quarantine through the EXISTING fleet approve gate.
--
-- A network action is an `agent_actions` row with NO agent (it is executed by
-- the orchestrator through an ACTION integration, never by a host agent) and
-- an `integration_id`. The propose -> approve (admin, four-eyes,
-- apply_for_real) -> apply -> revert state machine, dry-run default and audit
-- trail are exactly the fleet ones. Agents never see these rows: heartbeat
-- only returns actions WHERE agent_id = <that agent>.
-- =====================================================================
ALTER TABLE agent_actions ALTER COLUMN agent_id DROP NOT NULL;
ALTER TABLE agent_actions
  ADD COLUMN IF NOT EXISTS integration_id UUID REFERENCES integrations(id) ON DELETE SET NULL;

ALTER TABLE agent_actions DROP CONSTRAINT IF EXISTS agent_actions_action_type_check;
ALTER TABLE agent_actions ADD CONSTRAINT agent_actions_action_type_check CHECK (action_type IN (
  'block_ip','block_domain','quarantine_file','firewall_rule','revert',
  'quarantine_device','release_device'
));

-- Host actions need an agent; network actions need an integration; a revert
-- row inherits its executor from the action it reverts.
ALTER TABLE agent_actions DROP CONSTRAINT IF EXISTS agent_actions_executor_check;
ALTER TABLE agent_actions ADD CONSTRAINT agent_actions_executor_check CHECK (
  agent_id IS NOT NULL OR integration_id IS NOT NULL OR revert_of IS NOT NULL
);
-- Network action types are never executed by a host agent.
ALTER TABLE agent_actions DROP CONSTRAINT IF EXISTS agent_actions_network_type_check;
ALTER TABLE agent_actions ADD CONSTRAINT agent_actions_network_type_check CHECK (
  action_type NOT IN ('quarantine_device','release_device') OR agent_id IS NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_actions_integration
  ON agent_actions (integration_id, status) WHERE integration_id IS NOT NULL;
