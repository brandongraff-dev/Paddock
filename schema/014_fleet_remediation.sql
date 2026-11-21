-- Fleet agents (host-local, report to the orchestrator), GATED defensive
-- enforcement (propose->approve->apply, host-only, reversible, audited),
-- auto-remediation PRs (proposed never merged, constrained + double-checked),
-- and IoT/OT asset kinds. Applied after 001-013.

-- IoT/OT + network asset kinds (recreate the assets.kind CHECK additively)
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_kind_check;
ALTER TABLE assets ADD CONSTRAINT assets_kind_check CHECK (kind IN (
  'org','domain','subdomain','ipv4','ipv6','port','service','technology',
  'certificate','endpoint','repository','secret_candidate','cloud_account',
  'cloud_resource','iot_device','ot_device','network_segment'
));

-- =====================================================================
-- Fleet agents + inventory
-- =====================================================================
CREATE TABLE IF NOT EXISTS fleet_agents (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname      TEXT NOT NULL,
  platform      TEXT,                     -- linux/windows/macos
  agent_version TEXT,
  labels        TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  capabilities  TEXT[] NOT NULL DEFAULT ARRAY['inventory']::TEXT[],  -- inventory, block, quarantine
  status        TEXT NOT NULL DEFAULT 'enrolled' CHECK (status IN ('enrolled','online','stale','offline','revoked')),
  token_prefix  TEXT UNIQUE,
  token_hash    TEXT,                     -- sha256 of the enrollment token; raw never stored
  enrolled_by   TEXT,
  enrolled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen     TIMESTAMPTZ,
  UNIQUE (hostname)
);

CREATE TABLE IF NOT EXISTS agent_inventory (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id     UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  os_info      JSONB NOT NULL DEFAULT '{}'::jsonb,
  packages     JSONB NOT NULL DEFAULT '[]'::jsonb,
  listeners    JSONB NOT NULL DEFAULT '[]'::jsonb,   -- listening ports/services
  posture      JSONB NOT NULL DEFAULT '{}'::jsonb    -- firewall on, patch level, etc.
);
CREATE INDEX IF NOT EXISTS idx_agent_inv_agent ON agent_inventory(agent_id, collected_at DESC);

-- =====================================================================
-- Gated enforcement actions. Host-local only. propose -> approve -> apply.
-- Dry-run by default. Reversible. Every transition is audit-logged.
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_actions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id      UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  action_type   TEXT NOT NULL CHECK (action_type IN (
                  'block_ip','block_domain','quarantine_file','firewall_rule','revert')),
  target        TEXT NOT NULL,            -- the IP/domain/path to act on (host-local effect)
  reason        TEXT,
  indicator_id  UUID REFERENCES ti_indicators(id) ON DELETE SET NULL,
  finding_id    UUID REFERENCES findings(id) ON DELETE SET NULL,
  dry_run       BOOLEAN NOT NULL DEFAULT TRUE,
  status        TEXT NOT NULL DEFAULT 'proposed'
                  CHECK (status IN ('proposed','approved','applied','failed','reverted','denied')),
  requested_by  TEXT,
  approved_by   TEXT,                     -- required to leave 'proposed'; four-eyes
  result        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at    TIMESTAMPTZ,
  applied_at    TIMESTAMPTZ,
  revert_of     UUID REFERENCES agent_actions(id)
);
CREATE INDEX IF NOT EXISTS idx_agent_actions_agent ON agent_actions(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_actions_status ON agent_actions(status);

-- =====================================================================
-- Auto-remediation PRs. Proposed, NEVER auto-merged. Constrained change
-- classes. Each carries a verifier report + the prompt-injection checks.
-- =====================================================================
CREATE TABLE IF NOT EXISTS remediations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id      UUID REFERENCES findings(id) ON DELETE SET NULL,
  repo            TEXT,
  kind            TEXT NOT NULL CHECK (kind IN (
                   'dependency_bump','security_header','config_fix','tls_fix','dotfile_block')),
  summary         TEXT NOT NULL,
  base_branch     TEXT,
  head_branch     TEXT,
  diff            TEXT,                   -- the proposed unified diff
  status          TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN (
                   'proposed','verifying','verified','rejected','pr_open','merged','failed')),
  -- deterministic diff-gate result + the adversarial LLM re-check + injection scan
  verifier_report JSONB NOT NULL DEFAULT '{}'::jsonb,
  injection_checks JSONB NOT NULL DEFAULT '{}'::jsonb,
  pr_url          TEXT,
  pr_number       INTEGER,
  created_by      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  verified_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status);
