-- 041: Provable Containment, P2: agent v2 for servers. See docs/ASSURANCE_P2.md section 3.
--
--   fleet_enroll_tokens  per-tenant enrollment tokens ('fet_<prefix>_<secret>'; only the sha256 is stored).
--                        Single use by default; max_uses <= 50 for cloud-init fleets (the app caps the ttl).
--   fleet_agent_keys     one Ed25519 key per enrolled agent (active | rotated | revoked) and the replay
--                        counter (last_seq) the ingest claims atomically.
--   fleet_agents         + liveness, identity, node_ref, legacy flag, revocation, ingest counters.
--                        Agents that have no key row are marked legacy (decision O3): they keep their rows
--                        and history and get 403 re_enroll_required on every agent route.
--   agent_posture        the signed posture envelopes (raw payload bytes kept so P3 can re-verify them).
--   reach_node_facts     compact per-node facts the host invariants read (written by the host_fw builder).
--
-- Runs BEFORE 099_tenancy.sql, which adds the tenant_id default / FK / RLS / tenant_isolation policy to every
-- table (and is re-applied by the migration runner after this file). tenant_id is declared here so UNIQUE
-- constraints can name it: every UNIQUE below includes it, except fleet_enroll_tokens.token_prefix, which is
-- the credential lookup handle (resolved before the tenant is known; random, 12 hex) and is therefore global.
-- Columns are plain and carry defaults, and no NOT NULL column without a default has a length/regex CHECK, so
-- the generic isolation-sweep row generator can fill them.

-- ---------------------------------------------------------------------------
-- Enrollment tokens
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fleet_enroll_tokens (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  token_prefix TEXT NOT NULL UNIQUE,             -- shown in the UI, not secret; the lookup handle (global)
  token_hash   TEXT NOT NULL,                    -- sha256 of the full token; the token itself is never stored
  label        TEXT NOT NULL DEFAULT '',
  labels       JSONB NOT NULL DEFAULT '[]'::jsonb,   -- labels given to the agents this token enrolls
  max_uses     INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 50),
  uses         INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
  for_agent    UUID,                             -- re-key token: rebinds this existing agent (history kept)
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL,
  revoked_at   TIMESTAMPTZ,
  revoked_by   TEXT,
  CONSTRAINT fleet_enroll_tokens_uses_le_max CHECK (uses <= max_uses)
);
CREATE INDEX IF NOT EXISTS idx_fleet_enroll_tokens_open
  ON fleet_enroll_tokens (tenant_id, expires_at) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Agent keys
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fleet_agent_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id      UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  key_id        TEXT NOT NULL,                   -- hex(sha256(pub32))[:32]
  public_key    BYTEA NOT NULL DEFAULT '',       -- raw 32 bytes; the app validates it, an empty one verifies nothing
  alg           TEXT NOT NULL DEFAULT 'ed25519' CHECK (alg IN ('ed25519')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'revoked')),
  last_seq      BIGINT NOT NULL DEFAULT 0 CHECK (last_seq >= 0),   -- highest envelope seq accepted
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retired_at    TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ,
  revoke_reason TEXT,
  CONSTRAINT fleet_agent_keys_pub_len CHECK (octet_length(public_key) IN (0, 32)),
  UNIQUE (tenant_id, key_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_agent_keys_agent ON fleet_agent_keys (tenant_id, agent_id, status);
-- An agent has at most one usable key. Rotation and re-keying must retire the old key BEFORE the new
-- one becomes active (the app does it in one transaction); two active keys are a hard error.
CREATE UNIQUE INDEX IF NOT EXISTS uq_fleet_agent_keys_one_active
  ON fleet_agent_keys (tenant_id, agent_id) WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- fleet_agents: v2 columns
-- ---------------------------------------------------------------------------
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS silent_after_s INTEGER NOT NULL DEFAULT 300
  CHECK (silent_after_s BETWEEN 30 AND 86400);
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS online BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS offline_since TIMESTAMPTZ;
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS identity JSONB NOT NULL DEFAULT '{}'::jsonb;  -- hostname, ips, machine_id_hash, basis claimed|corroborated
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS node_ref TEXT;                                -- 'agent:<uuid>' or 'asset:<uuid>' once corroborated
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS legacy BOOLEAN NOT NULL DEFAULT FALSE;        -- v1 agent without a key (O3)
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS revoked_by TEXT;
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS rejected_total BIGINT NOT NULL DEFAULT 0;
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS last_posture_at TIMESTAMPTZ;
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS last_posture_seq BIGINT NOT NULL DEFAULT 0;

-- Credential lookup across tenants for the agent principal (X-Agent-Token -> token_prefix). SELECT only;
-- writes stay tenant-scoped. Same shape as sensor_auth_lookup (034).
DROP POLICY IF EXISTS fleet_agent_auth_lookup ON fleet_agents;
CREATE POLICY fleet_agent_auth_lookup ON fleet_agents FOR SELECT
  USING (current_setting('app.auth_lookup', true) = 'on');
-- Same for the enrollment token, which is resolved before the tenant is known.
DROP POLICY IF EXISTS fleet_token_auth_lookup ON fleet_enroll_tokens;
CREATE POLICY fleet_token_auth_lookup ON fleet_enroll_tokens FOR SELECT
  USING (current_setting('app.auth_lookup', true) = 'on');

-- ---------------------------------------------------------------------------
-- Signed posture history
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_posture (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id       UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  key_id         TEXT NOT NULL DEFAULT '',
  seq            BIGINT NOT NULL DEFAULT 0,
  schema_version INTEGER NOT NULL DEFAULT 2,
  collected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),   -- the agent's issued_at
  received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),   -- the server's clock
  header         JSONB NOT NULL DEFAULT '{}'::jsonb,   -- the signed envelope header (everything but payload_b64, sig)
  payload_raw    BYTEA NOT NULL DEFAULT '',            -- the exact payload bytes, so the signature stays re-verifiable
  payload_sha256 TEXT NOT NULL DEFAULT '',
  signature      BYTEA NOT NULL DEFAULT '',
  -- Defaults to FALSE on purpose: a row is only "signed" when the ingest says so after verifying the
  -- signature. (docs/ASSURANCE_P2.md writes DEFAULT TRUE; the safe direction wins, see WP1 report.)
  signed         BOOLEAN NOT NULL DEFAULT FALSE,
  size_bytes     INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, agent_id, key_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_agent_posture_agent ON agent_posture (tenant_id, agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_posture_received ON agent_posture (received_at);

-- ---------------------------------------------------------------------------
-- Compact per-node facts for the invariants (about 1 KB per row; replaced per source by the builder)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reach_node_facts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  node_ref    TEXT NOT NULL,
  source      TEXT NOT NULL DEFAULT '',
  tier        TEXT NOT NULL DEFAULT 'configured' CHECK (tier IN ('declared', 'configured', 'observed', 'tested')),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  digest      TEXT NOT NULL DEFAULT '',
  facts       JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, node_ref, source)
);
CREATE INDEX IF NOT EXISTS idx_reach_node_facts_source ON reach_node_facts (tenant_id, source);

-- ---------------------------------------------------------------------------
-- O3, hard cut: every agent that exists without a key is a v1 agent. It keeps its row and history, but the
-- agent principal refuses it (403 re_enroll_required) until an admin mints a re-key token (for_agent).
-- Idempotent: an agent enrolled through v2 always has a key row in the same transaction, so a re-run
-- marks nothing new.
--
-- The UPDATE runs once per tenant with app.tenant_id set (transaction-local), so it also works when the
-- migration owner is a plain table owner that FORCE ROW LEVEL SECURITY (099) applies to, instead of
-- silently matching no rows. On a fresh database `tenants` does not exist yet (099 creates it) and there
-- are no agents either.
-- ---------------------------------------------------------------------------
DO $$
DECLARE t record;
BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'public' AND table_name = 'fleet_agents' AND column_name = 'tenant_id')
     AND EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'public' AND table_name = 'fleet_agent_keys' AND column_name = 'tenant_id') THEN
    FOR t IN SELECT id FROM tenants LOOP
      PERFORM set_config('app.tenant_id', t.id::text, true);
      UPDATE fleet_agents SET legacy = TRUE
       WHERE legacy = FALSE
         AND NOT EXISTS (SELECT 1 FROM fleet_agent_keys k WHERE k.agent_id = fleet_agents.id);
    END LOOP;
    PERFORM set_config('app.tenant_id', '', true);
  ELSE
    UPDATE fleet_agents SET legacy = TRUE
     WHERE legacy = FALSE
       AND NOT EXISTS (SELECT 1 FROM fleet_agent_keys k WHERE k.agent_id = fleet_agents.id);
  END IF;
END $$;
