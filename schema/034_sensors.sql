-- 034: Sentry sensor enrollment + health + idempotent upload accounting.
--
--   sensor_enroll_tokens  one-time, short-lived enrollment tokens (hashed)
--   sensors               enrolled sensors: per-sensor credential (hashed),
--                         site, version, interfaces, latest health, liveness
--   sensor_batches        upload batch ids, so a retried batch is never
--                         counted twice (purged by the orchestrator monitor)
--
-- Tenancy: 099_tenancy.sql adds tenant_id + FORCEd RLS to all three tables
-- when it is re-applied after this file. A sensor presenting its credential
-- does not yet know its tenant, so (like api_keys) the credential lookup runs
-- under `app.auth_lookup = 'on'`; the extra SELECT-only policies below allow
-- exactly that read and nothing else (writes stay tenant-scoped).

CREATE TABLE IF NOT EXISTS sensor_enroll_tokens (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_prefix   TEXT NOT NULL UNIQUE,           -- shown in the UI; not secret
  token_hash     TEXT NOT NULL,                  -- sha256 of the full token
  site           TEXT NOT NULL,
  label          TEXT,
  created_by     TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at     TIMESTAMPTZ NOT NULL,
  used_at        TIMESTAMPTZ,                    -- single use: set once, atomically
  used_by_sensor UUID,
  revoked_at     TIMESTAMPTZ,
  revoked_by     TEXT
);

CREATE TABLE IF NOT EXISTS sensors (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name              TEXT NOT NULL,
  site              TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  cred_prefix       TEXT NOT NULL UNIQUE,
  cred_hash         TEXT NOT NULL,               -- sha256 of the full credential
  version           TEXT,
  hostname          TEXT,
  interfaces        JSONB NOT NULL DEFAULT '[]'::jsonb,
  token_id          UUID REFERENCES sensor_enroll_tokens(id) ON DELETE SET NULL,
  enrolled_by       TEXT,
  enrolled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ,                 -- any authenticated contact
  last_heartbeat_at TIMESTAMPTZ,
  last_upload_at    TIMESTAMPTZ,                 -- last batch fully ingested
  health            JSONB NOT NULL DEFAULT '{}'::jsonb,
  online            BOOLEAN NOT NULL DEFAULT TRUE,
  offline_since     TIMESTAMPTZ,
  silent_after_s    INTEGER NOT NULL DEFAULT 300 CHECK (silent_after_s BETWEEN 30 AND 86400),
  batches_total     BIGINT NOT NULL DEFAULT 0,
  flows_total       BIGINT NOT NULL DEFAULT 0,
  duplicates_total  BIGINT NOT NULL DEFAULT 0,
  revoked_at        TIMESTAMPTZ,
  revoked_by        TEXT
);
CREATE INDEX IF NOT EXISTS idx_sensors_liveness ON sensors (status, online, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_sensors_site ON sensors (site);
CREATE INDEX IF NOT EXISTS idx_sensor_tokens_open ON sensor_enroll_tokens (expires_at)
  WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS sensor_batches (
  sensor_id  UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  batch_id   TEXT NOT NULL,
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  done_at    TIMESTAMPTZ,                         -- NULL = claimed, not yet ingested
  flows      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (sensor_id, batch_id)
);
CREATE INDEX IF NOT EXISTS idx_sensor_batches_claimed ON sensor_batches (claimed_at);

-- Credential lookup across tenants (see header). SELECT only.
DROP POLICY IF EXISTS sensor_auth_lookup ON sensors;
CREATE POLICY sensor_auth_lookup ON sensors FOR SELECT
  USING (current_setting('app.auth_lookup', true) = 'on');
DROP POLICY IF EXISTS sensor_token_auth_lookup ON sensor_enroll_tokens;
CREATE POLICY sensor_token_auth_lookup ON sensor_enroll_tokens FOR SELECT
  USING (current_setting('app.auth_lookup', true) = 'on');
