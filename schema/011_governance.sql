-- Governance + security foundation: identities, RBAC/ABAC, classification,
-- a tamper-evident (hash-chained) audit log, and data provenance.
-- This is the layer that turns the platform from a dashboard into a
-- system of record. Applied after 001-010.

-- =====================================================================
-- Identities + API keys + roles (RBAC)
-- =====================================================================
CREATE TABLE IF NOT EXISTS app_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username      TEXT NOT NULL UNIQUE,
  email         TEXT,
  display_name  TEXT,
  role          TEXT NOT NULL DEFAULT 'viewer'
                  CHECK (role IN ('viewer','analyst','admin','auditor')),
  -- clearance: the max classification this user may see (ABAC)
  clearance     TEXT NOT NULL DEFAULT 'internal'
                  CHECK (clearance IN ('public','internal','confidential','restricted')),
  pw_hash       TEXT,                 -- argon2/bcrypt; null = SSO-only
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS api_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID REFERENCES app_users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  prefix        TEXT NOT NULL,        -- first chars, shown in UI
  key_hash      TEXT NOT NULL,        -- sha256 of the full key; raw never stored
  scopes        TEXT[] NOT NULL DEFAULT ARRAY['read']::TEXT[],
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used     TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ,
  revoked       BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (prefix)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash) WHERE NOT revoked;

-- =====================================================================
-- Classification labels (ABAC). Column on the hot tables + a general
-- labels table for anything else.
-- =====================================================================
ALTER TABLE assets   ADD COLUMN IF NOT EXISTS classification TEXT NOT NULL DEFAULT 'internal'
  CHECK (classification IN ('public','internal','confidential','restricted'));
ALTER TABLE findings ADD COLUMN IF NOT EXISTS classification TEXT NOT NULL DEFAULT 'internal'
  CHECK (classification IN ('public','internal','confidential','restricted'));

-- =====================================================================
-- Tamper-evident audit log: append-only, hash-chained.
-- entry_hash = sha256(prev_hash || canonical(row)). Any edit/delete to a
-- past row breaks the chain, which the verify endpoint detects.
-- =====================================================================
CREATE TABLE IF NOT EXISTS audit_log (
  id            BIGSERIAL PRIMARY KEY,
  ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor         TEXT NOT NULL,            -- username or service name
  actor_role    TEXT,
  action        TEXT NOT NULL,            -- read|create|update|delete|login|export|verify|deny
  resource_type TEXT,
  resource_id   TEXT,
  method        TEXT,
  path          TEXT,
  status        INTEGER,
  classification TEXT,                    -- sensitivity of the data touched
  justification TEXT,                     -- purpose-based access reason
  ip            TEXT,
  request_id    TEXT,
  details       JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_hash     TEXT NOT NULL,
  entry_hash    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);

-- Revoke UPDATE/DELETE at the DB level for the app role (belt + braces with
-- the hash chain). The app connects as a role that can only INSERT/SELECT here.
-- (Applied by the orchestrator on startup if it holds the privilege.)

-- =====================================================================
-- Provenance / lineage: how the platform came to believe each fact.
-- =====================================================================
CREATE TABLE IF NOT EXISTS provenance (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type   TEXT NOT NULL CHECK (subject_type IN ('asset','finding','attack_path','sbom_component','ticket','anomaly')),
  subject_id     UUID NOT NULL,
  source_service TEXT NOT NULL,          -- which worker/service produced it
  source_detail  TEXT,                   -- e.g. 'crt.sh', 'nuclei:exposed-dotgit', 'osv.dev'
  method         TEXT,                   -- passive|active|intel|correlation|ml|import
  evidence       JSONB NOT NULL DEFAULT '{}'::jsonb,
  confidence     SMALLINT NOT NULL DEFAULT 100,
  recorded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_provenance_subject ON provenance(subject_type, subject_id);

-- Seed a default admin + bootstrap API key placeholder (the orchestrator
-- replaces the hash on first boot from an env secret; never ship a known key).
INSERT INTO app_users (username, display_name, role, clearance)
VALUES ('admin', 'Bootstrap Admin', 'admin', 'restricted')
ON CONFLICT (username) DO NOTHING;
