-- Universal ingest: per-source ingest tokens + an ingest log.
-- Applied after 001-025 (026 belongs to another workstream). Additive only.
-- tenant_id + RLS arrive from 099_tenancy.sql, which the migration runner
-- re-applies after every migration.
--
-- A "source" is one external tool/pipeline allowed to POST /v1/ingest. It gets
-- a token scoped to ingest ONLY (no other API capability). The token is shown
-- once; only its SHA-256 is stored.

CREATE TABLE IF NOT EXISTS ingest_sources (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name               TEXT NOT NULL CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  description        TEXT,
  token_hash         TEXT NOT NULL,                  -- sha256(secret), hex
  token_prefix       TEXT NOT NULL,                  -- first chars of the secret, for display
  default_project    TEXT,                           -- repo/project/asset findings attach to when the file names none
  allowed_formats    TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],   -- empty = any supported format
  rate_limit_per_min INTEGER NOT NULL DEFAULT 60 CHECK (rate_limit_per_min BETWEEN 1 AND 6000),
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  created_by         TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rotated_at         TIMESTAMPTZ,
  revoked_at         TIMESTAMPTZ,
  revoked_by         TEXT,
  last_used_at       TIMESTAMPTZ,
  ingest_count       BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ingest_sources_created ON ingest_sources(created_at DESC);

CREATE TABLE IF NOT EXISTS ingest_log (
  id                BIGSERIAL PRIMARY KEY,
  source_id         UUID REFERENCES ingest_sources(id) ON DELETE SET NULL,
  source_name       TEXT NOT NULL,                   -- survives source deletion
  actor             TEXT NOT NULL,                   -- 'ingest:<source>' or the API-key actor
  format            TEXT,                            -- detected format (NULL when undetectable)
  status            TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'rejected', 'dry_run')),
  http_status       INTEGER,
  findings_new      INTEGER NOT NULL DEFAULT 0,
  findings_updated  INTEGER NOT NULL DEFAULT 0,
  components        INTEGER NOT NULL DEFAULT 0,
  assets            INTEGER NOT NULL DEFAULT 0,
  skipped           INTEGER NOT NULL DEFAULT 0,
  duplicates        INTEGER NOT NULL DEFAULT 0,
  suppressed        INTEGER NOT NULL DEFAULT 0,
  errors            JSONB NOT NULL DEFAULT '[]'::jsonb,   -- capped list of {where, message}
  bytes             BIGINT NOT NULL DEFAULT 0,
  sha256            TEXT,
  project           TEXT,
  client_ip         TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ingest_log_created ON ingest_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ingest_log_source ON ingest_log(source_id, created_at DESC);
