-- Audit: every outbound request and every scan job gets logged.
-- This is what distinguishes a scanner you can show someone from a script
-- that silently touches the internet.

CREATE TABLE IF NOT EXISTS outbound_log (
  id              BIGSERIAL PRIMARY KEY,
  worker          TEXT NOT NULL,
  target          TEXT NOT NULL,
  tool            TEXT NOT NULL,
  method          TEXT,
  request_summary TEXT,
  response_code   INTEGER,
  scope_matched   BOOLEAN NOT NULL,
  scope_entry_id  INTEGER REFERENCES scope_entries(id),
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  duration_ms     INTEGER,
  bytes_in        BIGINT,
  bytes_out       BIGINT,
  error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_outbound_target ON outbound_log(target, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbound_ts ON outbound_log(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbound_worker ON outbound_log(worker, started_at DESC);

CREATE TABLE IF NOT EXISTS scans (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind            TEXT NOT NULL,
  target          TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
  priority        SMALLINT NOT NULL DEFAULT 5,
  queued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  worker_id       TEXT,
  config          JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_summary  JSONB NOT NULL DEFAULT '{}'::jsonb,
  error           TEXT,
  parent_scan_id  UUID REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status, queued_at);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, queued_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_parent ON scans(parent_scan_id);

CREATE TABLE IF NOT EXISTS schedules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,
  scan_kind       TEXT NOT NULL,
  target_scope    TEXT NOT NULL,  -- which scope entries to scan
  cron            TEXT NOT NULL,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  last_run_at     TIMESTAMPTZ,
  next_run_at     TIMESTAMPTZ,
  config          JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run_at) WHERE enabled;
