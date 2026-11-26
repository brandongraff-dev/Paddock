-- 063: provable containment P3, push targets and their job queue (docs/ASSURANCE_P3.md 5.8, 6.4).

CREATE TABLE IF NOT EXISTS attest_push_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  publication_id UUID,
  kind TEXT NOT NULL DEFAULT 'file' CHECK (kind IN ('file', 's3', 'github_pages')),
  name TEXT NOT NULL DEFAULT '',
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  secret_blob TEXT NOT NULL DEFAULT '',                   -- sealed push credentials; never returned by the API
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  last_push_at TIMESTAMPTZ,
  last_ok_at TIMESTAMPTZ,
  last_error TEXT,
  last_digest TEXT NOT NULL DEFAULT '',
  fail_count INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS attest_push_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  target_id UUID NOT NULL DEFAULT gen_random_uuid(),
  seq BIGINT NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'done', 'dead')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_attest_push_due ON attest_push_jobs (tenant_id, state, next_attempt_at);
