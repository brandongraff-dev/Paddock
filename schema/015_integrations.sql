-- 015: integrations framework (shared contract; see orchestrator/app/integrations)

CREATE TABLE IF NOT EXISTS integrations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind            TEXT NOT NULL,                       -- connector kind, e.g. 'slack'
  name            TEXT NOT NULL,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  config          JSONB NOT NULL DEFAULT '{}'::jsonb,  -- NON-secret settings only
  secrets         TEXT,                                -- AES-GCM blob (app.integrations.secrets)
  events          TEXT[] NOT NULL DEFAULT '{}',        -- subscribed event types (EVENT_TYPES)
  min_severity    TEXT NOT NULL DEFAULT 'low'
                  CHECK (min_severity IN ('info','low','medium','high','critical')),
  filters         JSONB NOT NULL DEFAULT '{}'::jsonb,  -- optional: asset tags, owners, sites
  allow_private   BOOLEAN NOT NULL DEFAULT FALSE,      -- deliberate opt-in for LAN targets
  inbound_token   TEXT UNIQUE,                         -- for two-way sync callbacks
  created_by      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_ok_at      TIMESTAMPTZ,
  last_error      TEXT,
  last_error_at   TIMESTAMPTZ,
  UNIQUE (kind, name)
);

CREATE TABLE IF NOT EXISTS integration_deliveries (
  id              BIGSERIAL PRIMARY KEY,
  integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  event_id        TEXT NOT NULL,
  event_type      TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('pending','sent','failed','dead','skipped')),
  attempts        INT NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ,
  status_code     INT,
  detail          TEXT,
  payload         JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (integration_id, event_id)                    -- idempotency
);
CREATE INDEX IF NOT EXISTS idx_integration_deliveries_due
  ON integration_deliveries (status, next_attempt_at);

-- Two-way sync: which external object mirrors which finding.
CREATE TABLE IF NOT EXISTS integration_links (
  id              BIGSERIAL PRIMARY KEY,
  integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  finding_id      UUID NOT NULL,
  external_id     TEXT NOT NULL,
  external_url    TEXT,
  external_status TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (integration_id, finding_id),
  UNIQUE (integration_id, external_id)
);
