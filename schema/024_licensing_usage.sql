-- 024: editions/licensing + usage metering (see orchestrator/app/licensing.py,
-- orchestrator/app/routers/licensing.py and docs/EDITIONS.md).
--
-- No license row = Community edition: everything that exists today stays free.
-- License keys are Ed25519-signed JSON verified OFFLINE against the vendor
-- public key(s); the private key never lives in this repo or this database.

-- Uploaded license keys. The newest non-removed row is the active one; older
-- rows are kept for history (who uploaded what, when).
CREATE TABLE IF NOT EXISTS license_keys (
  id            BIGSERIAL PRIMARY KEY,
  license_id    TEXT NOT NULL,                 -- payload.license_id (vendor-assigned)
  edition       TEXT NOT NULL
                CHECK (edition IN ('community','team','enterprise','edge')),
  licensee      TEXT,
  key_text      TEXT NOT NULL,                 -- the full signed key (not a secret: it is
                                               -- useless without the vendor signature check)
  expires_at    TIMESTAMPTZ,
  uploaded_by   TEXT,
  uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  removed_at    TIMESTAMPTZ                    -- set when an admin reverts to Community
);
CREATE INDEX IF NOT EXISTS idx_license_keys_active
  ON license_keys (uploaded_at DESC) WHERE removed_at IS NULL;

-- One usage snapshot per UTC day, for billing/true-up. Written by
-- POST /v1/usage/snapshot (cron-able) and lazily by GET /v1/usage.
CREATE TABLE IF NOT EXISTS usage_snapshots (
  day               DATE PRIMARY KEY,
  monitored_assets  INT NOT NULL DEFAULT 0,
  total_assets      INT NOT NULL DEFAULT 0,
  sites             INT,                       -- NULL = otdiscovery unreachable that day
  sensors           INT,
  fleet_agents      INT NOT NULL DEFAULT 0,
  users             INT NOT NULL DEFAULT 0,
  scans_month       INT NOT NULL DEFAULT 0,
  integrations      INT NOT NULL DEFAULT 0,
  edition           TEXT NOT NULL DEFAULT 'community',
  license_id        TEXT,
  detail            JSONB NOT NULL DEFAULT '{}'::jsonb,
  taken_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
