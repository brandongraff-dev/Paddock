-- Tier 2: TLS posture grading, subdomain-takeover detection,
-- ownership mapping + ticketing/SLA, and continuous-monitoring schedules.
-- Applied after 001-007.

-- Allow the two new finding sources.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_rule_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_rule_source_check CHECK (rule_source IN (
  'nuclei','cve_match','policy','chain','secret_scan','tls_check',
  'header_check','exposed_file','manual','takeover','tls_grade'
));

-- =====================================================================
-- TLS posture grades (one current grade per asset; history optional)
-- =====================================================================
CREATE TABLE IF NOT EXISTS tls_grades (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id      UUID REFERENCES assets(id) ON DELETE CASCADE,
  host          TEXT NOT NULL,
  grade         TEXT NOT NULL CHECK (grade IN ('A+','A','B','C','D','E','F','T')),  -- T = trust/validation issue
  score         SMALLINT NOT NULL CHECK (score BETWEEN 0 AND 100),
  protocols     JSONB NOT NULL DEFAULT '[]'::jsonb,   -- e.g. ["TLS1.3","TLS1.2","TLS1.0"]
  weak_ciphers  JSONB NOT NULL DEFAULT '[]'::jsonb,
  issues        JSONB NOT NULL DEFAULT '[]'::jsonb,   -- ["TLS1.0 enabled","cert expires in 15d",...]
  cert_expires  TIMESTAMPTZ,
  graded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (asset_id)
);

CREATE INDEX IF NOT EXISTS idx_tls_grades_grade ON tls_grades(grade);
CREATE INDEX IF NOT EXISTS idx_tls_grades_host ON tls_grades(host);

-- =====================================================================
-- Ownership mapping: pattern -> team
-- =====================================================================
CREATE TABLE IF NOT EXISTS asset_owners (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  -- match: {kinds:[...], value_regex:"", cidr:"", metadata_env:"", tag:""} (all optional, AND-ed)
  match       JSONB NOT NULL DEFAULT '{}'::jsonb,
  team        TEXT NOT NULL,
  contact     TEXT,                -- email / slack handle
  priority    SMALLINT NOT NULL DEFAULT 100,  -- lower wins when several rules match
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_owners_pri ON asset_owners(enabled, priority);

-- =====================================================================
-- SLA policy: severity -> hours-to-fix
-- =====================================================================
CREATE TABLE IF NOT EXISTS sla_policies (
  severity  TEXT PRIMARY KEY CHECK (severity IN ('info','low','medium','high','critical')),
  hours     INTEGER NOT NULL
);
INSERT INTO sla_policies (severity, hours) VALUES
  ('critical', 24), ('high', 72), ('medium', 168), ('low', 720), ('info', 0)
ON CONFLICT (severity) DO NOTHING;

-- =====================================================================
-- Tickets: a finding/chain/path routed to an owner with an SLA clock
-- =====================================================================
CREATE TABLE IF NOT EXISTS tickets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id      UUID REFERENCES findings(id) ON DELETE CASCADE,
  chain_id        UUID REFERENCES finding_chains(id) ON DELETE SET NULL,
  attack_path_id  UUID REFERENCES attack_paths(id) ON DELETE SET NULL,
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  owner_team      TEXT,
  contact         TEXT,
  system          TEXT NOT NULL DEFAULT 'internal' CHECK (system IN ('internal','webhook','github','jira')),
  external_id     TEXT,
  external_url    TEXT,
  status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','acknowledged','in_progress','resolved','closed','wontfix')),
  sla_hours       INTEGER,
  sla_due         TIMESTAMPTZ,
  breached        BOOLEAN NOT NULL DEFAULT FALSE,
  opened_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at       TIMESTAMPTZ,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (finding_id)   -- one ticket per finding
);

CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status, severity);
CREATE INDEX IF NOT EXISTS idx_tickets_team ON tickets(owner_team);
CREATE INDEX IF NOT EXISTS idx_tickets_sla ON tickets(sla_due) WHERE status NOT IN ('resolved','closed','wontfix');
CREATE INDEX IF NOT EXISTS idx_tickets_breached ON tickets(breached) WHERE breached;

-- =====================================================================
-- Continuous monitoring: extend the existing schedules table (004).
-- =====================================================================
ALTER TABLE schedules ADD COLUMN IF NOT EXISTS last_status  TEXT;
ALTER TABLE schedules ADD COLUMN IF NOT EXISTS created_by   TEXT;
ALTER TABLE schedules ADD COLUMN IF NOT EXISTS last_scan_id UUID;
