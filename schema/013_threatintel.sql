-- Threat-intel fusion: ingest STIX 2.1 / poll TAXII 2.1, store IOCs, and match
-- them against the owner's own assets + findings (defensive: "is any of my
-- surface a known-bad indicator / does it touch known threat infrastructure").
-- Applied after 001-012.

-- new finding source for an asset/finding that matches a threat indicator
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_rule_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_rule_source_check CHECK (rule_source IN (
  'nuclei','cve_match','policy','chain','secret_scan','tls_check','header_check',
  'exposed_file','manual','takeover','tls_grade','sca','sast','threat_intel'
));

CREATE TABLE IF NOT EXISTS ti_feeds (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('taxii','stix_url','stix_upload','manual')),
  url          TEXT,                 -- TAXII server root / STIX bundle URL (user-configured)
  collection   TEXT,                 -- TAXII collection id
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  last_poll    TIMESTAMPTZ,
  last_status  TEXT,
  indicator_count INTEGER NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS ti_indicators (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id      TEXT UNIQUE,          -- STIX indicator id if from a feed
  type         TEXT NOT NULL CHECK (type IN ('ipv4','ipv6','domain','url','file_sha256','file_md5','email','cidr')),
  value        TEXT NOT NULL,
  pattern      TEXT,                 -- raw STIX pattern
  labels       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],   -- malicious-activity, c2, phishing, ...
  malware      TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  threat_actor TEXT,
  confidence   SMALLINT NOT NULL DEFAULT 50,
  valid_from   TIMESTAMPTZ,
  valid_until  TIMESTAMPTZ,
  feed_id      UUID REFERENCES ti_feeds(id) ON DELETE SET NULL,
  source       TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (type, value)
);

CREATE INDEX IF NOT EXISTS idx_ti_ind_type_val ON ti_indicators(type, value);
CREATE INDEX IF NOT EXISTS idx_ti_ind_feed ON ti_indicators(feed_id);

CREATE TABLE IF NOT EXISTS ti_matches (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_id  UUID NOT NULL REFERENCES ti_indicators(id) ON DELETE CASCADE,
  subject_type  TEXT NOT NULL CHECK (subject_type IN ('asset','finding','endpoint','ip','domain')),
  subject_id    UUID,
  matched_value TEXT NOT NULL,
  severity      TEXT NOT NULL DEFAULT 'high' CHECK (severity IN ('info','low','medium','high','critical')),
  finding_id    UUID REFERENCES findings(id) ON DELETE SET NULL,
  matched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (indicator_id, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_ti_matches_indicator ON ti_matches(indicator_id);
CREATE INDEX IF NOT EXISTS idx_ti_matches_subject ON ti_matches(subject_type, subject_id);
