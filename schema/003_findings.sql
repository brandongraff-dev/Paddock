-- Findings: individual issues attached to assets.
-- Chains: composite findings that correlate multiple individual findings
-- into a higher-severity narrative ("exposed .git + outdated lib + no WAF").

CREATE TABLE IF NOT EXISTS findings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  rule_id       TEXT NOT NULL,
  rule_source   TEXT NOT NULL CHECK (rule_source IN (
                  'nuclei', 'cve_match', 'policy', 'chain', 'secret_scan',
                  'tls_check', 'header_check', 'exposed_file', 'manual'
                )),
  severity      TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  title         TEXT NOT NULL,
  description   TEXT NOT NULL,
  impact        TEXT,
  remediation   TEXT,
  evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
  cvss          NUMERIC(3,1),
  epss          NUMERIC(4,3),
  "references"  TEXT[] DEFAULT ARRAY[]::TEXT[],
  status        TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'triaged', 'false_positive', 'accepted_risk', 'fixed', 'wontfix')),
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  assigned_to   TEXT,
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (asset_id, rule_id, rule_source)
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen DESC);

CREATE TABLE IF NOT EXISTS finding_chains (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chain_rule_id        TEXT NOT NULL,
  severity             TEXT NOT NULL,
  title                TEXT NOT NULL,
  description          TEXT NOT NULL,
  impact_narrative     TEXT,
  blast_radius_score   NUMERIC(5,2),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finding_ids          UUID[] NOT NULL,
  anchor_asset_id      UUID REFERENCES assets(id) ON DELETE CASCADE,
  metadata             JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_chains_anchor ON finding_chains(anchor_asset_id);
CREATE INDEX IF NOT EXISTS idx_chains_severity ON finding_chains(severity);
