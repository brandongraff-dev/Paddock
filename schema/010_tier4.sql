-- Tier 4: code reachability + SAST, and an adaptive ML risk/anomaly layer.
-- Reachability tells you WHICH dependency vulns are actually callable; SAST
-- finds first-party code weaknesses; the ML layer learns from analyst triage
-- to prioritize, and flags statistical anomalies in the surface. Detection /
-- analysis / prioritization only — never exploitation. Applied after 001-009.

-- new finding source: first-party static analysis
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_rule_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_rule_source_check CHECK (rule_source IN (
  'nuclei','cve_match','policy','chain','secret_scan','tls_check','header_check',
  'exposed_file','manual','takeover','tls_grade','sca','sast'
));

-- =====================================================================
-- Reachability: re-grade each dependency vuln by whether the vulnerable
-- symbol is actually reachable from first-party code.
-- =====================================================================
ALTER TABLE sbom_component_vulns
  ADD COLUMN IF NOT EXISTS reachability TEXT NOT NULL DEFAULT 'unknown'
    CHECK (reachability IN ('reachable','potential','unreachable','unknown')),
  ADD COLUMN IF NOT EXISTS reachable_symbol TEXT,
  ADD COLUMN IF NOT EXISTS call_path JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_sbom_vulns_reach ON sbom_component_vulns(reachability);

-- =====================================================================
-- SAST: first-party code weaknesses (taint/dataflow + pattern rules).
-- =====================================================================
CREATE TABLE IF NOT EXISTS code_findings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    UUID REFERENCES sca_projects(id) ON DELETE CASCADE,
  asset_id      UUID REFERENCES assets(id) ON DELETE SET NULL,
  finding_id    UUID REFERENCES findings(id) ON DELETE SET NULL,  -- unified mirror
  engine        TEXT NOT NULL DEFAULT 'semgrep',
  rule          TEXT NOT NULL,
  message       TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  file          TEXT NOT NULL,
  start_line    INTEGER,
  end_line      INTEGER,
  source        TEXT,                 -- taint source (e.g. request.args)
  sink          TEXT,                 -- dangerous sink (e.g. cursor.execute)
  dataflow      JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ordered source->sink steps
  cwe           TEXT,
  detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (project_id, rule, file, start_line)
);

CREATE INDEX IF NOT EXISTS idx_code_findings_project ON code_findings(project_id);
CREATE INDEX IF NOT EXISTS idx_code_findings_severity ON code_findings(severity);

-- =====================================================================
-- Adaptive ML: models, learned risk scores, anomalies.
-- =====================================================================
CREATE TABLE IF NOT EXISTS ml_models (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version            INTEGER NOT NULL,
  kind               TEXT NOT NULL CHECK (kind IN ('risk_ranker','anomaly_detector')),
  algo               TEXT NOT NULL,          -- e.g. gradient_boosting, isolation_forest, heuristic_prior
  trained_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  n_samples          INTEGER NOT NULL DEFAULT 0,
  metrics            JSONB NOT NULL DEFAULT '{}'::jsonb,   -- auc, precision@k, etc.
  feature_importance JSONB NOT NULL DEFAULT '{}'::jsonb,
  cold_start         BOOLEAN NOT NULL DEFAULT TRUE,        -- true until enough labels
  active             BOOLEAN NOT NULL DEFAULT FALSE,
  notes              TEXT,
  UNIQUE (kind, version)
);

CREATE INDEX IF NOT EXISTS idx_ml_models_active ON ml_models(kind, active);

-- One learned risk score per finding (0-100), with the feature vector + a
-- human-readable rationale (top contributing signals) for explainability.
CREATE TABLE IF NOT EXISTS ml_risk_scores (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id    UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  ml_risk       NUMERIC(5,2) NOT NULL,
  model_version INTEGER,
  features      JSONB NOT NULL DEFAULT '{}'::jsonb,
  rationale     JSONB NOT NULL DEFAULT '[]'::jsonb,   -- [{feature, contribution}]
  scored_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (finding_id)
);

CREATE INDEX IF NOT EXISTS idx_ml_risk ON ml_risk_scores(ml_risk DESC);

-- Statistical anomalies in the surface (novel outliers the rules don't encode).
CREATE TABLE IF NOT EXISTS anomalies (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type  TEXT NOT NULL CHECK (subject_type IN ('asset','host','change_velocity','finding_pattern')),
  subject_id    UUID,
  subject_label TEXT NOT NULL,
  score         NUMERIC(5,2) NOT NULL,          -- anomaly score 0-100 (higher = more anomalous)
  severity      TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('info','low','medium','high','critical')),
  reason        TEXT NOT NULL,
  features      JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_version INTEGER,
  detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acknowledged  BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (subject_type, subject_label, detected_at)
);

CREATE INDEX IF NOT EXISTS idx_anomalies_score ON anomalies(score DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_unack ON anomalies(acknowledged) WHERE NOT acknowledged;

-- Training labels are DERIVED at train time from analyst actions (ticket
-- status, finding status). This view is the label source — no PII, no secrets.
CREATE OR REPLACE VIEW ml_training_labels AS
  SELECT f.id AS finding_id,
         f.severity, f.rule_source, f.cvss, f.epss,
         (f.metadata->>'blast_score')::float AS blast_score,
         CASE
           WHEN f.status IN ('fixed') THEN 1          -- acted on → was real
           WHEN t.status IN ('resolved','closed') THEN 1
           WHEN f.status IN ('false_positive','wontfix') THEN 0  -- dismissed → noise
           WHEN t.status = 'wontfix' THEN 0
           ELSE NULL                                   -- unlabeled
         END AS label,
         t.breached AS sla_breached
  FROM findings f
  LEFT JOIN tickets t ON t.finding_id = f.id;
