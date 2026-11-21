-- Tier 3 + SCA: software composition analysis / supply-chain risk,
-- MITRE ATT&CK mapping, LLM triage clusters, and NL-query audit.
-- Neo4j is an external store (mirrored from these tables); only a sync
-- cursor lives here. Applied after 001-008.

-- new finding source for SCA
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_rule_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_rule_source_check CHECK (rule_source IN (
  'nuclei','cve_match','policy','chain','secret_scan','tls_check','header_check',
  'exposed_file','manual','takeover','tls_grade','sca'
));

-- =====================================================================
-- Software Composition Analysis (SBOM + vulns + supply-chain risk)
-- =====================================================================
CREATE TABLE IF NOT EXISTS sca_projects (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  source_ref    TEXT,                 -- repo URL / path the lockfiles came from
  ecosystems    TEXT[] DEFAULT ARRAY[]::TEXT[],
  asset_id      UUID REFERENCES assets(id) ON DELETE SET NULL,  -- link to a repository asset
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_scanned  TIMESTAMPTZ,
  UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS sbom_components (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    UUID NOT NULL REFERENCES sca_projects(id) ON DELETE CASCADE,
  ecosystem     TEXT NOT NULL,        -- npm, PyPI, Go, crates.io, Maven, RubyGems
  name          TEXT NOT NULL,
  version       TEXT NOT NULL,
  purl          TEXT,                 -- package URL
  direct        BOOLEAN NOT NULL DEFAULT TRUE,
  depth         SMALLINT NOT NULL DEFAULT 0,
  paths         JSONB NOT NULL DEFAULT '[]'::jsonb,  -- dependency paths (who pulls it)
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (project_id, ecosystem, name, version)
);

CREATE INDEX IF NOT EXISTS idx_sbom_project ON sbom_components(project_id);
CREATE INDEX IF NOT EXISTS idx_sbom_name ON sbom_components(ecosystem, name);

CREATE TABLE IF NOT EXISTS sbom_component_vulns (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  component_id   UUID NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
  osv_id         TEXT NOT NULL,       -- e.g. GHSA-xxxx / OSV id
  cve_id         TEXT,
  severity       TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('info','low','medium','high','critical')),
  cvss           NUMERIC(3,1),
  summary        TEXT,
  fixed_version  TEXT,
  refs           JSONB NOT NULL DEFAULT '[]'::jsonb,
  matched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (component_id, osv_id)
);

CREATE INDEX IF NOT EXISTS idx_sbom_vulns_component ON sbom_component_vulns(component_id);
CREATE INDEX IF NOT EXISTS idx_sbom_vulns_severity ON sbom_component_vulns(severity);

CREATE TABLE IF NOT EXISTS supply_chain_risks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    UUID REFERENCES sca_projects(id) ON DELETE CASCADE,
  component_id  UUID REFERENCES sbom_components(id) ON DELETE CASCADE,
  risk_type     TEXT NOT NULL CHECK (risk_type IN (
                  'dependency_confusion','typosquat','abandoned','malicious_version',
                  'yanked','unpinned','install_scripts'
                )),
  severity      TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('info','low','medium','high','critical')),
  summary       TEXT NOT NULL,
  detail        JSONB NOT NULL DEFAULT '{}'::jsonb,
  detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (project_id, component_id, risk_type)
);

CREATE INDEX IF NOT EXISTS idx_scr_type ON supply_chain_risks(risk_type, severity);

-- =====================================================================
-- MITRE ATT&CK + CWE mapping
-- =====================================================================
CREATE TABLE IF NOT EXISTS attack_technique_map (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- match: {rule_source, rule_id_regex, title_regex} (AND-ed, all optional)
  match         JSONB NOT NULL DEFAULT '{}'::jsonb,
  technique_id  TEXT NOT NULL,        -- e.g. T1190
  technique     TEXT NOT NULL,        -- Exploit Public-Facing Application
  tactic        TEXT NOT NULL,        -- Initial Access
  cwe           TEXT,                 -- e.g. CWE-22
  priority      SMALLINT NOT NULL DEFAULT 100,
  enabled       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS finding_techniques (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id    UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  technique_id  TEXT NOT NULL,
  technique     TEXT NOT NULL,
  tactic        TEXT NOT NULL,
  cwe           TEXT,
  confidence    SMALLINT NOT NULL DEFAULT 80,
  mapped_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (finding_id, technique_id)
);

CREATE INDEX IF NOT EXISTS idx_fintech_finding ON finding_techniques(finding_id);
CREATE INDEX IF NOT EXISTS idx_fintech_technique ON finding_techniques(technique_id, tactic);

-- =====================================================================
-- LLM triage clusters + NL-query audit
-- =====================================================================
CREATE TABLE IF NOT EXISTS finding_clusters (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  label         TEXT NOT NULL,
  summary       TEXT,
  severity      TEXT,
  finding_ids   UUID[] NOT NULL DEFAULT ARRAY[]::UUID[],
  engine        TEXT NOT NULL DEFAULT 'template',   -- 'llm' | 'template'
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Every natural-language query is audited (the generated SQL is logged, run
-- read-only). This table is the accountability record for the Ask feature.
CREATE TABLE IF NOT EXISTS nl_queries (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  question       TEXT NOT NULL,
  generated_sql  TEXT,
  engine         TEXT NOT NULL,       -- 'llm' | 'fallback'
  ok             BOOLEAN NOT NULL,
  row_count      INTEGER,
  error          TEXT,
  asked_by       TEXT,
  asked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nl_queries_at ON nl_queries(asked_at DESC);

-- A read-only, safe projection the NL-query engine is ALLOWED to query.
-- (No scope secrets, no alert targets, no credentials — graph + findings only.)
CREATE OR REPLACE VIEW ask_assets AS
  SELECT id, kind, value, canonical, first_seen, last_seen, source,
         (metadata->>'env') AS env, (metadata->>'blast_score')::float AS blast_score
  FROM assets;
CREATE OR REPLACE VIEW ask_findings AS
  SELECT f.id, f.asset_id, a.value AS asset_value, a.kind AS asset_kind,
         f.rule_id, f.rule_source, f.severity, f.title, f.status,
         f.cvss, f.epss, f.first_seen
  FROM findings f LEFT JOIN assets a ON a.id = f.asset_id;
CREATE OR REPLACE VIEW ask_attack_paths AS
  SELECT id, severity, exploitability, kev_on_path, length, title FROM attack_paths;

-- sync cursor for the neo4j mirror
INSERT INTO intel_cursors (source, last_synced)
VALUES ('neo4j_sync', NOW() - INTERVAL '1 day')
ON CONFLICT (source) DO NOTHING;
