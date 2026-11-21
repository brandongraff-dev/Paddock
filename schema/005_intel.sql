-- Threat intel layer: CVE feed, EPSS scores, CPE matching.

CREATE TABLE IF NOT EXISTS cves (
  id                TEXT PRIMARY KEY,  -- CVE-YYYY-NNNNN
  published_at      TIMESTAMPTZ,
  modified_at       TIMESTAMPTZ,
  cvss_v3           NUMERIC(3,1),
  cvss_v3_vector    TEXT,
  cvss_v2           NUMERIC(3,1),
  epss              NUMERIC(4,3),
  epss_percentile   NUMERIC(4,3),
  description       TEXT,
  refs              JSONB NOT NULL DEFAULT '[]'::jsonb,
  cpe_affected      JSONB NOT NULL DEFAULT '[]'::jsonb,
  cwe_ids           TEXT[],
  known_exploited   BOOLEAN NOT NULL DEFAULT FALSE,
  kev_added_at      TIMESTAMPTZ,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_v3 DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(known_exploited) WHERE known_exploited;
CREATE INDEX IF NOT EXISTS idx_cves_cpe_gin ON cves USING GIN (cpe_affected);

CREATE TABLE IF NOT EXISTS cve_matches (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id      TEXT NOT NULL REFERENCES cves(id),
  asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  confidence  SMALLINT NOT NULL,
  matched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  matcher     TEXT NOT NULL,  -- which matcher produced this (cpe, nuclei, manual)
  UNIQUE (cve_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_matches_cve ON cve_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_matches_asset ON cve_matches(asset_id);

-- Ingestion cursors
CREATE TABLE IF NOT EXISTS intel_cursors (
  source        TEXT PRIMARY KEY,  -- 'nvd', 'epss', 'kev', 'ct_logs'
  last_synced   TIMESTAMPTZ,
  last_cursor   TEXT,
  stats         JSONB NOT NULL DEFAULT '{}'::jsonb
);
