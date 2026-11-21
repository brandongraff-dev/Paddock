-- Finding lifecycle: triage states with reasons + expiry, suppression rules,
-- cross-engine deduplication, and SLA due dates.
-- Applied after 001-018. Additive only: every existing column, status and
-- index keeps its meaning, so older clients see the same rows they always did.

-- =====================================================================
-- Statuses: add `accepted` (risk accepted). `false_positive` already exists.
-- Both now REQUIRE a reason; both may carry an expiry (`accepted_until`),
-- after which the scheduler reopens the finding.
-- =====================================================================
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_status_check;
ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (status IN (
  'open', 'triaged', 'false_positive', 'accepted_risk', 'accepted', 'fixed', 'wontfix'
));

ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_reason     TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_by         TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_until    TIMESTAMPTZ;

-- Rows dismissed before reasons were required get an explicit legacy reason so
-- the constraint below can be validated (and later updates still pass it).
UPDATE findings
   SET status_reason = 'legacy: dismissed before reasons were required'
 WHERE status IN ('accepted', 'false_positive')
   AND (status_reason IS NULL OR btrim(status_reason) = '');

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_dismissal_reason_check;
ALTER TABLE findings ADD CONSTRAINT findings_dismissal_reason_check CHECK (
  status NOT IN ('accepted', 'false_positive')
  OR (status_reason IS NOT NULL AND btrim(status_reason) <> '')
);

CREATE INDEX IF NOT EXISTS idx_findings_accepted_until
  ON findings(accepted_until) WHERE accepted_until IS NOT NULL;

-- Append-only transition history (the hash-chained audit_log is the integrity
-- authority; this table is the queryable per-finding timeline).
CREATE TABLE IF NOT EXISTS finding_status_history (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  from_status     TEXT,
  to_status       TEXT NOT NULL,
  reason          TEXT,
  accepted_until  TIMESTAMPTZ,
  actor           TEXT NOT NULL,
  at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_finding_history_finding
  ON finding_status_history(finding_id, at DESC);

-- =====================================================================
-- Suppression rules. Matched at ingest: a suppressed finding is STORED (so it
-- is countable and auditable) but hidden from default reads.
-- Matchers are AND-ed; at least one must be set.
--   rule_id        glob on findings.rule_id   (e.g. 'sast:weak-hash', 'CVE-2021-*')
--   rule_source    exact findings.rule_source
--   asset_pattern  glob on the asset value / canonical (e.g. '*.staging.example.com')
--   tag            present in asset.metadata.tags or finding.metadata.tags
-- =====================================================================
CREATE TABLE IF NOT EXISTS finding_suppressions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT,
  rule_id          TEXT,
  rule_source      TEXT,
  asset_pattern    TEXT,
  tag              TEXT,
  reason           TEXT NOT NULL CHECK (btrim(reason) <> ''),
  author           TEXT NOT NULL,
  expires_at       TIMESTAMPTZ,
  enabled          BOOLEAN NOT NULL DEFAULT TRUE,
  match_count      INTEGER NOT NULL DEFAULT 0,
  last_matched_at  TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (rule_id IS NOT NULL OR asset_pattern IS NOT NULL OR tag IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_suppressions_active
  ON finding_suppressions(enabled, expires_at);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS suppressed_by UUID
  REFERENCES finding_suppressions(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS suppressed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_findings_suppressed
  ON findings(suppressed_by) WHERE suppressed_by IS NOT NULL;

-- =====================================================================
-- Cross-engine deduplication.
--   asset_key    normalized asset identity (host for network assets)
--   vuln_keys    normalized vuln identities: cve:CVE-…, ghsa:GHSA-…,
--                cwe:CWE-…@file:line, or rule:<source>:<rule_id> as fallback
--   fingerprint  sha256(asset_key | primary vuln key), stable across engines
--   duplicate_of the primary finding this one collapses into (NULL = primary)
-- =====================================================================
ALTER TABLE findings ADD COLUMN IF NOT EXISTS asset_key    TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS vuln_keys    TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint  TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS duplicate_of UUID
  REFERENCES findings(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_asset_key ON findings(asset_key);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_keys ON findings USING GIN (vuln_keys);
CREATE INDEX IF NOT EXISTS idx_findings_duplicate_of
  ON findings(duplicate_of) WHERE duplicate_of IS NOT NULL;

-- =====================================================================
-- SLA: due_at is computed on read from sla_policies (008) -- or the finding's
-- ticket sla_due when one exists -- so editing a policy re-dates every open
-- finding. Nothing to store; the index below keeps the join cheap.
-- =====================================================================
CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON findings(first_seen);
