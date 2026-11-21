-- 023: reporting (weekly digest, executive report, compliance evidence packs).
--
-- Reports need two facts the core schema does not record:
--   1. WHEN a finding was resolved (findings only carry first_seen/last_seen),
--      so MTTR, SLA outcomes and the exposure trend are exact.
--   2. WHEN an attack path appeared and disappeared (the correlation service
--      upserts attack_paths by fingerprint and DELETEs stale rows), so the
--      report can say "N paths to crown jewels closed this month".
-- Both are captured by triggers, so every writer (orchestrator PATCH, triage,
-- correlation, ad-hoc SQL) is covered without touching their code.
-- Additive only; safe to re-run.

-- --------------------------------------------------------------------------
-- Finding status history (append-only) + current resolution (one row/finding)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding_status_events (
  id          BIGSERIAL PRIMARY KEY,
  finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  old_status  TEXT,
  new_status  TEXT NOT NULL,
  severity    TEXT,
  changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fse_finding ON finding_status_events (finding_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_fse_changed ON finding_status_events (changed_at);

-- A finding in a terminal status has exactly one row here; reopening deletes it.
CREATE TABLE IF NOT EXISTS finding_resolutions (
  finding_id  UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
  status      TEXT NOT NULL,
  resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_finding_resolutions_at ON finding_resolutions (resolved_at);

CREATE OR REPLACE FUNCTION paddock_track_finding_status() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NEW;
  END IF;
  -- An ordinary open insert needs no history row (first_seen records it);
  -- skipping it keeps bulk ingest cheap.
  IF TG_OP = 'INSERT' AND NEW.status IN ('open', 'triaged') THEN
    RETURN NEW;
  END IF;
  INSERT INTO finding_status_events (finding_id, old_status, new_status, severity)
  VALUES (NEW.id, CASE WHEN TG_OP = 'UPDATE' THEN OLD.status END, NEW.status, NEW.severity);
  IF NEW.status IN ('fixed', 'false_positive', 'accepted_risk', 'wontfix') THEN
    INSERT INTO finding_resolutions (finding_id, status, resolved_at)
    VALUES (NEW.id, NEW.status, NOW())
    ON CONFLICT (finding_id) DO UPDATE
      SET status = EXCLUDED.status, resolved_at = EXCLUDED.resolved_at;
  ELSE
    DELETE FROM finding_resolutions WHERE finding_id = NEW.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_findings_status_history ON findings;
CREATE TRIGGER trg_findings_status_history
  AFTER INSERT OR UPDATE OF status ON findings
  FOR EACH ROW EXECUTE FUNCTION paddock_track_finding_status();

-- Backfill: findings already closed before this migration get their last_seen
-- as the best available resolution time (documented in docs/REPORTS.md).
INSERT INTO finding_resolutions (finding_id, status, resolved_at)
SELECT id, status, last_seen FROM findings
 WHERE status IN ('fixed', 'false_positive', 'accepted_risk', 'wontfix')
ON CONFLICT (finding_id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON findings (first_seen);
CREATE INDEX IF NOT EXISTS idx_assets_first_seen ON assets (first_seen);

-- --------------------------------------------------------------------------
-- Attack-path ledger: one row per "episode" (open .. closed) of a fingerprint
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_path_ledger (
  id               BIGSERIAL PRIMARY KEY,
  fingerprint      TEXT NOT NULL,
  title            TEXT NOT NULL,
  severity         TEXT NOT NULL,
  exploitability   NUMERIC(5,2),
  kev_on_path      BOOLEAN NOT NULL DEFAULT FALSE,
  length           SMALLINT,
  source_asset_id  UUID,
  target_asset_id  UUID,
  opened_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at        TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_apl_open ON attack_path_ledger (fingerprint) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_apl_opened ON attack_path_ledger (opened_at);
CREATE INDEX IF NOT EXISTS idx_apl_closed ON attack_path_ledger (closed_at);

CREATE OR REPLACE FUNCTION paddock_track_attack_path() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    UPDATE attack_path_ledger SET closed_at = NOW()
     WHERE fingerprint = OLD.fingerprint AND closed_at IS NULL;
    RETURN OLD;
  END IF;
  UPDATE attack_path_ledger
     SET title = NEW.title, severity = NEW.severity,
         exploitability = NEW.exploitability, kev_on_path = NEW.kev_on_path,
         length = NEW.length, source_asset_id = NEW.source_asset_id,
         target_asset_id = NEW.target_asset_id, last_seen_at = NOW()
   WHERE fingerprint = NEW.fingerprint AND closed_at IS NULL;
  IF NOT FOUND THEN
    INSERT INTO attack_path_ledger (fingerprint, title, severity, exploitability,
                                    kev_on_path, length, source_asset_id, target_asset_id)
    VALUES (NEW.fingerprint, NEW.title, NEW.severity, NEW.exploitability,
            NEW.kev_on_path, NEW.length, NEW.source_asset_id, NEW.target_asset_id);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_attack_paths_ledger ON attack_paths;
CREATE TRIGGER trg_attack_paths_ledger
  AFTER INSERT OR UPDATE OR DELETE ON attack_paths
  FOR EACH ROW EXECUTE FUNCTION paddock_track_attack_path();

INSERT INTO attack_path_ledger (fingerprint, title, severity, exploitability, kev_on_path,
                                length, source_asset_id, target_asset_id, opened_at, last_seen_at)
SELECT p.fingerprint, p.title, p.severity, p.exploitability, p.kev_on_path, p.length,
       p.source_asset_id, p.target_asset_id, p.computed_at, p.computed_at
  FROM attack_paths p
 WHERE NOT EXISTS (SELECT 1 FROM attack_path_ledger l
                    WHERE l.fingerprint = p.fingerprint AND l.closed_at IS NULL);

-- --------------------------------------------------------------------------
-- Digest runs: history + idempotency for the scheduler (one per slot)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_digests (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace     TEXT NOT NULL DEFAULT 'default',
  kind          TEXT NOT NULL DEFAULT 'weekly' CHECK (kind IN ('weekly', 'manual')),
  period_start  TIMESTAMPTZ NOT NULL,
  period_end    TIMESTAMPTZ NOT NULL,
  generated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_id      TEXT,
  status        TEXT NOT NULL DEFAULT 'built'
                CHECK (status IN ('built', 'emitted', 'emit_unavailable', 'emit_failed')),
  detail        TEXT,
  summary       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_report_digests_slot
  ON report_digests (workspace, kind, period_end) WHERE kind = 'weekly';
CREATE INDEX IF NOT EXISTS idx_report_digests_generated ON report_digests (generated_at DESC);
