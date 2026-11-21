-- 022: production-operations indexes (see docs/OPERATIONS.md "Scale test").
--
-- Every index here was justified by hardening/scale_test.py at
-- 10k assets / 100k findings / 1M scope decisions; the before/after numbers
-- are in docs/OPERATIONS.md. Plain CREATE INDEX (inside the migration's
-- transaction) briefly blocks writes to the table while it builds: seconds
-- at the sizes above, so run upgrades in a quiet window on very large DBs.
--
-- The schema_migrations bookkeeping table is created by the migration runner
-- itself (orchestrator/app/migrate.py), not here.

-- Scope decisions for one entry, newest first (GET /v1/scope/{id}/decisions).
-- Without it, an entry with few decisions walks the whole decided_at index
-- (1M rows: ~300 ms).
CREATE INDEX IF NOT EXISTS idx_scope_decisions_entry_ts
  ON scope_decisions (matched_entry, decided_at DESC);

-- Findings list: the common filters, already in the API's sort order.
CREATE INDEX IF NOT EXISTS idx_findings_status_last_seen
  ON findings (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_sev_status_last_seen
  ON findings (severity, status, last_seen DESC);

-- Timeline buckets by first_seen (GET /v1/timeline).
CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON findings (first_seen);
CREATE INDEX IF NOT EXISTS idx_assets_first_seen ON assets (first_seen);
CREATE INDEX IF NOT EXISTS idx_scans_queued_at ON scans (queued_at);

-- Surface graph: open high/critical findings per asset.
CREATE INDEX IF NOT EXISTS idx_findings_open_hi_asset
  ON findings (asset_id)
  WHERE status = 'open' AND severity IN ('high', 'critical');

-- Assets list by kind in the API's sort order; ingest freshness per source
-- (/metrics paddock_asset_source_last_seen_timestamp_seconds).
CREATE INDEX IF NOT EXISTS idx_assets_kind_last_seen ON assets (kind, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_assets_source_last_seen ON assets (source, last_seen DESC);

-- Retention purge of terminal integration deliveries (app/retention.py).
CREATE INDEX IF NOT EXISTS idx_integration_deliveries_updated
  ON integration_deliveries (updated_at)
  WHERE status IN ('sent', 'dead', 'skipped');

-- Findings free-text search (?q=) uses ILIKE '%term%'. Trigram GIN indexes
-- turn a rare-term search from a full scan into an index lookup. pg_trgm is a
-- trusted contrib extension (PG >= 13), but some managed services restrict
-- extensions: if it cannot be created we skip these two indexes rather than
-- fail the migration.
DO $$
BEGIN
  BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
  EXCEPTION WHEN insufficient_privilege OR undefined_file OR feature_not_supported THEN
    RAISE NOTICE '022_ops: pg_trgm unavailable (%), skipping trigram indexes', SQLERRM;
  END;
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_findings_title_trgm '
            'ON findings USING gin (title gin_trgm_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_findings_description_trgm '
            'ON findings USING gin (description gin_trgm_ops)';
  END IF;
END
$$;
