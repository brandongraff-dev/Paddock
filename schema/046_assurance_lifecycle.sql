-- 046: Provable Containment P2.1, section F: lifecycle residuals. See docs/ASSURANCE_P2_1.md 6.1 and 6.2 (D33, D34).
--
--   invariants.archived_at / disabled_at / disabled_by
--       runner-4: a disabled or deleted invariant keeps its findings OPEN and annotates them (`metadata.invariant_state`);
--       it never closes them (closing by absence would be a false verification). Before this, PUT enabled=false and DELETE
--       both just set enabled=false and the two were indistinguishable. State machine (the application's):
--         active --PUT enabled=false--> disabled (disabled_at, disabled_by)
--         active|disabled --DELETE--> archived (archived_at, enabled=false)
--         disabled|archived --PUT enabled=true--> active (the timestamps are cleared)
--   findings index on the annotation, for the runner's reconcile step and the release route.
--   invariant_runs.compacted_at / pinned
--       the heavy result JSON is compacted after assurance_runs_compact_days and rows are purged after
--       RETENTION_INVARIANT_RUNS_DAYS (retention.py), except the newest row of each (tenant, invariant) and pinned rows.
--       `pinned` is never compacted or deleted; unused until P3 attestations reference run ids (D34).
--
-- Runs BEFORE 099_tenancy.sql (re-applied by the runner afterwards). Idempotent. The backfill runs once per tenant with
-- app.tenant_id set (transaction-local), so it also works when the migration owner is a plain table owner that FORCE ROW
-- LEVEL SECURITY applies to, instead of silently matching no rows (the 041/042 pattern). On a fresh database `tenants`
-- does not exist yet (099 creates it) and neither do invariants.
--
-- Backfill: a row that is not enabled gets disabled_at = updated_at (the last change is the best date there is). archived_at
-- is NEVER invented: an invariant deleted before this migration is indistinguishable from a disabled one, and a disabled one
-- can be re-enabled, which is the safe reading.

ALTER TABLE invariants ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ,
                       ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ,
                       ADD COLUMN IF NOT EXISTS disabled_by TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_invariant_state ON findings ((metadata->>'invariant_state'))
  WHERE rule_source = 'invariant' AND metadata ? 'invariant_state';

ALTER TABLE invariant_runs ADD COLUMN IF NOT EXISTS compacted_at TIMESTAMPTZ,
                           ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_invariant_runs_evaluated ON invariant_runs (tenant_id, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_invariant_runs_uncompacted ON invariant_runs (tenant_id, evaluated_at) WHERE compacted_at IS NULL;

DO $$
DECLARE t record;
BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'public' AND table_name = 'invariants' AND column_name = 'tenant_id') THEN
    FOR t IN SELECT id FROM tenants LOOP
      PERFORM set_config('app.tenant_id', t.id::text, true);
      UPDATE invariants SET disabled_at = updated_at
       WHERE NOT enabled AND disabled_at IS NULL AND archived_at IS NULL;
    END LOOP;
    PERFORM set_config('app.tenant_id', '', true);
  ELSE
    UPDATE invariants SET disabled_at = updated_at
     WHERE NOT enabled AND disabled_at IS NULL AND archived_at IS NULL;
  END IF;
END $$;
