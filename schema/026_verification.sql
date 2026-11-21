-- 026: verified findings -- "find -> prove it's real -> fix -> prove it's fixed".
--
-- A finding is a CLAIM until a non-destructive safe check (GET/HEAD/TLS
-- handshake/TCP connect only; workers/active app/modules/safe_checks) has
-- reproduced it. This file adds
--
--   * per-finding verification state: `exploitability`
--       unverified | confirmed | not_reproducible | inconclusive
--     plus `last_verified_at`, and `fix_verified_at` (set when a finding that
--     was marked fixed re-checked as not reproducible = "verified fixed");
--   * `finding_verifications`: an append-only ledger of EVERY attempt (who or
--     what triggered it, scope/proof it ran under, verdict, redacted and
--     size-capped evidence), including attempts that were refused.
--
-- Additive and idempotent. docs/VERIFICATION.md has the long form.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS exploitability TEXT NOT NULL DEFAULT 'unverified';
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_exploitability_check;
ALTER TABLE findings ADD CONSTRAINT findings_exploitability_check CHECK (
  exploitability IN ('unverified', 'confirmed', 'not_reproducible', 'inconclusive')
);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fix_verified_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_findings_exploitability
  ON findings (exploitability) WHERE exploitability <> 'unverified';

CREATE TABLE IF NOT EXISTS finding_verifications (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  -- exploitability: "is it real?"; fix: "did the fix hold?"
  purpose         TEXT NOT NULL DEFAULT 'exploitability'
                  CHECK (purpose IN ('exploitability', 'fix')),
  -- what asked for it
  trigger         TEXT NOT NULL DEFAULT 'manual'
                  CHECK (trigger IN ('manual', 'bulk', 'fix_status', 'fix_ticket',
                                     'fix_pr', 'retry', 'scheduled')),
  requested_by    TEXT NOT NULL,                      -- user / api key / system:verification
  -- scheduled: waiting for run_after; queued: on the worker stream;
  -- done: the worker returned a verdict; refused: scope or proof said no;
  -- unsupported: no safe check exists for this rule; error: worker failed or
  -- never reported; cancelled: no longer applicable (finding no longer fixed).
  status          TEXT NOT NULL DEFAULT 'scheduled'
                  CHECK (status IN ('scheduled', 'queued', 'done', 'refused',
                                    'unsupported', 'error', 'cancelled')),
  verdict         TEXT CHECK (verdict IN ('confirmed', 'not_reproducible', 'inconclusive')),
  check_id        TEXT,                               -- registry id, e.g. exposed_file
  target          TEXT,                               -- normalised host the check touched
  scope_entry_id  INTEGER,                            -- the effective scope entry
  scope_proof     TEXT,                               -- its proof status at dispatch
  scan_id         UUID,                               -- the scans row carrying the job
  evidence        JSONB NOT NULL DEFAULT '{}'::jsonb, -- redacted, size-capped
  reason          TEXT,                               -- refusal / error / verdict detail
  requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  run_after       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  dispatched_at   TIMESTAMPTZ,
  checked_at      TIMESTAMPTZ,                        -- when the worker observed it
  completed_at    TIMESTAMPTZ,
  CHECK (verdict IS NULL OR status = 'done')
);

CREATE INDEX IF NOT EXISTS idx_finding_verifications_finding
  ON finding_verifications (finding_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_verifications_due
  ON finding_verifications (run_after) WHERE status = 'scheduled';
CREATE INDEX IF NOT EXISTS idx_finding_verifications_queued
  ON finding_verifications (dispatched_at) WHERE status = 'queued';
-- At most one in-flight verification per finding and purpose.
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_verifications_inflight
  ON finding_verifications (finding_id, purpose) WHERE status IN ('scheduled', 'queued');

-- The ledger is append-only: a finished attempt never changes.
CREATE OR REPLACE FUNCTION paddock_verification_immutable() RETURNS trigger AS $$
BEGIN
  IF OLD.status NOT IN ('scheduled', 'queued') THEN
    RAISE EXCEPTION 'finding_verifications rows are immutable once % (id %)', OLD.status, OLD.id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_finding_verifications_immutable ON finding_verifications;
CREATE TRIGGER trg_finding_verifications_immutable
  BEFORE UPDATE ON finding_verifications
  FOR EACH ROW EXECUTE FUNCTION paddock_verification_immutable();
