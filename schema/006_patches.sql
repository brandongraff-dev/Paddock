-- Integration patches:
--   - scope_entries gains a metadata JSONB column (per-scope politeness
--     overrides and whatever other opaque config scope callers want to
--     attach without a dedicated column). Default is empty object so
--     existing code paths are unaffected.
--
--   - finding_chains gains a uniqueness scaffolding so the correlator's
--     upsert-by-(rule, anchor) and upsert-by-(rule, fingerprint)
--     semantics are well defined. The orchestrator does the upsert
--     manually (asyncpg doesn't play well with partial indexes across
--     ON CONFLICT targets), but these two indexes make the lookups fast.
--
-- Postgres initializes schema in alphabetical filename order, so this
-- file applies last, after 001..005.

ALTER TABLE scope_entries
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_chains_rule_anchor
  ON finding_chains(chain_rule_id, anchor_asset_id);

CREATE INDEX IF NOT EXISTS idx_chains_rule_fingerprint
  ON finding_chains(chain_rule_id, (metadata->>'fingerprint'))
  WHERE anchor_asset_id IS NULL;
