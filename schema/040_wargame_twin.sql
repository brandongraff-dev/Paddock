-- Wargame twin: the persisted, rule-aware model an assessment runs over.
-- Parsed firewall/cloud rule sets + the declared topology (segments and
-- edges) are stored here by the correlation service when config is
-- ingested; /compute-wargame loads them into an Environment so routes are
-- proved by config, not merely inferred from the asset graph.
-- tenant_id + RLS are retrofitted by 099_tenancy.sql (applied later), so a
-- tenant only ever sees and replaces its own twin. There is no cross-tenant
-- UNIQUE here on purpose: a twin is replaced by deleting the tenant's rows
-- and reinserting, which RLS scopes automatically.
-- =====================================================================

-- A vendor-neutral rule set (a firewall, security-group set, NACL, ...).
CREATE TABLE IF NOT EXISTS wargame_rulesets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ruleset_key     TEXT NOT NULL,                 -- logical id, e.g. "sg-db"
  vendor          TEXT NOT NULL DEFAULT '',
  default_action  TEXT NOT NULL DEFAULT 'deny' CHECK (default_action IN ('allow','deny')),
  name            TEXT NOT NULL DEFAULT '',
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wg_rulesets_key ON wargame_rulesets(ruleset_key);

-- One rule inside a rule set.
CREATE TABLE IF NOT EXISTS wargame_rules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ruleset_key     TEXT NOT NULL,
  rule_id         TEXT NOT NULL,
  ord             INTEGER NOT NULL DEFAULT 0,     -- evaluation order (lower first)
  action          TEXT NOT NULL CHECK (action IN ('allow','deny')),
  src_cidrs       JSONB NOT NULL DEFAULT '[]'::jsonb,
  dst_cidrs       JSONB NOT NULL DEFAULT '[]'::jsonb,
  -- ports: [{proto, low, high}]
  ports           JSONB NOT NULL DEFAULT '[]'::jsonb,
  conditional     BOOLEAN NOT NULL DEFAULT FALSE,
  vendor          TEXT NOT NULL DEFAULT '',
  raw_ref         TEXT NOT NULL DEFAULT '',
  cost_class      TEXT NOT NULL DEFAULT 'network_rule'
);
CREATE INDEX IF NOT EXISTS idx_wg_rules_rs ON wargame_rules(ruleset_key, ord);

-- A segment / host / identity node of the topology.
CREATE TABLE IF NOT EXISTS wargame_segments (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seg_key         TEXT NOT NULL,
  cidrs           JSONB NOT NULL DEFAULT '[]'::jsonb,
  role            TEXT NOT NULL DEFAULT 'intermediate'
                    CHECK (role IN ('entry','crown_jewel','intermediate')),
  reason          TEXT NOT NULL DEFAULT '',
  jewel_kind      TEXT NOT NULL DEFAULT '',
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wg_segments_key ON wargame_segments(seg_key);

-- A directed adjacency, optionally gated by a rule set.
CREATE TABLE IF NOT EXISTS wargame_edges (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  src             TEXT NOT NULL,
  dst             TEXT NOT NULL,
  rule_set_id     TEXT,                           -- NULL = ungoverned adjacency
  -- port: {proto, low, high} or NULL
  port            JSONB,
  base_labels     JSONB NOT NULL DEFAULT '[]'::jsonb,
  fix_candidate_id TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_wg_edges_src ON wargame_edges(src);
CREATE INDEX IF NOT EXISTS idx_wg_edges_dst ON wargame_edges(dst);

-- Config snapshots behind the twin, for certificate provenance (the exact
-- bytes a "closed" proof was computed against).
CREATE TABLE IF NOT EXISTS wargame_config_snapshots (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor          TEXT NOT NULL DEFAULT '',
  source          TEXT NOT NULL DEFAULT '',       -- file path / connector id
  sha256          TEXT NOT NULL,
  ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wg_snap_sha ON wargame_config_snapshots(sha256);
