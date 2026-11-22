-- 039: reachability closure, choke-points, and path coverage.
--
-- Part 1 of the "Wargame" line of work (docs/WARGAME.md): turn the existing
-- forward attack-path list (007_tier1 attack_paths, computed by correlation)
-- into a *defensive* answer to the only question a CISO, board or insurer
-- actually pays for -- "can anyone reach what we care about, and have we shut
-- the door?" -- by adding three computed artefacts:
--
--   choke_points         the MINIMUM set of assets whose removal cuts every
--                        open path from an internet-facing source to a crown
--                        jewel (a node-capacitated min-cut over the asset
--                        graph). "These N fixes cut M paths" -- the smallest,
--                        highest-leverage remediation set, ranked.
--   crown_jewel_exposure per crown jewel: how many internet-facing sources can
--                        reach it, over how many open paths, in how few hops,
--                        and whether it is currently proven-closed.
--   coverage_snapshots   a time series of PATH COVERAGE: the share of paths to
--                        crown jewels that are proven-closed, tripwired, or
--                        risk-accepted vs. still open. The headline number.
--
-- All three are computed by the correlation service from attack_paths +
-- findings (verification state) + suppressions, and upserted by fingerprint
-- with stale pruning, exactly like attack_paths. They are DERIVED and
-- disposable: a full recompute always reproduces them.
--
-- Tenancy: 099_tenancy.sql (applied after this file) auto-discovers every
-- non-global table and adds tenant_id + FORCEd RLS. We also declare tenant_id
-- here with the default-tenant literal (as 036 does) so the per-tenant unique
-- keys below can be built immediately and this file is self-sufficient.
--
-- Additive and idempotent: safe to apply on top of an existing database.

-- =====================================================================
-- Choke points: the minimum cut set.
-- One row per asset the current min-cut recommends removing/segmenting.
-- =====================================================================
CREATE TABLE IF NOT EXISTS choke_points (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id       UUID REFERENCES assets(id) ON DELETE CASCADE,
  -- How many of the current open source->jewel paths traverse this asset.
  paths_cut      INTEGER NOT NULL DEFAULT 0,
  -- True when this asset is part of the computed minimum cut (vs. merely a
  -- high-betweenness node surfaced for context).
  in_min_cut     BOOLEAN NOT NULL DEFAULT TRUE,
  -- 1 = cut this first. Ranked by marginal paths removed, then cost.
  cut_rank       SMALLINT NOT NULL DEFAULT 1,
  -- Cumulative share of open paths removed once this rank and every lower
  -- rank are cut (0-100). Lets the UI say "top 3 fixes close 86% of paths".
  reduction_pct  NUMERIC(5,2) NOT NULL DEFAULT 0,
  total_paths    INTEGER NOT NULL DEFAULT 0,
  -- Cheapest action to neutralise this node, as a hint: segment | patch |
  -- decommission | restrict. Never an exploitation instruction.
  action_hint    TEXT NOT NULL DEFAULT 'segment'
                 CHECK (action_hint IN ('segment','patch','decommission','restrict','review')),
  narrative      TEXT,
  fingerprint    TEXT NOT NULL,
  computed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  tenant_id      UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  UNIQUE (tenant_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_choke_points_rank
  ON choke_points (tenant_id, cut_rank);
CREATE INDEX IF NOT EXISTS idx_choke_points_asset
  ON choke_points (asset_id);
CREATE INDEX IF NOT EXISTS idx_choke_points_paths
  ON choke_points (tenant_id, paths_cut DESC);

-- =====================================================================
-- Crown-jewel exposure: one row per crown-jewel target.
-- =====================================================================
CREATE TABLE IF NOT EXISTS crown_jewel_exposure (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  target_reason   TEXT,                                 -- why it's a crown jewel
  reachable_source_count INTEGER NOT NULL DEFAULT 0,    -- distinct sources that can reach it
  open_path_count INTEGER NOT NULL DEFAULT 0,           -- open paths terminating here
  min_hops        SMALLINT,                             -- shortest path length from any source
  max_exploitability NUMERIC(5,2) NOT NULL DEFAULT 0,
  kev_on_any_path BOOLEAN NOT NULL DEFAULT FALSE,
  -- No open path currently reaches this jewel (model-level evidence of absence).
  proven_closed   BOOLEAN NOT NULL DEFAULT FALSE,
  computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  UNIQUE (tenant_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_cje_exposed
  ON crown_jewel_exposure (tenant_id, proven_closed, open_path_count DESC);

-- =====================================================================
-- Coverage snapshots: the headline "path coverage" time series.
-- A path counts as COVERED when it is proven-closed (no longer reachable),
-- tripwired (a decoy/canary watches the open route), or risk-accepted (a
-- suppression with a reason + expiry). Everything else is OPEN.
-- =====================================================================
CREATE TABLE IF NOT EXISTS coverage_snapshots (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  total_paths         INTEGER NOT NULL DEFAULT 0,
  open_paths          INTEGER NOT NULL DEFAULT 0,
  proven_closed_paths INTEGER NOT NULL DEFAULT 0,
  tripwired_paths     INTEGER NOT NULL DEFAULT 0,
  risk_accepted_paths INTEGER NOT NULL DEFAULT 0,
  -- (covered / total) * 100, where covered = closed + tripwired + accepted.
  coverage_pct        NUMERIC(5,2) NOT NULL DEFAULT 0,
  crown_jewels_total  INTEGER NOT NULL DEFAULT 0,
  crown_jewels_exposed INTEGER NOT NULL DEFAULT 0,
  choke_point_count   INTEGER NOT NULL DEFAULT 0,
  -- Paths with at least one proven (verified / observed) hop vs. purely inferred.
  proven_hop_paths    INTEGER NOT NULL DEFAULT 0,
  metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
  tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'
);

CREATE INDEX IF NOT EXISTS idx_coverage_snapshots_at
  ON coverage_snapshots (tenant_id, snapshot_at DESC);

-- =====================================================================
-- Grants. The 029 service-grant allow-list is hardcoded and does not know
-- these tables, so grant explicitly here (guarded by role existence, since a
-- fresh dev database may not have run 029/the role scripts yet).
-- correlation computes them; the orchestrator API (paddock_app) reads them.
-- =====================================================================
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['choke_points','crown_jewel_exposure','coverage_snapshots'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_svc_correlation') THEN
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO paddock_svc_correlation', t);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_app') THEN
      EXECUTE format('GRANT SELECT ON public.%I TO paddock_app', t);
    END IF;
  END LOOP;
END $$;
