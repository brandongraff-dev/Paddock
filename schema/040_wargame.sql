-- 040: Wargame / Proving Ground -- prove a hop on an attack path by rebuilding
-- the component in an ISOLATED replica and running the real check against the
-- copy, never against a live system.
--
-- Part 2 of the Wargame line of work (docs/WARGAME.md). Where the safe-check
-- verifier (026_verification) confirms a finding non-destructively against the
-- owner's live asset, the Proving Ground goes further for the hops that matter
-- most: it stands up a throwaway replica of the exact component (same product,
-- version and config, from the SBOM / technology asset), proves the hop is
-- real by actually exercising it IN THE SANDBOX, applies the candidate fix to
-- the replica, and proves the hop is shut -- producing a hash-chained,
-- signed before/after proof.
--
-- THE ONE INVARIANT, enforced in code (wargame/app/sandbox/guard.py) and
-- recorded on every run: a scenario only ever runs against an isolated
-- replica the customer owns, on an internal-only network with no route to any
-- live or out-of-scope system. There is no "run against production" path.
--
--   wargame_scenarios  catalogue of proving-ground scenarios (GLOBAL, like
--                      attack_technique_map). Each names what it reproduces
--                      and against which component class.
--   wargame_runs       one proving-ground run: a scenario, the component it
--                      rebuilt, the isolation that held, and the before/after
--                      verdict + outcome.
--   wargame_proofs     append-only, hash-chained, signed proof entries per run
--                      (before exploit succeeded on the replica; after the fix
--                      it failed). This is the artefact an insurer / auditor
--                      verifies without trusting the tenant.
--
-- Tenancy: 099_tenancy.sql (after this file) adds tenant_id + FORCEd RLS to
-- wargame_runs / wargame_proofs automatically; wargame_scenarios is marked
-- @paddock:global so it gets the global read / platform-write policies. We
-- declare tenant_id with the default literal here too, so the per-tenant keys
-- build immediately.
--
-- Additive and idempotent.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================================
-- Scenario catalogue (global).
-- =====================================================================
CREATE TABLE IF NOT EXISTS wargame_scenarios (
  id           TEXT PRIMARY KEY,                      -- e.g. 'cve-container-repro'
  title        TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  -- What class of hop this proves.
  category     TEXT NOT NULL DEFAULT 'other'
               CHECK (category IN ('cve_repro','default_cred','unauth_access',
                                   'exposed_service','misconfig','segmentation','other')),
  technique    TEXT,                                  -- optional ATT&CK technique id
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  -- Matcher + parameters the engine reads: {matches:{rule_source,product,...},
  -- replica:{image,...}, requires:[...]}. Never exploitation payloads: the
  -- scenario code lives in wargame/app/scenarios, this is only its config.
  spec         JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE wargame_scenarios IS
  'Proving-ground scenario catalogue. @paddock:global catalogue (read-all, platform-write).';

-- =====================================================================
-- Runs.
-- =====================================================================
CREATE TABLE IF NOT EXISTS wargame_runs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- The attack path + the specific hop/component under test. Both nullable so
  -- a run survives the path being recomputed away.
  attack_path_id  UUID REFERENCES attack_paths(id) ON DELETE SET NULL,
  target_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
  scenario_id     TEXT NOT NULL,                      -- -> wargame_scenarios.id (global; no cross-tenant FK)
  -- What the replica is rebuilt from: {product, version, image, purl,
  -- source:'sbom'|'technology'|'image', config:{...}}.
  component       JSONB NOT NULL DEFAULT '{}'::jsonb,
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','building','proving','fixing',
                                    'verifying','done','refused','unsupported','error')),
  phase           TEXT,                               -- human-readable current phase
  before_verdict  TEXT CHECK (before_verdict IN ('vulnerable','not_vulnerable','inconclusive')),
  after_verdict   TEXT CHECK (after_verdict  IN ('vulnerable','not_vulnerable','inconclusive')),
  outcome         TEXT CHECK (outcome IN ('proven_exploitable','proven_fixed',
                                          'not_exploitable','inconclusive','refused','error')),
  -- The candidate fix exercised between before and after (version bump, config
  -- change). A reference, not a patch blob.
  fix_ref         TEXT,
  -- The isolation that held for this run: {backend, network_mode, egress:'none',
  -- replica_id, image_digest, started_at}. Written by the IsolationGuard.
  isolation       JSONB NOT NULL DEFAULT '{}'::jsonb,
  requested_by    TEXT NOT NULL DEFAULT 'system:wargame',
  reason          TEXT,                               -- refusal / error detail
  fingerprint     TEXT NOT NULL,                      -- stable dedupe key
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at    TIMESTAMPTZ,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  UNIQUE (tenant_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_wargame_runs_status
  ON wargame_runs (tenant_id, status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_wargame_runs_path
  ON wargame_runs (attack_path_id);
CREATE INDEX IF NOT EXISTS idx_wargame_runs_outcome
  ON wargame_runs (tenant_id, outcome) WHERE outcome IS NOT NULL;

-- =====================================================================
-- Proofs: append-only, hash-chained, signed.
-- Each run's proofs form a chain: entry_hash = sha256(prev_hash ||
-- payload_hash || phase || seq). The signature is a key-bound MAC over
-- entry_hash. A verifier replays the chain and checks each signature; it
-- cannot be forged or silently truncated.
-- =====================================================================
CREATE TABLE IF NOT EXISTS wargame_proofs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id        UUID NOT NULL REFERENCES wargame_runs(id) ON DELETE CASCADE,
  seq           INTEGER NOT NULL,                     -- 0,1,2,... within the run
  phase         TEXT NOT NULL CHECK (phase IN ('setup','before','fix','after','summary')),
  prev_hash     TEXT NOT NULL,                        -- hex; genesis = 64 zeros
  payload_hash  TEXT NOT NULL,                        -- sha256 of canonical payload
  entry_hash    TEXT NOT NULL,                        -- chain link
  signature     TEXT,                                 -- key-bound MAC over entry_hash
  key_id        TEXT,                                 -- which signing key produced it
  -- Redacted, size-capped evidence (same envelope as finding_verifications).
  payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  UNIQUE (tenant_id, run_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_wargame_proofs_run
  ON wargame_proofs (run_id, seq);

-- Append-only: a proof entry never changes once written (like
-- finding_verifications' immutability, but proofs are write-once -- any UPDATE
-- is refused).
CREATE OR REPLACE FUNCTION paddock_wargame_proof_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'wargame_proofs rows are append-only (id %)', OLD.id
    USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_wargame_proofs_immutable ON wargame_proofs;
CREATE TRIGGER trg_wargame_proofs_immutable
  BEFORE UPDATE ON wargame_proofs
  FOR EACH ROW EXECUTE FUNCTION paddock_wargame_proof_immutable();

-- =====================================================================
-- Service role: paddock_svc_wargame (least privilege). The 029 allow-list is
-- hardcoded and predates this service, so create + grant here, guarded.
--   reads   attack_paths, assets, asset_edges, findings, sbom_components,
--           sbom_component_vulns, choke_points
--   writes  wargame_runs, wargame_proofs
--   append  wargame_scenarios   (global catalogue; RLS limits writes to platform)
-- The orchestrator API (paddock_app) reads all three for the dashboard.
-- =====================================================================
DO $$
DECLARE
  r text := 'paddock_svc_wargame';
  t text;
  seq record;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB '
                   'NOCREATEROLE NOREPLICATION NOINHERIT', r);
  END IF;
  EXECUTE format('ALTER ROLE %I NOSUPERUSER NOBYPASSRLS', r);
  EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
  IF to_regclass('public.tenants') IS NOT NULL THEN
    EXECUTE format('GRANT SELECT ON public.tenants TO %I', r);
  END IF;

  FOREACH t IN ARRAY ARRAY['attack_paths','assets','asset_edges','findings',
                           'sbom_components','sbom_component_vulns','choke_points'] LOOP
    IF to_regclass('public.' || quote_ident(t)) IS NOT NULL THEN
      EXECUTE format('GRANT SELECT ON public.%I TO %I', t, r);
    END IF;
  END LOOP;

  EXECUTE format('GRANT SELECT, INSERT, UPDATE ON public.wargame_scenarios TO %I', r);

  FOREACH t IN ARRAY ARRAY['wargame_runs','wargame_proofs'] LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO %I', t, r);
    FOR seq IN
      SELECT s.oid::regclass AS sname
        FROM pg_class s
        JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a','i')
       WHERE s.relkind = 'S' AND d.refobjid = to_regclass('public.' || quote_ident(t))
    LOOP
      EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO %I', seq.sname, r);
    END LOOP;
  END LOOP;

  -- Orchestrator API reads the proving-ground tables for the UI.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_app') THEN
    EXECUTE 'GRANT SELECT ON public.wargame_scenarios TO paddock_app';
    EXECUTE 'GRANT SELECT ON public.wargame_runs TO paddock_app';
    EXECUTE 'GRANT SELECT ON public.wargame_proofs TO paddock_app';
  END IF;
END $$;
