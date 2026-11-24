-- 039: Provable Containment, P1. The persistent reach graph, declared zones and labels,
-- invariants with their run ledger, the per-tenant evaluation state, and the findings
-- rule_source 'invariant'. See docs/ASSURANCE_P1.md for the design.
--
--   reach_nodes       who can be a source/target (asset-backed, ip, cidr, internet)
--   reach_edges       directed "A may open connections to B" facts, each with a basis tier
--   reach_coverage    which nodes we know completely, per direction, per source, with a time
--   reach_flow_obs    aggregated passive flows from Sentry (input to the sentry_flow builder)
--   zones             tenant-declared zones (guest, pos, ...) with CIDRs
--   asset_labels      tenant-declared labels (zone, class, crown-jewel, app-tier) WITH provenance
--   invariants        the tenant's invariants (+ latest verdict); invariant_versions is append-only
--   invariant_runs    verdict transitions ledger
--   assurance_state   graph version, evaluation watermark and lease, one row per tenant
--
-- Runs BEFORE 099_tenancy.sql, which adds the tenant_id default / FK / RLS / policy to every
-- table (and is re-applied by the migration runner after this file). tenant_id is declared
-- here so UNIQUE constraints can name it; ON CONFLICT targets must include it.
-- Columns are deliberately plain (text/int/uuid/jsonb/text[]/timestamptz/bool, defaults on
-- everything optional) so the generic isolation-sweep row generator can fill them.

-- ---------------------------------------------------------------------------
-- findings.rule_source += 'invariant' (full list re-stated, as in 013)
-- ---------------------------------------------------------------------------
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_rule_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_rule_source_check CHECK (rule_source IN (
  'nuclei','cve_match','policy','chain','secret_scan','tls_check','header_check',
  'exposed_file','manual','takeover','tls_grade','sca','sast','threat_intel','invariant'
));

-- ---------------------------------------------------------------------------
-- Graph
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reach_nodes (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  node_ref   TEXT NOT NULL,                       -- 'internet' | 'asset:<uuid>' | 'ip:<addr>' | 'cidr:<cidr>'
  kind       TEXT NOT NULL DEFAULT 'host',        -- internet|host|cloud_instance|cloud_db|cloud_lb|device|ip|cidr
  label      TEXT NOT NULL DEFAULT '',
  asset_id   UUID,                                -- set when the node is an assets row
  attrs      JSONB NOT NULL DEFAULT '{}'::jsonb,  -- ips, cidr, account/region... (builder-defined)
  source     TEXT NOT NULL DEFAULT '',
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, node_ref)
);
CREATE INDEX IF NOT EXISTS idx_reach_nodes_asset ON reach_nodes (tenant_id, asset_id) WHERE asset_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS reach_edges (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  src_ref    TEXT NOT NULL,
  dst_ref    TEXT NOT NULL,
  proto      TEXT NOT NULL DEFAULT 'tcp' CHECK (proto IN ('icmp','tcp','udp','any')),
  port_lo    INTEGER NOT NULL DEFAULT 1,
  port_hi    INTEGER NOT NULL DEFAULT 65535,
  basis      TEXT NOT NULL DEFAULT 'configured' CHECK (basis IN ('declared','configured','observed','tested')),
  source     TEXT NOT NULL DEFAULT '',            -- aws_sg | external_scan | sentry_flow | declared | ...
  confidence SMALLINT NOT NULL DEFAULT 100,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  evidence   JSONB NOT NULL DEFAULT '{}'::jsonb,  -- ids of the assets/rules that justify it
  CHECK (port_lo >= 0 AND port_hi <= 65535 AND port_lo <= port_hi),
  UNIQUE (tenant_id, source, src_ref, dst_ref, proto, port_lo, port_hi)
);
CREATE INDEX IF NOT EXISTS idx_reach_edges_src ON reach_edges (tenant_id, src_ref);
CREATE INDEX IF NOT EXISTS idx_reach_edges_dst ON reach_edges (tenant_id, dst_ref);
CREATE INDEX IF NOT EXISTS idx_reach_edges_source_seen ON reach_edges (tenant_id, source, last_seen);

-- "We know every connection into / out of this node, as of observed_at, to this tier."
-- Coverage is per direction and per source: a security group's ingress rules cover INBOUND
-- only; an observer on a mirror port covers what it saw, at tier 'observed'.
CREATE TABLE IF NOT EXISTS reach_coverage (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  node_ref    TEXT NOT NULL,
  direction   TEXT NOT NULL DEFAULT 'in' CHECK (direction IN ('in','out')),
  source      TEXT NOT NULL DEFAULT '',
  tier        TEXT NOT NULL DEFAULT 'configured' CHECK (tier IN ('declared','configured','observed','tested')),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, node_ref, direction, source)
);
CREATE INDEX IF NOT EXISTS idx_reach_coverage_node ON reach_coverage (tenant_id, node_ref);

-- Aggregated passive flows posted by otdiscovery (one row per src,dst,proto,dst_port,sensor).
-- No FK on sensor_id on purpose: retention removes old rows; sensors can be revoked/deleted.
CREATE TABLE IF NOT EXISTS reach_flow_obs (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  src_ip     TEXT NOT NULL DEFAULT '',
  dst_ip     TEXT NOT NULL DEFAULT '',
  proto      TEXT NOT NULL DEFAULT 'tcp' CHECK (proto IN ('icmp','tcp','udp','any')),
  dst_port   INTEGER NOT NULL DEFAULT 0,
  sensor_id  UUID,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  packets    BIGINT NOT NULL DEFAULT 0,
  bytes      BIGINT NOT NULL DEFAULT 0,
  oriented   TEXT NOT NULL DEFAULT 'syn' CHECK (oriented IN ('syn','heuristic')),
  UNIQUE (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id)
);
CREATE INDEX IF NOT EXISTS idx_reach_flow_seen ON reach_flow_obs (tenant_id, last_seen);

-- ---------------------------------------------------------------------------
-- Declared zones and labels (tenant-controlled; every change carries who/why)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS zones (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'custom',
  cidrs       TEXT[] NOT NULL DEFAULT '{}',
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'declared',
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS asset_labels (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  node_ref      TEXT NOT NULL,
  tag           TEXT NOT NULL,                     -- zone | class | crown-jewel | app-tier | ...
  value         TEXT NOT NULL DEFAULT '',
  source        TEXT NOT NULL DEFAULT 'declared' CHECK (source IN ('declared','metadata','connector')),
  set_by        TEXT,
  justification TEXT NOT NULL DEFAULT '',
  set_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, node_ref, tag)
);

-- ---------------------------------------------------------------------------
-- Invariants
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS invariants (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  invariant_id       TEXT NOT NULL,                -- 'std:no-internet-to-datastore' | 'acme:my-rule'
  title              TEXT NOT NULL DEFAULT '',
  severity           TEXT NOT NULL DEFAULT 'high',
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  source             TEXT NOT NULL DEFAULT 'custom' CHECK (source IN ('std','custom')),
  yaml               TEXT NOT NULL DEFAULT '',
  digest             TEXT NOT NULL DEFAULT '',
  version            INTEGER NOT NULL DEFAULT 1,
  last_verdict       TEXT CHECK (last_verdict IN ('HOLDS','VIOLATED','UNKNOWN')),
  last_result        JSONB,
  last_graph_version BIGINT,
  last_evaluated_at  TIMESTAMPTZ,
  valid_until        TIMESTAMPTZ,
  created_by         TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by         TEXT,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, invariant_id)
);

-- Append-only: every distinct definition ever active (digest-addressed).
CREATE TABLE IF NOT EXISTS invariant_versions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  invariant_id TEXT NOT NULL DEFAULT '',
  digest       TEXT NOT NULL DEFAULT '',
  version      INTEGER NOT NULL DEFAULT 1,
  yaml         TEXT NOT NULL DEFAULT '',
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, invariant_id, digest)
);

-- Verdict transitions (and at most one heartbeat row per day), not every evaluation.
CREATE TABLE IF NOT EXISTS invariant_runs (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  invariant_id      TEXT NOT NULL DEFAULT '',
  digest            TEXT NOT NULL DEFAULT '',
  verdict           TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (verdict IN ('HOLDS','VIOLATED','UNKNOWN')),
  reasons           JSONB NOT NULL DEFAULT '[]'::jsonb,
  result            JSONB NOT NULL DEFAULT '{}'::jsonb,
  graph_version     BIGINT NOT NULL DEFAULT 0,
  violation_count   INTEGER NOT NULL DEFAULT 0,
  coverage_covered  INTEGER NOT NULL DEFAULT 0,
  coverage_universe INTEGER NOT NULL DEFAULT 0,
  evaluated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  valid_until       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_invariant_runs_inv ON invariant_runs (tenant_id, invariant_id, evaluated_at DESC);

-- One row per tenant: the graph version (bumped when a builder changes anything), the last
-- evaluated version, and a lease so N orchestrator replicas never evaluate the same tenant twice.
CREATE TABLE IF NOT EXISTS assurance_state (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL UNIQUE DEFAULT '00000000-0000-0000-0000-000000000001',
  graph_version     BIGINT NOT NULL DEFAULT 0,
  last_build_at     TIMESTAMPTZ,
  last_eval_at      TIMESTAMPTZ,
  last_eval_version BIGINT NOT NULL DEFAULT -1,
  lease_until       TIMESTAMPTZ,
  lease_owner       TEXT
);
