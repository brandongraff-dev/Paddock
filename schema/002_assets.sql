-- Asset graph: the intelligence layer.
-- Everything discovered (domains, hosts, services, techs, certs, endpoints,
-- repositories, secret candidates) is a node. Relationships are edges.
-- Temporal (first_seen / last_seen) so diffing over time is trivial.

CREATE TABLE IF NOT EXISTS assets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        TEXT NOT NULL CHECK (kind IN (
                'org', 'domain', 'subdomain', 'ipv4', 'ipv6',
                'port', 'service', 'technology', 'certificate',
                'endpoint', 'repository', 'secret_candidate',
                'cloud_account', 'cloud_resource'
              )),
  value       TEXT NOT NULL,
  canonical   TEXT NOT NULL,
  first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confidence  SMALLINT NOT NULL DEFAULT 100 CHECK (confidence BETWEEN 0 AND 100),
  source      TEXT NOT NULL,
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (kind, canonical)
);

CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);
CREATE INDEX IF NOT EXISTS idx_assets_canonical ON assets(canonical);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_assets_metadata_gin ON assets USING GIN (metadata);

-- Edges: resolves_to, hosts, runs, has_version, contains, owns, issued_for, references
CREATE TABLE IF NOT EXISTS asset_edges (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  src_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  dst_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (src_id, dst_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_edges_src ON asset_edges(src_id, kind);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON asset_edges(dst_id, kind);

-- Snapshots: materialized view of asset counts per day, feeds the timeline UI.
CREATE TABLE IF NOT EXISTS asset_snapshots (
  snapshot_date DATE NOT NULL,
  kind          TEXT NOT NULL,
  count         INTEGER NOT NULL,
  PRIMARY KEY (snapshot_date, kind)
);
