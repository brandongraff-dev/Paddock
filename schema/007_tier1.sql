-- Tier 1 intelligence: attack-path analysis + change intelligence.
-- Applied after 001-006 (alphabetical init order).

-- =====================================================================
-- Attack paths
-- A path is a weighted route through the asset graph from an
-- internet-facing source to a crown-jewel target. Computed by the
-- correlation service; read by the orchestrator API.
-- =====================================================================
CREATE TABLE IF NOT EXISTS attack_paths (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_asset_id  UUID REFERENCES assets(id) ON DELETE CASCADE,
  target_asset_id  UUID REFERENCES assets(id) ON DELETE CASCADE,
  -- ordered hops: [{asset_id, kind, value, edge_kind_in, entry_cost, finding_ids:[], max_severity}]
  hops             JSONB NOT NULL DEFAULT '[]'::jsonb,
  length           SMALLINT NOT NULL,
  total_cost       NUMERIC(8,2) NOT NULL,
  exploitability   NUMERIC(5,2) NOT NULL,   -- 0-100, higher = easier to walk
  severity         TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  title            TEXT NOT NULL,
  narrative        TEXT,
  kev_on_path      BOOLEAN NOT NULL DEFAULT FALSE,
  fingerprint      TEXT NOT NULL,           -- stable hash of the hop asset_id sequence
  computed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_exploit ON attack_paths(exploitability DESC);
CREATE INDEX IF NOT EXISTS idx_attack_paths_severity ON attack_paths(severity);
CREATE INDEX IF NOT EXISTS idx_attack_paths_source ON attack_paths(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_target ON attack_paths(target_asset_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_computed ON attack_paths(computed_at DESC);

-- =====================================================================
-- Change intelligence
-- surface_changes is the ledger of everything that changed in the
-- attack surface over time. Written by the changewatch service.
-- =====================================================================
CREATE TABLE IF NOT EXISTS surface_changes (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  change_type   TEXT NOT NULL CHECK (change_type IN (
                  'subdomain_discovered', 'endpoint_discovered', 'ip_discovered',
                  'port_opened', 'port_closed', 'tech_detected', 'tech_version_changed',
                  'cert_added', 'cert_expiring', 'secret_found', 'repository_found',
                  'finding_opened', 'finding_resolved', 'exposure_increased',
                  'asset_removed', 'chain_detected', 'attack_path_found'
                )),
  asset_id      UUID REFERENCES assets(id) ON DELETE SET NULL,
  asset_kind    TEXT,
  asset_value   TEXT,
  severity      TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','low','medium','high','critical')),
  summary       TEXT NOT NULL,
  detail        JSONB NOT NULL DEFAULT '{}'::jsonb,
  detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acknowledged  BOOLEAN NOT NULL DEFAULT FALSE,
  ack_by        TEXT,
  ack_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_changes_detected ON surface_changes(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_changes_type ON surface_changes(change_type);
CREATE INDEX IF NOT EXISTS idx_changes_severity ON surface_changes(severity, acknowledged);
CREATE INDEX IF NOT EXISTS idx_changes_unack ON surface_changes(acknowledged) WHERE NOT acknowledged;

-- Alert rules + delivery log for change intelligence.
CREATE TABLE IF NOT EXISTS alert_rules (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  -- match: {change_types:[...], min_severity:'high', kinds:[...]}  (all optional, AND-ed)
  match        JSONB NOT NULL DEFAULT '{}'::jsonb,
  channel      TEXT NOT NULL CHECK (channel IN ('log','webhook','slack')),
  target       TEXT,                 -- webhook/slack URL. Treat as a secret in prod.
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_fired   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);

CREATE TABLE IF NOT EXISTS alert_deliveries (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id       UUID REFERENCES alert_rules(id) ON DELETE CASCADE,
  change_id     UUID REFERENCES surface_changes(id) ON DELETE CASCADE,
  status        TEXT NOT NULL CHECK (status IN ('sent','failed','suppressed')),
  channel       TEXT NOT NULL,
  response      TEXT,
  delivered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_deliveries_rule ON alert_deliveries(rule_id, delivered_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_change ON alert_deliveries(change_id);

-- changewatch keeps its cursor here too (reuses intel_cursors).
INSERT INTO intel_cursors (source, last_synced)
VALUES ('changewatch', NOW() - INTERVAL '1 day')
ON CONFLICT (source) DO NOTHING;
