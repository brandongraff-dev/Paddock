-- 045: Provable Containment P2.1, section D: the identity trust root. See docs/ASSURANCE_P2_1.md 4.2 (D26 to D30).
--
--   fleet_agent_pairings  a LEDGER of "agent row A is the machine that is cloud asset X", asserted by an admin with a
--                         justification. Rows are never deleted or re-pointed; only status / ended_* change. The partial
--                         unique indexes let the DATABASE, not the app, forbid two agents on one asset (attack 19).
--   fleet_conflict_acks   one acknowledgement per (agent, kind, proto, port) of a scan conflict, bound to the observation
--                         the operator looked at (through_seen_at); a LATER observation is not covered (D30).
--
-- Runs BEFORE 099_tenancy.sql, which adds the tenant_id default / FK / RLS / tenant_isolation policy (and is re-applied by
-- the runner). No `auth_lookup` policy: both tables are only ever read inside a tenant context. No data backfill. The
-- sweep rules of 041 hold: tenant_id with a default and in every UNIQUE, every NOT NULL column has a default (so the
-- justification length is enforced by the application: a length CHECK would break the generic row generator), no global
-- UNIQUE. These are TENANT tables: they must never carry the global marker.

CREATE TABLE IF NOT EXISTS fleet_agent_pairings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id        UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  asset_id        UUID NOT NULL DEFAULT gen_random_uuid(),   -- assets.id; NO FK on purpose: a deleted asset makes the pairing inert, not erased
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','ended')),
  justification   TEXT NOT NULL DEFAULT '',                  -- >= 3 characters enforced by the app
  paired_by       TEXT NOT NULL DEFAULT '',
  paired_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  asset_canonical TEXT NOT NULL DEFAULT '',                  -- ARN snapshot for the audit trail
  checks          JSONB NOT NULL DEFAULT '{}'::jsonb,        -- what the server compared at pairing time
  ended_at        TIMESTAMPTZ,
  ended_by        TEXT,
  ended_reason    TEXT NOT NULL DEFAULT '',                  -- unpaired | agent_revoked | rekeyed | superseded
  CONSTRAINT fleet_agent_pairings_end_chk CHECK ((status = 'ended') = (ended_at IS NOT NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS uq_pairing_active_agent ON fleet_agent_pairings (tenant_id, agent_id) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_pairing_active_asset ON fleet_agent_pairings (tenant_id, asset_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_pairing_agent ON fleet_agent_pairings (tenant_id, agent_id, paired_at DESC);
-- a ledger: rows are never deleted or re-pointed; only status / ended_* change.

CREATE TABLE IF NOT EXISTS fleet_conflict_acks (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id        UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL DEFAULT 'agent_closed_scan_open' CHECK (kind IN ('agent_closed_scan_open')),
  proto           TEXT NOT NULL DEFAULT 'tcp' CHECK (proto IN ('tcp','udp')),      -- conflicts are expanded per proto ('any' scan edges -> tcp+udp)
  port            INTEGER NOT NULL DEFAULT 1 CHECK (port BETWEEN 1 AND 65535),
  through_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),                              -- the newest scan observation of this (proto, port) the operator looked at
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','cleared','superseded','expired')),
  justification   TEXT NOT NULL DEFAULT '',
  acked_by        TEXT NOT NULL DEFAULT '',
  acked_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
  cleared_by      TEXT,
  cleared_at      TIMESTAMPTZ,
  cleared_reason  TEXT NOT NULL DEFAULT '',
  evidence        JSONB NOT NULL DEFAULT '{}'::jsonb);                             -- the conflict record as shown to the operator
CREATE UNIQUE INDEX IF NOT EXISTS uq_conflict_ack_active ON fleet_conflict_acks (tenant_id, agent_id, kind, proto, port) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_conflict_ack_agent ON fleet_conflict_acks (tenant_id, agent_id, status, expires_at);
