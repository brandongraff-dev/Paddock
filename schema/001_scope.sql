-- Scope: the allowlist of authorized targets.
-- No worker is permitted to emit a packet toward a target that doesn't match
-- an active entry here. Enforcement is at dispatch AND at the per-request layer.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS scope_entries (
  id            SERIAL PRIMARY KEY,
  kind          TEXT NOT NULL CHECK (kind IN ('domain', 'subdomain_wildcard', 'ipv4_cidr', 'ipv6_cidr', 'asn')),
  value         TEXT NOT NULL,
  auth_doc_ref  TEXT,
  added_by      TEXT NOT NULL,
  added_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ,
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  notes         TEXT,
  UNIQUE (kind, value)
);

CREATE INDEX IF NOT EXISTS idx_scope_active ON scope_entries(active, kind);

-- Every scope decision gets logged, allow or deny. This is the auditable
-- record you show an employer / an auditor / your own future self.
CREATE TABLE IF NOT EXISTS scope_decisions (
  id             BIGSERIAL PRIMARY KEY,
  target         TEXT NOT NULL,
  normalized     TEXT NOT NULL,
  decision       TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
  matched_entry  INTEGER REFERENCES scope_entries(id),
  worker         TEXT NOT NULL,
  reason         TEXT,
  decided_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scope_decisions_ts ON scope_decisions(decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_scope_decisions_target ON scope_decisions(target, decided_at DESC);
