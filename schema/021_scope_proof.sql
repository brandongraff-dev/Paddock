-- 021: proof-of-control for scope + first-run onboarding state.
--
-- A scope entry says "we are allowed to scan this". In a hosted scanner that
-- claim must be PROVEN, ACME-style, before it authorises a single packet:
--
--   domain / subdomain_wildcard  -> DNS TXT  _paddock-challenge.<domain> = <token>
--                                   or (domain only) an HTTPS file at
--                                   /.well-known/paddock-verification/<token>
--   ipv4_cidr / ipv6_cidr / asn  -> no automatic proof exists; an admin records
--                                   an attestation: the authorization (LOA)
--                                   reference, the named approver, who/when.
--
-- When REQUIRE_SCOPE_PROOF=true, only entries whose proof status is
-- 'verified' or 'attested' ever match in scope.check(). An entry with no row
-- here is 'pending'. The orchestrator scheduler re-verifies proofs and expires
-- ones that disappear for longer than the grace period.
--
-- Idempotent: safe to apply on top of an existing database.

CREATE TABLE IF NOT EXISTS scope_proofs (
  scope_entry_id       INTEGER PRIMARY KEY REFERENCES scope_entries(id) ON DELETE CASCADE,
  status               TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'verified', 'attested', 'expired')),
  -- How the current (or last) proof was established.
  method               TEXT CHECK (method IN ('dns_txt', 'http_file', 'attestation')),
  -- Per-entry random challenge. Never reused across entries, so a token that is
  -- publicly visible in DNS can't prove a different entry.
  token                TEXT,
  token_issued_at      TIMESTAMPTZ,
  verified_at          TIMESTAMPTZ,          -- first successful automatic proof
  last_checked_at      TIMESTAMPTZ,
  last_ok_at           TIMESTAMPTZ,
  last_error           TEXT,
  -- Set when a previously valid proof starts failing; cleared on success.
  -- The entry keeps authorising scans until failing_since + grace.
  failing_since        TIMESTAMPTZ,
  expired_at           TIMESTAMPTZ,
  -- Attestation (IP ranges / ASN).
  loa_ref              TEXT,
  approver             TEXT,
  attested_by          TEXT,
  attested_at          TIMESTAMPTZ,
  attestation_expires_at TIMESTAMPTZ,
  -- Last N verification attempts: [{at, method, ok, detail, by}].
  history              JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scope_proofs_status ON scope_proofs(status, last_checked_at);

-- First-run wizard progress. Single-tenant today, so exactly one row (id = 1).
CREATE TABLE IF NOT EXISTS onboarding (
  id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  workspace_name  TEXT,
  current_step    TEXT NOT NULL DEFAULT 'workspace',
  steps_done      TEXT[] NOT NULL DEFAULT '{}',
  scope_entry_id  INTEGER REFERENCES scope_entries(id) ON DELETE SET NULL,
  first_scan_id   UUID,
  dismissed       BOOLEAN NOT NULL DEFAULT FALSE,
  completed_at    TIMESTAMPTZ,
  updated_by      TEXT,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO onboarding (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
