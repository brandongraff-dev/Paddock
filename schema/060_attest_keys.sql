-- 060: provable containment P3, estates, keys, sealed secrets, revocations (docs/ASSURANCE_P3.md 5.1, 5.8, 3.5).
--
-- Runs BEFORE 099, which adds the tenant_id default, the tenant FK and RLS to every table here. Sweep rules (as P2):
-- tenant_id is declared with a default and sits in every UNIQUE; no NOT NULL column without a default carries a
-- length/regex CHECK (defaults are '' and the CHECKs allow ''); ON CONFLICT targets include tenant_id.
-- Migrations 065 to 069 are reserved (transparency log, per-publication keys, BYOK registration, profiles).

-- One row per tenant, created lazily and idempotently by attest.estate.ensure_estate().
CREATE TABLE IF NOT EXISTS attest_estates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL UNIQUE DEFAULT '00000000-0000-0000-0000-000000000001',
  estate_id TEXT NOT NULL DEFAULT '' CHECK (estate_id = '' OR estate_id ~ '^e_[a-z2-7]{26}$'),
  ttl_h INTEGER NOT NULL DEFAULT 24 CHECK (ttl_h BETWEEN 1 AND 72),
  issuing_suspended BOOLEAN NOT NULL DEFAULT FALSE,
  hold_reason TEXT NOT NULL DEFAULT '' CHECK (octet_length(hold_reason) <= 64),
  hold_requires_ack BOOLEAN NOT NULL DEFAULT FALSE,
  hold_set_at TIMESTAMPTZ,
  revocation_seq BIGINT NOT NULL DEFAULT 0,
  revocation_doc JSONB NOT NULL DEFAULT '{}'::jsonb,
  revocation_signed_at TIMESTAMPTZ,
  anchor_v2_since BIGINT,
  lease_until TIMESTAMPTZ,
  lease_owner TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Public identity of every estate key. Never holds private material (that is attest_key_secrets, below).
CREATE TABLE IF NOT EXISTS attest_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  kid TEXT NOT NULL DEFAULT '' CHECK (kid = '' OR kid ~ '^[0-9a-f]{32}$'),
  usage TEXT NOT NULL DEFAULT 'attest' CHECK (usage IN ('attest', 'anchor')),
  alg TEXT NOT NULL DEFAULT 'ed25519' CHECK (alg IN ('ed25519', 'ecdsa-p256-sha256')),   -- only ed25519 is enabled in v1
  public_key BYTEA NOT NULL DEFAULT '' CHECK (octet_length(public_key) IN (0, 32, 33)),
  custody TEXT NOT NULL DEFAULT 'hosted' CHECK (custody IN ('hosted', 'byok-kms', 'byok-hsm')),
  backend TEXT NOT NULL DEFAULT 'local-aes-gcm',
  key_ref TEXT NOT NULL DEFAULT '',                                                      -- '' for local; a KMS ARN later
  publication_id UUID,                                                                   -- NULL = estate-wide (v1)
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'retiring', 'retired', 'revoked')),
  not_before TIMESTAMPTZ,
  not_after TIMESTAMPTZ,
  cert JSONB NOT NULL DEFAULT '{}'::jsonb,
  cert_serial BIGINT NOT NULL DEFAULT 0,
  cert_expires_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  activated_at TIMESTAMPTZ,
  retired_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  UNIQUE (tenant_id, kid)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_attest_keys_one_active ON attest_keys (tenant_id, usage)
  WHERE status = 'active' AND publication_id IS NULL;

-- The ONLY copy of sealed key material; deleting a row is the crypto-erase. Only attest/crypto.py and
-- attest/backend_local.py may name this table (a lint test enforces it). `sealed` is an AES-256-GCM blob under the
-- dedicated attestation KEK with AAD binding tenant, kind, kid, usage and alg.
CREATE TABLE IF NOT EXISTS attest_key_secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  kind TEXT NOT NULL DEFAULT 'signing' CHECK (kind IN ('signing', 'commit')),
  kid TEXT NOT NULL DEFAULT '',                          -- 'commit' for the commit key
  sealed TEXT NOT NULL DEFAULT '',
  kek_id TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, kind, kid)
);

-- Strictly append-only (trigger in 064).
CREATE TABLE IF NOT EXISTS attest_revocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  kid TEXT NOT NULL DEFAULT '',
  reason_code TEXT NOT NULL DEFAULT 'superseded' CHECK (reason_code IN ('key_compromise', 'superseded', 'cessation')),
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor TEXT,
  justification TEXT NOT NULL DEFAULT '',
  UNIQUE (tenant_id, kid)
);
