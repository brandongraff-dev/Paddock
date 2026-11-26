-- 062: provable containment P3, the statement ledger, anchors, disclosure material and pre-rendered public objects
-- (docs/ASSURANCE_P3.md 5.4, 5.8, 5.9, 6.3). The ledger is append-only (triggers in 064).

CREATE TABLE IF NOT EXISTS attest_statements (            -- the private source of truth
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  publication_id UUID NOT NULL DEFAULT gen_random_uuid(),
  seq BIGINT NOT NULL DEFAULT 0 CHECK (seq >= 0),
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  valid_until TIMESTAMPTZ,
  snapshot_at TIMESTAMPTZ,
  kid TEXT NOT NULL DEFAULT '',
  statement_digest TEXT NOT NULL DEFAULT '',              -- sha256 hex of the payload bytes
  prev_digest TEXT NOT NULL DEFAULT '',
  trigger_digest TEXT NOT NULL DEFAULT '',
  graph_root TEXT NOT NULL DEFAULT '',
  policy_commitment TEXT NOT NULL DEFAULT '',
  anchor_max_id BIGINT,
  envelope BYTEA NOT NULL DEFAULT '' CHECK (octet_length(envelope) <= 524288),   -- the exact served bytes
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,             -- [{id,digest,verdict,tier}], verdict_counts, disclosed, total, limiting_invariants
  idempotency_key TEXT,
  UNIQUE (tenant_id, publication_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_attest_stmt_idem ON attest_statements (tenant_id, publication_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS attest_anchors (               -- public-form anchors referenced by statements
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  max_id BIGINT NOT NULL DEFAULT 0,
  at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  doc JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, max_id, at)
);

CREATE TABLE IF NOT EXISTS attest_disclosures (           -- encrypted leaf material per statement (5.9)
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  publication_id UUID NOT NULL DEFAULT gen_random_uuid(),
  seq BIGINT NOT NULL DEFAULT 0,
  pinned BOOLEAN NOT NULL DEFAULT FALSE,
  leaves INTEGER NOT NULL DEFAULT 0,
  blob BYTEA NOT NULL DEFAULT '' CHECK (octet_length(blob) <= 67108864),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, publication_id, seq)
);

-- Pre-rendered public bytes: what hosted serving reads (D22). Public routes never read live tenant tables.
CREATE TABLE IF NOT EXISTS attest_bundle_objects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  publication_id UUID NOT NULL DEFAULT gen_random_uuid(),
  domain_key TEXT NOT NULL DEFAULT '' CHECK (domain_key = '' OR domain_key ~ '^[0-9a-f]{64}$'),
  path TEXT NOT NULL DEFAULT '' CHECK (octet_length(path) <= 128),
  content_type TEXT NOT NULL DEFAULT 'application/json',
  cache_control TEXT NOT NULL DEFAULT '',
  etag TEXT NOT NULL DEFAULT '',
  body BYTEA NOT NULL DEFAULT '' CHECK (octet_length(body) <= 524288),
  public BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, publication_id, path)
);
-- GLOBAL on purpose (no tenant_id): one domain is served from one place. Registered in GLOBAL_UNIQUE_OK of
-- tests/test_isolation_keys.py.
CREATE UNIQUE INDEX IF NOT EXISTS uq_attest_public_object ON attest_bundle_objects (domain_key, path) WHERE public;

-- The one extra permissive policy: a narrow, exact-match, SELECT-only lookup for the public route (the trust_links
-- pattern). It needs BOTH GUCs set on the connection (app.attest_lookup = 'on', app.attest_domain = sha256(domain)),
-- shows only rows already marked public, and never a row with an empty domain key. No WITH CHECK, so it cannot write.
ALTER TABLE attest_bundle_objects ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS attest_public_lookup ON attest_bundle_objects;
CREATE POLICY attest_public_lookup ON attest_bundle_objects FOR SELECT
  USING (current_setting('app.attest_lookup', true) = 'on'
         AND public
         AND domain_key <> ''
         AND domain_key = current_setting('app.attest_domain', true));
