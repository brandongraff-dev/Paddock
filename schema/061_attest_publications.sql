-- 061: provable containment P3, domain bindings and publications (docs/ASSURANCE_P3.md 5.1, 5.8).

CREATE TABLE IF NOT EXISTS attest_domains (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  domain TEXT NOT NULL DEFAULT '' CHECK (domain = '' OR domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  domain_key TEXT NOT NULL DEFAULT '' CHECK (domain_key = '' OR domain_key ~ '^[0-9a-f]{64}$'),   -- sha256(domain)
  scope_entry_id INTEGER REFERENCES scope_entries(id) ON DELETE SET NULL,
  binding_status TEXT NOT NULL DEFAULT 'pending' CHECK (binding_status IN ('pending', 'verified', 'failing', 'failed')),
  last_checked_at TIMESTAMPTZ,
  last_ok_at TIMESTAMPTZ,
  failing_since TIMESTAMPTZ,
  last_error TEXT,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,           -- {observed_at, ttl, records, matched_kid, ad, resolver}
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, domain)
);

-- The unit of issuance (D2): one chain, one subject, one disclosure profile. Limits (1 estate publication, 10 domain
-- publications) are enforced by the application; UNIQUE (tenant_id, subject_kind, domain) holds the estate one.
CREATE TABLE IF NOT EXISTS attest_publications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  subject_kind TEXT NOT NULL DEFAULT 'estate' CHECK (subject_kind IN ('estate', 'domain')),
  domain TEXT NOT NULL DEFAULT '' CHECK (domain = '' OR domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  domain_key TEXT NOT NULL DEFAULT '' CHECK (domain_key = '' OR domain_key ~ '^[0-9a-f]{64}$'),
  verdicts TEXT NOT NULL DEFAULT 'holds_only' CHECK (verdicts IN ('holds_only', 'all')),
  disclose_custom BOOLEAN NOT NULL DEFAULT FALSE,
  published BOOLEAN NOT NULL DEFAULT FALSE,
  serving BOOLEAN NOT NULL DEFAULT FALSE,
  serving_reason TEXT NOT NULL DEFAULT '' CHECK (octet_length(serving_reason) <= 64),
  last_seq BIGINT NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  head_digest TEXT NOT NULL DEFAULT '',
  head_issued_at TIMESTAMPTZ,
  head_valid_until TIMESTAMPTZ,
  next_due_at TIMESTAMPTZ,
  trigger_digest TEXT NOT NULL DEFAULT '',
  last_refused_reason TEXT NOT NULL DEFAULT '',
  last_refused_at TIMESTAMPTZ,
  published_at TIMESTAMPTZ,
  published_by TEXT,
  archived_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, subject_kind, domain),
  -- an estate publication names no domain, a domain publication always does
  CHECK ((subject_kind = 'estate' AND domain = '') OR (subject_kind = 'domain' AND domain <> ''))
);
