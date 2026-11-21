-- 031: cloud SOURCE connectors (GCP, Azure) -- scope suggestions.
-- Applied after 025_context_connectors.sql. Purely additive.
--
-- A cloud inventory sees internet-facing names and addresses (public IPs,
-- load balancers, Cloud Run URLs, DNS zones) that the customer may want in
-- their scan scope. Connectors NEVER add scope themselves: they leave a
-- suggestion here, and a human accepts it through the normal scope add
-- (routers/scope.py add_scope: validation, audit, cache invalidation) which
-- still requires proof-of-control (schema 021) before anything is scanned.
CREATE TABLE IF NOT EXISTS scope_suggestions (
  id              BIGSERIAL PRIMARY KEY,
  integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  source          TEXT NOT NULL,                       -- 'integration:gcp'
  kind            TEXT NOT NULL CHECK (kind IN
                  ('domain', 'subdomain_wildcard', 'ipv4_cidr', 'ipv6_cidr', 'asn')),
  value           TEXT NOT NULL,
  evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,  -- what the cloud said (resource, project...)
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'accepted', 'dismissed')),
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_by      TEXT,
  decided_at      TIMESTAMPTZ,
  scope_entry_id  INTEGER REFERENCES scope_entries(id) ON DELETE SET NULL,
  UNIQUE (integration_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_scope_suggestions_status
  ON scope_suggestions (status, last_seen DESC);
