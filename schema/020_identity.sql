-- 020: enterprise identity -- OIDC / SAML single sign-on and SCIM 2.0
-- provisioning (see orchestrator/app/identity and docs/SSO.md).
--
-- Secrets: IdP client secrets live in identity_providers.secrets as an
-- AES-GCM blob (app.integrations.secrets). SCIM bearer tokens, SSO state
-- values and one-time exchange codes are stored only as sha256 hashes.

-- ---------------------------------------------------------------------
-- app_users: provisioning metadata + a session-revocation watermark.
-- Every JWT whose iat <= sessions_revoked_at is rejected per request
-- (auth._principal_from_jwt), so deactivation / role changes take effect
-- immediately, and re-activating a user never revives an old token.
-- ---------------------------------------------------------------------
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS external_id TEXT;         -- SCIM externalId (Okta user id / Entra objectId)
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS given_name TEXT;
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS family_name TEXT;
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS provisioned_by TEXT;      -- NULL/'local' | 'scim' | 'sso:<slug>'
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS sessions_revoked_at TIMESTAMPTZ;
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_app_users_external_id ON app_users(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_app_users_email_lower ON app_users(lower(email));

-- ---------------------------------------------------------------------
-- Identity providers (OIDC + SAML), many per deployment.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_providers (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug              TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  kind              TEXT NOT NULL CHECK (kind IN ('oidc','saml')),
  preset            TEXT NOT NULL DEFAULT 'generic'
                      CHECK (preset IN ('generic','okta','entra','google','auth0','keycloak')),
  display_name      TEXT NOT NULL,
  enabled           BOOLEAN NOT NULL DEFAULT TRUE,
  -- NON-secret protocol settings (issuer, client_id, scopes, SAML entity id,
  -- SSO URL, IdP signing cert, attribute names ...).
  config            JSONB NOT NULL DEFAULT '{}'::jsonb,
  secrets           TEXT,                                 -- AES-GCM blob: {"client_secret": ...}
  allowed_domains   TEXT[] NOT NULL DEFAULT '{}',         -- empty = any domain
  jit_provisioning  BOOLEAN NOT NULL DEFAULT TRUE,
  sync_roles        BOOLEAN NOT NULL DEFAULT TRUE,        -- re-apply mapping on every login
  require_mapping   BOOLEAN NOT NULL DEFAULT FALSE,       -- deny login when no mapping matches
  default_role      TEXT NOT NULL DEFAULT 'viewer'
                      CHECK (default_role IN ('viewer','analyst','admin','auditor')),
  default_clearance TEXT NOT NULL DEFAULT 'internal'
                      CHECK (default_clearance IN ('public','internal','confidential','restricted')),
  groups_claim      TEXT NOT NULL DEFAULT 'groups',
  -- ordered list, first match wins: [{"group": "...", "role": "...", "clearance": "..."}]
  role_mappings     JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by        TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- External identity -> local user link.
CREATE TABLE IF NOT EXISTS user_identities (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  provider_id  UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
  subject      TEXT NOT NULL,                             -- OIDC sub / SAML NameID
  email        TEXT,
  groups       TEXT[] NOT NULL DEFAULT '{}',              -- as of last login
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login   TIMESTAMPTZ,
  UNIQUE (provider_id, subject)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities(user_id);

-- In-flight SP-initiated logins. Single use: deleted when the callback runs.
CREATE TABLE IF NOT EXISTS sso_login_states (
  state_hash      TEXT PRIMARY KEY,                       -- sha256(state)
  provider_id     UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
  nonce           TEXT NOT NULL,                          -- OIDC nonce / SAML AuthnRequest ID
  code_verifier   TEXT,                                   -- OIDC PKCE verifier
  spa_challenge   TEXT,                                   -- sha256(SPA verifier), binds the exchange code
  return_to       TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sso_login_states_exp ON sso_login_states(expires_at);

-- One-time codes the SPA exchanges for a Paddock JWT (never a token in a URL).
CREATE TABLE IF NOT EXISTS sso_exchange_codes (
  code_hash       TEXT PRIMARY KEY,                       -- sha256(code)
  user_id         UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  provider_id     UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
  spa_challenge   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL
);

-- Replay cache: consumed SAML assertion IDs / OIDC nonces until they expire.
CREATE TABLE IF NOT EXISTS sso_replay_cache (
  key         TEXT PRIMARY KEY,
  expires_at  TIMESTAMPTZ NOT NULL
);

-- Deployment-wide identity policy (singleton row).
CREATE TABLE IF NOT EXISTS identity_settings (
  id                      BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  sso_required            BOOLEAN NOT NULL DEFAULT FALSE,
  break_glass_users       TEXT[] NOT NULL DEFAULT ARRAY['admin']::TEXT[],
  -- SCIM group (displayName) -> role/clearance, first match wins. Empty =
  -- SCIM never changes roles.
  scim_role_mappings      JSONB NOT NULL DEFAULT '[]'::jsonb,
  scim_default_role       TEXT NOT NULL DEFAULT 'viewer'
                            CHECK (scim_default_role IN ('viewer','analyst','admin','auditor')),
  scim_default_clearance  TEXT NOT NULL DEFAULT 'internal'
                            CHECK (scim_default_clearance IN ('public','internal','confidential','restricted')),
  updated_by              TEXT,
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO identity_settings (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------
-- SCIM 2.0
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scim_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  prefix      TEXT NOT NULL UNIQUE,
  token_hash  TEXT NOT NULL UNIQUE,                       -- sha256 of the full token
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used   TIMESTAMPTZ,
  expires_at  TIMESTAMPTZ,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS scim_groups (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name  TEXT NOT NULL UNIQUE,
  external_id   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_group_members (
  group_id  UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members(user_id);
