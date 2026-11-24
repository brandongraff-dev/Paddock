-- 039: AI features. One install-wide row holding the optional Anthropic API key
-- an admin pastes into Settings -> System, so no .env editing is needed.
--
-- The key is stored ENCRYPTED (AES-256-GCM with PADDOCK_SECRET_KEY, the same
-- scheme as integration credentials; see app/integrations/secrets.py) and is
-- never returned to a browser: the API only reports "configured" and the last
-- four characters. The brain service fetches it from the orchestrator with the
-- fleet service key when it needs to call the model.
--
-- A global (platform-wide) table: every tenant's AI triage uses the operator's
-- key, so only the platform (default) tenant may write it. 099_tenancy.sql adds
-- the RLS policies from the marker below. Idempotent.

CREATE TABLE IF NOT EXISTS ai_settings (
    id                BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),   -- exactly one row
    anthropic_secret  TEXT,                                          -- v1:<key_id>:<b64>
    key_hint          TEXT,                                          -- last 4 characters
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE ai_settings IS '@paddock:global operator-wide AI settings (encrypted Anthropic key); only the platform tenant writes it';
