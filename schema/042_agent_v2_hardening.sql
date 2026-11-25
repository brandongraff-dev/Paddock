-- 042: P2 hardening of the server wire / enrollment path (docs/ASSURANCE_P2.md, adversarial review package B).
--
--   fleet_agent_keys.rotated_from   the key id this key replaced (set when a rotate envelope registers it), so a
--                                   revoke of a rotated key can name, and on request revoke, the active successors
--                                   (wire-7). Plain TEXT, no FK: it is a pointer for the operator, not an invariant.
--   fleet_agents.enroll_token_id    the enrollment token an agent was FIRST enrolled with, so revoking the agent can
--                                   revoke that (multi-use) token too (enroll-6). A re-key does not overwrite it.
--
-- Both nullable with no default, so the generic isolation-sweep row generator needs nothing. Runs BEFORE
-- 099_tenancy.sql like 041; the backfill runs once per tenant with app.tenant_id set (FORCE ROW LEVEL SECURITY, see 041).

ALTER TABLE fleet_agent_keys ADD COLUMN IF NOT EXISTS rotated_from TEXT;
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS enroll_token_id UUID;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fleet_agent_keys_rotated_from_fmt') THEN
    ALTER TABLE fleet_agent_keys ADD CONSTRAINT fleet_agent_keys_rotated_from_fmt
      CHECK (rotated_from IS NULL OR rotated_from ~ '^[0-9a-f]{32}$');
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_fleet_agent_keys_rotated_from
  ON fleet_agent_keys (tenant_id, agent_id, rotated_from) WHERE rotated_from IS NOT NULL;

-- Backfill: a rotation retires the old key and inserts the new one in ONE transaction, so the old key's
-- retired_at equals the new key's created_at (both NOW()). A re-key revokes (status 'revoked', no retired_at), so it
-- never matches. Idempotent.
DO $$
DECLARE t record;
BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'public' AND table_name = 'fleet_agent_keys' AND column_name = 'tenant_id') THEN
    FOR t IN SELECT id FROM tenants LOOP
      PERFORM set_config('app.tenant_id', t.id::text, true);
      UPDATE fleet_agent_keys n SET rotated_from = o.key_id
        FROM fleet_agent_keys o
       WHERE n.rotated_from IS NULL AND o.agent_id = n.agent_id AND o.status = 'rotated'
         AND o.retired_at IS NOT NULL AND o.retired_at = n.created_at AND o.key_id <> n.key_id;
    END LOOP;
    PERFORM set_config('app.tenant_id', '', true);
  ELSE
    UPDATE fleet_agent_keys n SET rotated_from = o.key_id
      FROM fleet_agent_keys o
     WHERE n.rotated_from IS NULL AND o.agent_id = n.agent_id AND o.status = 'rotated'
       AND o.retired_at IS NOT NULL AND o.retired_at = n.created_at AND o.key_id <> n.key_id;
  END IF;
END $$;
