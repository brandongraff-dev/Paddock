-- 098: keyed audit chain (HMAC-SHA256) -- see orchestrator/app/audit.py.
--
-- Each audit row records the algorithm its entry_hash was computed with:
--   'sha256'               legacy, unkeyed: sha256(prev_hash || canonical(row))
--   'hmac-sha256:<kid>'    HMAC-SHA256 under the key whose id is <kid>; the key
--                          itself (AUDIT_HMAC_KEY) never touches the database.
-- Existing rows keep 'sha256' and still verify. Once a chain contains a keyed
-- row, verify() rejects any later unkeyed row (no silent downgrade).
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hash_alg TEXT NOT NULL DEFAULT 'sha256';
