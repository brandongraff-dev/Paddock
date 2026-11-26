-- 064: provable containment P3, immutability guards (docs/ASSURANCE_P3.md 5.8; same pattern as 026).
--
--   attest_statements  BEFORE UPDATE: always refused. BEFORE DELETE: refused unless the row is older than 90 days AND
--                      is not the newest (highest seq) statement of its publication, so the head is never removed.
--   attest_revocations BEFORE UPDATE OR DELETE: always refused (strictly append-only).
--   attest_keys        BEFORE DELETE: always refused. BEFORE UPDATE: refused if tenant_id, kid, public_key, alg, usage,
--                      custody, backend, key_ref or publication_id changes (publication_id is fixed at insert: moving an
--                      active key out of the estate-wide set would free uq_attest_keys_one_active for a second key), or if the status does not move forward
--                      (pending -> active -> retiring -> retired, any -> revoked, revoked is terminal).
--
-- The app role cannot disable triggers (099 revokes TRIGGER and it owns nothing), so these guards bind an application
-- bug or compromise but not the DB owner; the audit anchor is what covers the owner case (same boundary as
-- finding_verifications).

CREATE OR REPLACE FUNCTION paddock_attest_statements_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'attest_statements rows are immutable (id %)', OLD.id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.issued_at >= NOW() - INTERVAL '90 days' THEN
    RAISE EXCEPTION 'attest_statements rows are append-only: a statement under 90 days old cannot be deleted (id %)', OLD.id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM attest_statements s
                  WHERE s.tenant_id = OLD.tenant_id AND s.publication_id = OLD.publication_id AND s.seq > OLD.seq) THEN
    RAISE EXCEPTION 'attest_statements rows are append-only: the newest statement of a publication cannot be deleted (id %)', OLD.id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_attest_statements_guard ON attest_statements;
CREATE TRIGGER trg_attest_statements_guard
  BEFORE UPDATE OR DELETE ON attest_statements
  FOR EACH ROW EXECUTE FUNCTION paddock_attest_statements_guard();

CREATE OR REPLACE FUNCTION paddock_attest_revocations_guard() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'attest_revocations is append-only (id %)', OLD.id
    USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_attest_revocations_guard ON attest_revocations;
CREATE TRIGGER trg_attest_revocations_guard
  BEFORE UPDATE OR DELETE ON attest_revocations
  FOR EACH ROW EXECUTE FUNCTION paddock_attest_revocations_guard();

CREATE OR REPLACE FUNCTION paddock_attest_keys_guard() RETURNS trigger AS $$
DECLARE
  old_rank INTEGER;
  new_rank INTEGER;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'attest_keys rows are never deleted (kid %)', OLD.kid
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.kid IS DISTINCT FROM OLD.kid
     OR NEW.public_key IS DISTINCT FROM OLD.public_key OR NEW.alg IS DISTINCT FROM OLD.alg
     OR NEW.usage IS DISTINCT FROM OLD.usage OR NEW.custody IS DISTINCT FROM OLD.custody
     OR NEW.backend IS DISTINCT FROM OLD.backend OR NEW.key_ref IS DISTINCT FROM OLD.key_ref
     OR NEW.publication_id IS DISTINCT FROM OLD.publication_id THEN
    RAISE EXCEPTION 'attest_keys identity columns are immutable (kid %)', OLD.kid
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF OLD.status = 'revoked' THEN
      RAISE EXCEPTION 'attest_keys status is terminal once revoked (kid %)', OLD.kid
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status <> 'revoked' THEN
      old_rank := CASE OLD.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 WHEN 'retiring' THEN 2 WHEN 'retired' THEN 3 END;
      new_rank := CASE NEW.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 WHEN 'retiring' THEN 2 WHEN 'retired' THEN 3 END;
      IF old_rank IS NULL OR new_rank IS NULL OR new_rank < old_rank THEN
        RAISE EXCEPTION 'attest_keys status moves only forward: % -> % is refused (kid %)', OLD.status, NEW.status, OLD.kid
          USING ERRCODE = 'integrity_constraint_violation';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_attest_keys_guard ON attest_keys;
CREATE TRIGGER trg_attest_keys_guard
  BEFORE UPDATE OR DELETE ON attest_keys
  FOR EACH ROW EXECUTE FUNCTION paddock_attest_keys_guard();
