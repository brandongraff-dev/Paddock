# Data retention & deletion policy

*Policy template for an organisation operating Paddock, plus the facts about
what the software does today. Owner: [Security lead]. Review: annually.*

## 1. What the software does today (facts)

* **Paddock has no automatic retention jobs.** Nothing is expired or purged
  on a schedule; every table grows until an operator deletes data. Assets are
  never auto-deleted when they disappear from the internet (they keep
  `last_seen`).
* Deletions available in the product: deactivate scope entries (soft:
  `active = false`), delete schedules / owners / alert rules / TI feeds,
  revoke API keys (soft: `revoked = true`).
* The application database role **cannot delete or update audit rows**
  (`schema/099_tenancy.sql`); audit retention is enforced by the schema owner.
* Audit anchors in an S3 Object Lock bucket cannot be deleted before
  `AUDIT_ANCHOR_S3_RETENTION_DAYS` (default 400) — by anyone, in COMPLIANCE mode.
* Redis holds queues/events only (ephemeral); Neo4j is a derived projection
  rebuilt from Postgres.

## 2. Retention schedule (policy — adopt or adjust)

| Data | Table(s) | Retention | Rationale |
|---|---|---|---|
| Scope allowlist + authorisation reference | `scope_entries` | life of the tenant + 1 year after deactivation | evidence of authorisation to scan |
| Assets, edges, TLS grades, devices | `assets`, `asset_edges`, `tls_grades`, … | life of the tenant; assets unseen for [180] days may be purged | attack-surface history |
| Findings, chains, attack paths, tickets | `findings`, `finding_chains`, `attack_paths`, `tickets` | life of the tenant; closed findings [2] years | trend + remediation evidence |
| Scope decisions | `scope_decisions` | [1] year | proves what the system was permitted to touch |
| Outbound request log | `outbound_log` | [1] year | proves what the system actually touched |
| Scans, schedules | `scans`, `schedules` | [1] year (scans) | operations |
| NL queries (Ask) | `nl_queries` | [90] days | may contain free text |
| Audit log | `audit_log` | **[7] years** or the legal requirement, whichever is longer | integrity of the record |
| Audit anchors | anchor sink | ≥ audit-log retention of the rows they cover | truncation detection |
| User accounts | `app_users`, `api_keys` | until removal + [90] days | access evidence |
| Global intel | `cves`, `ti_*`, `attack_technique_map` | refreshed from source | not customer data |
| Backups | operator storage | [35] days rolling | recovery |

## 3. Routine purge (example)

Run as the schema **owner** (the app role cannot delete audit rows), per tenant,
in a maintenance window:

```sql
BEGIN;
SELECT set_config('app.tenant_id', '<tenant-uuid>', true);
DELETE FROM scope_decisions WHERE decided_at < now() - interval '1 year';
DELETE FROM outbound_log   WHERE started_at < now() - interval '1 year';
DELETE FROM nl_queries     WHERE asked_at < now() - interval '90 days';
COMMIT;
```

Never delete audit rows from the middle of a chain: the chain would no longer
verify. Archive and drop audit history only in whole prefixes, after exporting
the rows together with the anchor that covers them, and record the purge
(the next verify starts from a new genesis only if the whole tenant chain is
archived — document the archive's head hash).

## 4. Tenant deletion (offboarding)

1. Suspend: `UPDATE tenants SET status = 'suspended' WHERE id = '<uuid>';`
   (all of the tenant's credentials stop working immediately).
2. Export if requested: per-table `COPY (SELECT * FROM <t> WHERE tenant_id = '<uuid>') TO …`
   plus `GET /v1/audit/verify` output and the latest anchor.
3. Purge (owner/superuser; FK triggers disabled for the transaction so table
   order does not matter):

   ```sql
   BEGIN;
   SET LOCAL session_replication_role = replica;
   DO $$
   DECLARE t text;
   BEGIN
     FOR t IN SELECT table_name FROM information_schema.columns
               WHERE table_schema = 'public' AND column_name = 'tenant_id'
     LOOP
       EXECUTE format('DELETE FROM public.%I WHERE tenant_id = %L', t, '<uuid>');
     END LOOP;
   END $$;
   DELETE FROM tenants WHERE id = '<uuid>';
   COMMIT;
   ```
   Keep the tenant's audit rows instead (skip `audit_log` in the loop) where
   the DPA's audit-retention clause applies.
4. Graph/cache: rebuild Neo4j from Postgres (or delete the tenant's nodes);
   restart services to drop in-process caches.
5. Backups age out on the normal rotation; record the date in the deletion
   certificate sent to the customer.

## 5. Gaps

No scheduled purge job, no per-tenant export endpoint, no crypto-shredding
(per-tenant keys) — deletion relies on SQL deletes and backup rotation.
