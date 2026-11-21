# Incident response policy

*Template for an organisation operating Paddock, with Paddock-specific
playbooks. Owner: [Security lead]. Review: annually and after every SEV1/SEV2.*

## 1. Scope

Security incidents affecting a Paddock deployment or the data it holds:
unauthorised access, data exposure (including cross-tenant), integrity
compromise of the audit log, misuse of the scanner (out-of-scope probing),
compromise of a release artefact, and availability incidents with security
impact.

## 2. Roles

| Role | Responsibility |
|---|---|
| Incident commander (IC) | owns the incident, severity, decisions, timeline |
| Technical lead | investigation, containment, eradication |
| Communications lead | customer / regulator / public notices |
| Scribe | timeline, evidence log (chain of custody) |
| Legal / DPO | breach-notification assessment (GDPR Art. 33/34, contracts) |

## 3. Severity

| Sev | Examples | Response start | Customer notice |
|---|---|---|---|
| SEV1 | cross-tenant data exposure; DB superuser compromise; audit chain verify fails with `anchor_mismatch`/`anchor_truncated`; malicious release artefact; probing outside scope | 30 min, 24×7 | per DPA (≤ [48] h) |
| SEV2 | single-tenant data exposure; leaked API key/JWT secret/`AUDIT_HMAC_KEY`/`PADDOCK_SECRET_KEY`; RLS bypass bug | 4 h | per DPA if personal data affected |
| SEV3 | vulnerability without evidence of exploitation; failed anchoring for > 2 intervals | next business day | no |

## 4. Lifecycle

1. **Detect** — sources: `GET /v1/audit/verify` (schedule it; alert on
   `ok=false`), `audit_anchor_failed` / `audit_intent_failed` /
   "DATABASE ROLE … IS A SUPERUSER" log lines, `action=deny` spikes in the
   audit log, `outbound_log` rows with `scope_matched = false`, vulnerability
   reports ([VULNERABILITY_MANAGEMENT.md](VULNERABILITY_MANAGEMENT.md)).
2. **Triage** — assign IC and severity; open the incident record.
3. **Contain** — playbooks below.
4. **Preserve evidence** — before changing anything: export `audit_log`,
   `outbound_log`, `scope_decisions` for the window; save the latest anchors
   and the `/v1/audit/verify` output; snapshot the DB volume; keep container
   logs. Hash every artefact into the evidence log.
5. **Eradicate & recover** — patch, rotate, restore from known-good backup;
   re-verify the audit chain and re-anchor.
6. **Notify** — controller/customers per DPA; regulators within 72 h of
   awareness where GDPR Art. 33 applies; individuals where Art. 34 applies.
7. **Post-incident review** — blameless write-up within [10] business days,
   with tracked corrective actions.

## 5. Paddock playbooks

**Credential leak (API key / user):** revoke the key
(`DELETE /v1/auth/apikeys/{id}`) or deactivate the user
(`UPDATE app_users SET active = false`); tokens re-check the live user row on
every request. Review the actor's audit rows. If `JWT_SECRET` leaked: rotate it
and restart (invalidates all sessions).

**Tenant compromise / abuse:** `UPDATE tenants SET status = 'suspended'` —
all of the tenant's keys and logins fail immediately.

**Suspected cross-tenant exposure:** confirm the orchestrator is connected as
`paddock_app` (startup banner; `SELECT rolsuper FROM pg_roles WHERE rolname =
current_user`); run the isolation suite (`pytest tests/test_tenancy.py`)
against the deployed version; check whether the data came through a
non-tenant-aware service (TENANCY.md limits) — those must be disabled for
multi-tenant use.

**Audit integrity alert (`ok=false`):** treat as SEV1. Do not "fix" rows.
Record `first_broken_id`, `reason`, anchor status; compare with the anchor
sink (Object Lock bucket is authoritative); identify DB sessions with owner or
superuser access in the window. If `AUDIT_HMAC_KEY` may be exposed: rotate (new
key current, old key in `AUDIT_HMAC_PREVIOUS_KEYS`), then anchor immediately.

**Out-of-scope probing:** stop workers (`docker compose stop worker-active
worker-passive`); pull `outbound_log` + `scope_decisions`; notify the affected
third party if required; fix the scope entry/guard before restart.

**Malicious or unverifiable release artefact:** stop deploying; check
signatures and provenance ([VERIFY.md](VERIFY.md)); roll back to the last
verified digest; revoke/rotate CI credentials; publish an advisory.

**Secret-key exposure (`PADDOCK_SECRET_KEY`):** rotate (new primary, old key in
`PADDOCK_SECRET_KEY_OLD`), re-save integrations to re-encrypt, rotate the
third-party integration tokens themselves.

## 6. Testing

Tabletop exercise at least annually; restore-from-backup test at least
annually; audit-verify alerting tested after every upgrade.
