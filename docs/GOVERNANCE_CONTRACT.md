# Governance + hardening contract

Schema: `schema/011_governance.sql`. Turns the platform from a dashboard into a governable system of record: real auth, RBAC+ABAC with classification, a tamper-evident audit log, provenance, and ops hardening. Three streams.

| Stream | Owns |
|---|---|
| A. orchestrator security+governance | orchestrator auth/authz/audit/provenance + endpoints |
| B. dashboard auth + governance UI | login, role-aware nav, classification banners, audit viewer, provenance |
| C. ops hardening + real-run/FP harness | docker-compose hardening, SECURITY.md, threat model, real-target scan + FP runbook/script |

Everything defensive. Auth gates access; it adds no offensive capability.

## A. Orchestrator security + governance

### AuthN
- Two credential types: **API key** (header `Authorization: Bearer <key>` or `X-API-Key`) and **JWT** (login → short-lived access token). Keys: on create, generate `pak_<prefix>_<secret>`, store only `sha256(full)`, return the raw once. Verify by hashing the presented key and matching `api_keys.key_hash` where not revoked/expired; bump `last_used`.
- `POST /v1/auth/login {username,password}` → `{access_token, role, clearance, expires_in}` (argon2/bcrypt verify against `app_users.pw_hash`). `POST /v1/auth/apikeys` (admin) issues keys; `GET /v1/auth/apikeys`; `DELETE /v1/auth/apikeys/{id}` (revoke). `GET /v1/auth/me`.
- **Bootstrap**: on startup, if the seeded `admin` has no pw_hash, set it from env `ADMIN_BOOTSTRAP_PASSWORD` (or generate one and log it ONCE). Never ship a known credential. Replace the `ALLOW_NO_AUTH` stub: keep a dev escape hatch `AUTH_MODE=dev` that injects a synthetic admin (loudly logged) so local dev + the existing tests still work, but default `AUTH_MODE=enforce`.

### AuthZ — RBAC + ABAC
- Roles: `viewer` (read non-restricted), `analyst` (read + triage: patch findings/tickets/anomalies, ask, scan), `admin` (everything incl. scope/owners/alerts/keys), `auditor` (read + audit log + integrity verify, no mutate).
- A dependency `require(role)` / `require_scope(scope)` on every router. Map the existing `require_scope_admin` onto `require('admin')`.
- **ABAC/classification**: every asset/finding carries `classification` (public<internal<confidential<restricted). Reads filter out rows above the caller's `clearance`; the filter is applied in SQL (a `WHERE classification <= caller_clearance` rank check) so over-classified data never leaves the DB. Document the rank order.

### Tamper-evident audit log
- `app/audit.py`: `record(action, resource_type, resource_id, actor, ...)` appends to `audit_log` computing `entry_hash = sha256(prev_hash || canonical_json(row_without_hash))`, `prev_hash` = previous row's `entry_hash` (genesis = 64 zeros). Serialize appends (advisory lock or single-writer) so the chain is linear.
- Middleware records every mutating request (and denied requests) with actor, role, method, path, status, classification touched, request_id, ip, and optional `X-Justification` header (purpose-based access). Reads of restricted data are also logged.
- `GET /v1/audit?actor=&action=&from=&to=&limit=&offset=` (auditor/admin) paged. `GET /v1/audit/verify` → walks the chain, returns `{ok, checked, first_broken_id?}` — proves tamper-evidence.
- Harden at the DB layer where possible: on startup try `REVOKE UPDATE, DELETE ON audit_log FROM <app_role>` (best-effort; log if lacking privilege).

### Provenance
- A `provenance` row per produced fact. Add a bulk helper + wire the existing bulk endpoints (assets/findings) to accept optional `provenance` and record it (source_service, source_detail, method, evidence, confidence). `GET /v1/provenance?subject_type=&subject_id=` returns lineage for an item. Back-fill from existing `source` columns in a one-time pass endpoint `POST /v1/provenance/backfill` (admin).

### Rules
- Additive; existing endpoints keep working under `AUTH_MODE=dev` (so the 141 tests + the other services, which call the API as services, keep working — give services a service API key or the dev mode). Document how services authenticate (a per-service API key injected via env, scope `write`).
- Tests `tests/test_governance.py` (≥20): key hashing + verify + revoke; login + JWT; role gates (viewer can't mutate, auditor can't mutate, analyst can triage, admin all); classification filtering (a confidential finding hidden from an internal-clearance key); audit chain append + verify detects a tampered row; provenance record + fetch. `make test` must pass (adjust existing tests to run under AUTH_MODE=dev or with a seeded admin key). Paste counts.

## B. Dashboard auth + governance UI
- **Login screen** (username/password → store JWT; or paste an API key). Unauthenticated → redirect to login. Show current user + role + clearance in the top bar; logout.
- **Role-aware UI**: hide/disable mutate controls for `viewer`/`auditor`; show everything for `admin`. Read the role from `/v1/auth/me`.
- **Classification banners/badges**: a top banner reflecting the highest classification on screen; a small classification chip on finding/asset rows (color-coded public→restricted).
- **Audit Log page** (`/audit`, auditor/admin): the hash-chained log (actor, action, resource, time, classification, justification) + a "Verify integrity" button hitting `/v1/audit/verify` showing the chain-intact result.
- **Provenance**: in the finding/asset detail drawer, a "Provenance" section (source service, method, evidence, confidence, recorded time).
- api module `src/api/auth.ts`, `src/api/audit.ts`; an auth store (token, user) with the fetch client attaching `Authorization`. Nav entry for Audit. Match the dark/dense system. `npx tsc -b` clean + 2 smoke tests.

## C. Ops hardening + real-run / FP harness (`/home/user/palantir-asm/hardening/` + docs)
- **Compose hardening** (edit docker-compose.yml carefully, additively): default `AUTH_MODE=enforce` on the orchestrator; move secrets (DB password, NEO4J_AUTH, ADMIN_BOOTSTRAP_PASSWORD, ANTHROPIC_API_KEY) to a `.env` file read by compose (ship `.env.example`, gitignore `.env`); add `read_only: true` + `cap_drop: [ALL]` + `security_opt: [no-new-privileges]` where services allow; ensure non-root users; add healthchecks for every service; put workers on an internal network with no inbound. Document every change.
- **SECURITY.md** — a real threat model: trust boundaries, the scope-enforcement invariant, authz model, audit guarantees, the "detection not exploitation" posture, secret handling, the known gaps (no FIPS/FedRAMP, single-tenant, cold-start ML), and responsible-use/authorized-scope statement.
- **Real-run + FP harness** `hardening/realrun.py` + `hardening/RUNBOOK.md`: a script that (1) adds an AUTHORIZED target to scope (default `scanme.nmap.org` — nmap's official legal target — and `127.0.0.1`), (2) runs the active worker's modules against it, (3) collects findings, (4) prints a triage table and computes a crude false-positive rate given a small hand-labeled truth set for scanme.nmap.org, (5) writes a report. It MUST refuse any target not in scope and print the authorization reminder. If the ProjectDiscovery binaries or network egress are unavailable, it degrades to a clear "could not run live — here's the exact command to run on a real deployment" message (honest, no fake results).
- A `make harden-check` target running a quick self-audit (no default creds, AUTH_MODE enforce, no secrets in compose, audit chain verifies).

## Safety
This pass adds governance + hardening only. No offensive capability. The real-run harness only ever touches explicitly authorized scope (scanme.nmap.org / localhost) and refuses anything else, with the authorization reminder.
