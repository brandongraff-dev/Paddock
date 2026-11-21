# SECURITY.md — threat model & security posture

palantir-asm is a **defensive** Attack Surface Management platform for
authorized asset defense. This document is an honest threat model: what the
system protects, the trust boundaries, the invariants it enforces, how it is
hardened operationally, and — just as importantly — the gaps it does **not**
yet close. It ends with the authorized-use statement that governs the whole
project.

> Reporting a vulnerability in palantir-asm itself: open a private advisory /
> contact the maintainers before public disclosure. Do not file exploit details
> in a public issue.

---

## 1. What this system is (and is not)

palantir-asm **discovers** assets from passive sources, **politely probes** the
subset you have explicitly authorized, **correlates** findings against public
vulnerability feeds, and **surfaces** the result to an analyst. It is a
detection and situational-awareness tool.

It is **not** an exploit framework, a red-team C2, or a credential-attack tool.
These are not missing features; they are deliberately excluded (see §6).

---

## 2. Trust boundaries

```
  (untrusted)                                                   (trusted)
  ┌──────────┐   egress    ┌───────────┐  service API  ┌──────────────┐
  │ Internet │◄───────────►│  Workers  │◄─────────────►│ Orchestrator │
  │ targets, │  scope-     │ passive / │   (scope      │  (FastAPI)   │
  │ CT, NVD, │  gated,     │  active   │    checks,    │  authz +     │
  │ feeds    │  audited    │           │    bulk       │  audit +     │
  └──────────┘             └───────────┘    upserts)   │  provenance) │
                                                        └───┬──────┬───┘
                                            internal only   │      │
                              ┌──────────────┐  nginx /v1   │      │
   analyst ──login/JWT──►     │  Dashboard   │◄─proxy───────┘      │
   (RBAC+ABAC)                │  (React/nginx)│                    │
                              └──────────────┘        ┌───────────▼──────────┐
                                                       │ Postgres (system of  │
                                                       │ record) + Redis queue│
                                                       │ + Neo4j (graph)      │
                                                       └──────────────────────┘
```

Boundaries, from least to most trusted:

1. **Internet ↔ workers.** The internet is fully untrusted. Workers are the
   only components that talk to it, and only *outbound*, only to scope-approved
   hosts, only with detection-grade requests. Target responses are untrusted
   input and are parsed defensively (bounded body reads, pattern-gated
   findings). Workers accept **no inbound** connections.
2. **Workers ↔ orchestrator.** Workers hold no database credentials and never
   write the DB directly. They call the orchestrator's service API for the
   authoritative scope check, for bulk upserts, and to sink the outbound audit
   trail. The orchestrator owns all canonicalization. A worker is treated as a
   semi-trusted service principal (it authenticates with a per-service API key,
   scope `write`, under `AUTH_MODE=enforce`).
3. **Orchestrator ↔ data tier.** The orchestrator is the only component with
   Postgres credentials. Postgres is the system of record; Redis is an
   ephemeral queue/cache; Neo4j is a derived graph projection. The data tier
   has **no egress and no host-published ports** in the hardened profile.
4. **Dashboard ↔ orchestrator.** The dashboard is a static SPA served by nginx,
   which also reverse-proxies `/v1/*` to the orchestrator. It holds no secrets;
   all authority lives in the analyst's short-lived JWT, attached per request.
5. **Analyst ↔ dashboard.** Analysts are authenticated and authorized
   (§4–§5). The UI reflects — but does not define — authority: every mutation
   is re-checked server-side.

---

## 3. The scope-enforcement invariant (defense in depth, 3 layers)

**Invariant: no packet ever leaves this system toward a host that is not in the
`scope_entries` allowlist at the moment of the request.** An out-of-scope
request is a hard failure, never a warning.

It is enforced at three independent layers, with a single authoritative
decision point (`POST /v1/scope/check` on the orchestrator):

- **Layer 1 — dispatch gate (orchestrator).** `POST /v1/scans` scope-checks the
  target *before* a job is ever written or enqueued. Attack-aid scan kinds
  (exploit, cred-stuff, spray, WAF-bypass, stealth/fragment scan, exfil, …) are
  refused up front — they are not scope-checked, not enqueued, just `400`.
- **Layer 2 — egress wrapper (worker `scope_guard`).** Before any request the
  worker calls the authoritative `/v1/scope/check` (with a short TTL cache to
  avoid self-DoS). The decision is wired into the HTTP client as an httpx
  request hook that **re-checks every request including every redirect target**,
  and into a subprocess pre-flight that aborts before an external binary (naabu,
  tlsx, nuclei) even starts. Failures fail **closed**.
- **Layer 3 — output filter.** Tool output is filtered row-by-row: any result
  whose host has fallen out of scope (e.g. a redirect-followed row, a cert SAN
  for another host) is dropped before it is recorded.

Every decision — allow or deny — is written to `scope_decisions`, giving a
complete audit of what the system was *permitted* to touch, alongside the
`outbound_log` of what it *actually* touched.

The standalone FP harness (`hardening/realrun.py`) re-implements the same
authorization boundary **in-process**, so it refuses out-of-scope targets even
when run without the orchestrator.

---

## 4. Authentication

- **Two credential types.** API keys (`Authorization: Bearer pak_…` or
  `X-API-Key`) and JWTs (login → short-lived access token). API keys are stored
  only as `sha256(full_key)`; the raw key is returned exactly once at creation.
  Verification hashes the presented key and matches a non-revoked, non-expired
  row, bumping `last_used`.
- **Bootstrap.** On first start, if the seeded `admin` has no password hash, it
  is set from `ADMIN_BOOTSTRAP_PASSWORD` (or a value is generated and logged
  exactly once). **No known credential is ever shipped.**
- **Modes.** `AUTH_MODE=enforce` is the hardened default. `AUTH_MODE=dev`
  injects a loudly-logged synthetic admin so local development and the existing
  test suite keep working; it must never be used in production. The legacy
  `ALLOW_NO_AUTH` stub is pinned deny-closed (`false`) in the prod compose.
- **Service principals.** Inter-service callers (workers, correlation, …)
  authenticate with a per-service API key injected via env, scoped `write`.

## 5. Authorization — RBAC + ABAC + classification

- **Roles (RBAC).** `viewer` (read non-restricted), `analyst` (read + triage:
  patch findings/tickets/anomalies, ask, scan), `admin` (everything, incl.
  scope/owners/alerts/keys), `auditor` (read + audit log + integrity verify, no
  mutate). Every router carries a `require(role)` / `require_scope(scope)`
  dependency.
- **Classification (ABAC).** Every asset and finding carries a `classification`
  with a strict rank order:

  ```
  public  <  internal  <  confidential  <  restricted
  ```

  Reads filter out rows above the caller's `clearance` **in SQL**
  (`WHERE classification_rank <= caller_clearance_rank`), so over-classified
  data never leaves the database — the filter is not a UI concern. Reads of
  restricted data are themselves audited. An optional `X-Justification` header
  carries purpose-of-access for sensitive reads.

The dashboard mirrors this: mutate controls are hidden/disabled for
`viewer`/`auditor`, a top banner reflects the highest classification on screen,
and per-row classification chips are colour-coded `public → restricted`. The UI
is a convenience; the server is the authority.

## 6. "Detection, not exploitation" — and why

The platform will not, by construction:

- **auto-exploit** — no payload delivery, no PoC execution, no attempt at code
  execution on a target. Findings describe impact; they never carry a working
  exploit.
- **attack credentials** — no brute force, spray, or stuffing, and no
  default-credential test that actually submits credentials. Default-credential
  *risk* is detected by fingerprinting the exposed product, not by trying
  passwords.
- **evade** — no stealth/fragmented scans, no WAF-bypass headers, no decoys, no
  source spoofing. The scanner's User-Agent names itself
  (`palantir-asm-scanner/1.0 (+defensive-scanner)`). Evasion-flavoured config
  env vars and CLI flags are **refused at import/exec time**, not merely
  ignored. nuclei runs with `-exclude-tags intrusive,fuzz,dos` and fixed rate
  caps that narrowing config can tighten but never widen.

**Why.** This posture is what makes the tool legal to run against assets you
are authorized to assess, safe to run against production you depend on, and
employable inside an org without becoming an insider-threat multiplier. A
detector that cannot be turned into a weapon has a dramatically smaller blast
radius if it is itself compromised, and its outputs are defensible in an audit.
Every request it emits is polite (per-host concurrency + inter-request delay
floor + 429/Retry-After backoff + optional robots.txt compliance), capped, and
logged.

## 7. Audit guarantees — tamper-evident hash chain

- Every mutating request (and every denied request, and every read of
  restricted data) is appended to `audit_log` with actor, role, method, path,
  status, classification touched, request id, IP and optional justification.
- Each row stores `entry_hash = sha256(prev_hash || canonical_json(row_without_hash))`,
  with `prev_hash` = the previous row's `entry_hash` (genesis = 64 zeros).
  Appends are serialized (single-writer / advisory lock) so the chain is linear.
- `GET /v1/audit/verify` walks the chain and returns `{ok, checked,
  first_broken_id?}` — a tampered or deleted row breaks the hash link and is
  detected. `GET /v1/audit` (auditor/admin) exposes the paged log.
- As a second layer, on startup the orchestrator best-effort
  `REVOKE UPDATE, DELETE ON audit_log FROM <app_role>` so the application role
  can append but not rewrite history (logged if it lacks the privilege to do
  so).

This gives tamper-**evidence** (you can prove the record was not altered), not
tamper-**proofing** (a DB superuser can still rewrite rows and recompute hashes
— see §10).

## 8. Provenance

Every produced fact can carry a `provenance` row (source service, source
detail, method, evidence, confidence, recorded time). `GET /v1/provenance?
subject_type=&subject_id=` returns an item's lineage, so an analyst can see
*why* a finding exists and *what* produced it before acting on it.

## 9. Operational hardening (docker-compose)

The hardened baseline is `docker-compose.yml`; `docker-compose.override.yml`
re-opens ports + dev auth for local development and is auto-merged by
`docker compose`. Run `make harden-check` to self-audit the posture. Changes
applied:

- **Secrets out of the file.** `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`,
  `ADMIN_BOOTSTRAP_PASSWORD`, `ANTHROPIC_API_KEY` are read from a gitignored
  `.env` (template: `.env.example`) via `${VAR}` substitution. No plaintext
  secret or default admin credential is committed.
- **Auth default flipped.** Orchestrator `AUTH_MODE` defaults to `enforce`;
  legacy `ALLOW_NO_AUTH` pinned to `false` in prod.
- **Per-service sandboxing.** `security_opt: no-new-privileges` on every
  service; `cap_drop: ALL` on every service that tolerates it (our non-root
  Python images, which already ship a non-root `USER`); `read_only` root
  filesystem + `tmpfs` scratch for every stateless service; `restart:
  unless-stopped`; a `healthcheck` for every service.
- **Network segmentation.** Three networks: `edge` (only orchestrator +
  dashboard publish host ports), `internal` (`internal: true` — data tier,
  workers and compute services; **no egress, no host-published ports**), and
  `egress` (outbound-only bridge for the four services that must reach the
  internet: `worker-active`, `worker-passive`, `intel`, `brain`). Postgres,
  Redis and Neo4j are not reachable from the host in the hardened profile.
- **Data durability.** Neo4j now persists on named volumes (was ephemeral);
  active-worker screenshots persist on a named volume.

See the README "Operational hardening" section for the per-service rationale,
including the services that resist full lock-down and why (§10).

## 10. KNOWN GAPS / LIMITATIONS (read honestly)

This is an MVP-grade platform with real, un-papered-over gaps:

- **No FIPS / FedRAMP / formal compliance.** Crypto is stock library crypto
  (sha256 hashing, bcrypt/argon2 for passwords); there is no FIPS-validated
  module, no boundary accreditation, no control mapping (NIST 800-53, SOC 2,
  etc.). Do not represent it as compliant with any regime.
- **Single-tenant.** There is no tenant isolation. RBAC/ABAC/classification
  partition *access within one org*, not *data between orgs*. Running it as
  shared multi-tenant SaaS is not supported and would leak across tenants.
- **Tamper-evidence, not tamper-proofing.** The audit hash chain detects
  after-the-fact edits by the application role, but a Postgres superuser (or
  anyone with raw DB/disk access) can rewrite rows and recompute the chain.
  There is no external notarization/anchoring, no append-only WORM storage, and
  no off-box log shipping by default.
- **Cold-start ML.** The `mlrisk` ranker/anomaly detector has no pretrained
  model and no persisted model artifact; it bootstraps from whatever is in the
  DB and is effectively uncalibrated until enough real history accumulates.
  Early risk scores and anomaly flags should be treated as low-confidence.
- **Synthetic-data-only validation.** The test suite and the chain detectors
  are validated against synthetic fixtures and a single live reference host
  (`scanme.nmap.org`). The false-positive measurement in
  `hardening/realrun.py` is a **crude** metric over a small hand-labeled truth
  set for one host whose live config can drift — it is a regression tripwire,
  not a precision guarantee. No broad real-world precision/recall study has
  been done.
- **Fragile integration seams.** The orchestrator *proxies* several Tier 3/4
  services (brain, graphsync, codeanalysis, mlrisk) and is written to degrade
  gracefully when they are down, but the seams are loosely contract-tested;
  partial outages can produce confusing (never unsafe) states. The governance
  auth layer (Stream A) and this hardening pass (Stream C) are developed in
  parallel, so a build may have `AUTH_MODE` wired in compose before the
  orchestrator reads it — run the dev profile until the auth endpoints exist.
- **Services that resist full lock-down.** `postgres`/`redis`/`neo4j` keep
  Linux capabilities (their official entrypoints drop privileges via
  gosu/su-exec and need a writable data dir), so they get `no-new-privileges` +
  volumes/tmpfs but not `cap_drop: ALL`/`read_only`. The **active worker** is
  the least sandboxed service: naabu needs `NET_RAW`/`NET_ADMIN` for SYN scans
  and Playwright/Chromium + the ProjectDiscovery binaries write to many paths,
  so it runs with `cap_drop: ALL` + only `NET_RAW`/`NET_ADMIN` added, but not
  `read_only`, and (pending a Dockerfile `USER`) still as root. The passive
  worker, correlation and the nginx dashboard likewise cannot be forced
  non-root from compose alone without editing their images.
- **No secret manager / rotation.** Secrets live in `.env` on the host and in
  container env. There is no Vault/KMS integration and no automated rotation;
  `.env` file hygiene is the operator's responsibility.
- **DoS / abuse of the scanner.** Politeness caps protect *targets*; there is no
  strong protection against an authenticated insider queuing an abusive volume
  of authorized-but-excessive scans beyond the per-host rate limiter.

## 11. Secret handling

- Secrets are never committed: `.env` is gitignored, `.env.example` ships only
  `change-me-*` placeholders, and `make harden-check` fails if a plaintext
  secret or default admin credential appears in the compose files.
- API keys are stored hashed (`sha256`), shown once, revocable.
- Passwords are stored as bcrypt/argon2 hashes.
- The `ANTHROPIC_API_KEY` is confined to the `brain` service and must stay out
  of logs; the FP harness and other tooling never transmit project or user
  identifiers to third parties.
- The audit log and outbound log avoid recording secret values (headers/bodies
  are summarized, not dumped).

---

## 12. Authorized-use statement

**palantir-asm may be pointed only at assets you own or are explicitly,
documentedly authorized to assess.** The safe default scope is
`scanme.nmap.org` (Nmap's official legal scan target —
<https://nmap.org/book/legal-issues.html>) and loopback (`127.0.0.0/8`). Any
other target must be added to the scope allowlist together with an authorization
note referencing the document that grants permission. The system enforces this
allowlist at three layers and audits every outbound request; the included
tooling refuses out-of-scope targets by design. Using this software to scan,
probe, or otherwise interact with systems you are not authorized to test may be
illegal and is outside the supported and intended use of this project. You are
responsible for operating it lawfully and within the bounds of your
authorization.
