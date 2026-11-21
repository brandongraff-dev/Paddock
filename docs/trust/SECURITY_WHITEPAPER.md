# Paddock security whitepaper

*Audience: security reviewers, procurement, auditors. Scope: the open-source
Paddock code base as of this document's commit. Statements are about what the
code does; operator responsibilities are called out explicitly. The threat
model and known gaps live in [`SECURITY.md`](../../SECURITY.md) — this paper
does not repeat them all, but never contradicts them.*

Related: [Tenancy model](TENANCY.md) · [Release verification](VERIFY.md) ·
[SOC 2 mapping](SOC2_CONTROL_MAPPING.md) · [Data retention](DATA_RETENTION.md) ·
[Incident response](INCIDENT_RESPONSE.md) ·
[Vulnerability management](VULNERABILITY_MANAGEMENT.md) ·
[DPA template](DPA_TEMPLATE.md) · [Subprocessors](SUBPROCESSORS.md)

---

## 1. What Paddock is

A **defensive** attack-surface-management platform: it discovers a customer's
internet-facing assets from passive sources, politely probes only assets on an
explicit allowlist, correlates them with public vulnerability intelligence and
presents prioritised findings. It deliberately contains no exploitation,
credential-attack or evasion capability (SECURITY.md §6).

Deployment model today: **self-hosted** (docker-compose). Paddock the project
does not operate a hosted service; where this paper says "the operator" it
means whoever runs the stack.

## 2. Architecture

```
 Internet  <-- scope-gated egress --  workers (passive/active), intel, brain
                                         |  service API key (+ X-Paddock-Tenant)
 analyst --JWT--> dashboard (nginx) --/v1--> orchestrator (FastAPI)
                                         |  paddock_app role (RLS)      | owner role
                                         v                              v
                                     Postgres (system of record) <- compute services
                                     Redis (queue/events), Neo4j (derived graph)
```

* **Orchestrator** — the API, authN/Z, scope authority, audit writer. Connects
  to Postgres as the non-superuser `paddock_app` role.
* **Workers** — the only components that touch target hosts; outbound only,
  scope-checked per request and per redirect, every request logged to
  `outbound_log`.
* **Compute services** (intel, correlation, sca, codeanalysis, mlrisk, brain,
  graphsync, ontology, threatintel, changewatch, triage, otdiscovery,
  remediation) — read/write Postgres directly with the owner credential (see §6
  limits).
* **Network segmentation (compose)** — `edge` (only orchestrator + dashboard
  publish ports), `internal` (`internal: true`, no egress: data tier and compute),
  `egress` (only the services that must reach the internet).

## 3. Data flows and data inventory

| Data | Source | Stored | Leaves the deployment? |
|---|---|---|---|
| Scope allowlist (domains, CIDRs, ASNs, authorisation reference) | operator | `scope_entries` | no |
| Discovered assets, edges, TLS grades, services | passive sources + probes | `assets`, `asset_edges`, … | asset names are sent as *queries* to passive sources (CT logs/crt.sh, Wayback, BGP/RIPE, Shodan InternetDB, …) when those modules run |
| Findings, evidence summaries, attack paths | workers, correlation | `findings`, `finding_chains`, `attack_paths` | only to the LLM provider if `brain`/`remediation` LLM features are enabled with an API key (§4), and to integrations the operator configures |
| Vulnerability intelligence | NVD, FIRST EPSS, CISA KEV, OSV.dev, TI feeds | `cves`, `ti_*` (global) | no (inbound only) |
| User identities | operator | `app_users` (username, optional email, bcrypt hash) | no |
| API keys | generated | `api_keys` (sha256 of key only) | raw key shown once |
| Integration credentials | operator | `integrations.secrets` (AES-256-GCM) | sent only to the integration's own endpoint |
| Audit trail | every mutation / denial / restricted read | `audit_log` (hash chain) + anchors in the configured sink | anchors (hashes + ids only, no content) go to the anchor sink |
| Outbound request log | workers | `outbound_log` | no |

Personal data is limited to analyst account data, IP addresses in the audit
log, and whatever personal data happens to appear in the customer's own
internet-facing assets (e.g. names in TLS certificates or WHOIS).

## 4. Encryption

**In transit**

* Outbound: workers and intel clients use HTTPS to public sources where the
  source offers it (httpx with certificate verification).
* LLM provider (optional): HTTPS via the Anthropic SDK.
* **Inside the deployment, Paddock does not terminate TLS.** The orchestrator
  (`:8080`) and dashboard (`:3000`) serve plain HTTP; service-to-service and
  service-to-Postgres traffic is plaintext on private Docker networks.
  **Operator responsibility:** put a TLS-terminating reverse proxy (or a
  service mesh with mTLS) in front of the edge network, and enable Postgres
  `ssl=on` + `sslmode=verify-full` if the data tier is not on the same host.

**At rest**

* Paddock does **not** encrypt the Postgres, Redis or Neo4j volumes.
  **Operator responsibility:** host/volume encryption (LUKS, cloud-provider
  disk encryption).
* Field-level: integration credentials are encrypted with AES-256-GCM under
  `PADDOCK_SECRET_KEY` (key-id-tagged ciphertext, rotation via
  `PADDOCK_SECRET_KEY_OLD`). Passwords: bcrypt (sha256-prehashed). API keys:
  sha256 (high-entropy, so not brute-forceable). Per-tenant evidence-encryption
  keys are **not** implemented.

## 5. Identity and access

* Credentials: short-lived HS256 JWTs (default 1 h) from password login, or
  API keys (`pak_<prefix>_<secret>`, scope-narrowed, revocable, expiring).
  Login is throttled per username and per client IP; unknown-user and
  wrong-password paths take equal time.
* `AUTH_MODE=enforce` is the default (deny-closed). `dev` mode injects a
  synthetic admin and must never be exposed.
* RBAC: viewer / analyst / auditor / admin, plus a `service` principal for the
  shared service key. Unclassified mutating routes default to `admin`.
* ABAC: classification `public < internal < confidential < restricted`
  filtered **in SQL** against the caller's clearance.
* No SSO/SAML/OIDC login and no MFA in the code base today.

## 6. Tenancy

Paddock ships Postgres row-level-security tenancy (details and limits:
[TENANCY.md](TENANCY.md)). Every tenant-scoped table has a forced RLS policy
on `tenant_id = current_setting('app.tenant_id')`; the orchestrator stamps the
caller's tenant on every pooled connection and connects as a role that cannot
bypass RLS. **Only the orchestrator API is tenant-isolated today**; the compute
services and the scanning pipeline are not tenant-aware, so a shared
multi-tenant deployment is **not** yet supported. Single-tenant self-hosting is
the supported model.

## 7. Key management

| Key | Purpose | Where it lives | Rotation |
|---|---|---|---|
| `JWT_SECRET` | sign access tokens | env / secret file | change + restart (invalidates sessions) |
| `PADDOCK_SECRET_KEY` | AES-GCM for integration secrets | env | `PADDOCK_SECRET_KEY_OLD` keeps old ciphertext readable |
| `AUDIT_HMAC_KEY` / `AUDIT_HMAC_KEY_FILE` | keyed audit chain + anchor signatures | **outside the DB**: env, Docker secret, or a KMS-decrypted file | new key in `AUDIT_HMAC_KEY`, old one in `AUDIT_HMAC_PREVIOUS_KEYS`; per-row `hash_alg` records the key id |
| `SERVICE_API_KEY` | worker → orchestrator | env | change in all services |
| DB passwords | `asm` owner, `paddock_app` | `.env` | `ALTER ROLE … PASSWORD` |
| Release signing | — | **none**: Sigstore keyless (OIDC) | n/a |

There is no built-in KMS/Vault integration: "outside the DB" means the key is
never written to Postgres, not that it is HSM-protected. Use a secret manager
that materialises the key as a file (`AUDIT_HMAC_KEY_FILE`).

## 8. Audit logging

* Every mutating request, every denied request and every read of restricted
  data is appended to `audit_log` (actor, role, tenant, method, path, status,
  classification, justification, request id, client IP — X-Forwarded-For only
  from trusted proxies).
* **Fail-closed:** a write-ahead `intent` record is committed *before* a
  mutating handler runs; if it cannot be written the request is refused (503)
  and nothing changes. An `outcome` record with the status follows. Handlers
  can also write the audit row in the same DB transaction as their change
  (`audit.record(con=…)`).
* **Per-tenant hash chains.** New rows are HMAC-SHA256 under
  `AUDIT_HMAC_KEY`, so someone with database superuser access cannot forge a
  consistent history; unkeyed legacy rows still verify; a keyed→unkeyed
  downgrade is rejected.
* **Anchoring.** The chain head `(max_id, head_hash)` is signed and published
  to an append-only sink — a local `O_APPEND` file, S3-compatible storage with
  **Object Lock (COMPLIANCE)**, and/or an HTTP webhook — hourly by default.
  `GET /v1/audit/verify` streams the chain in batches and checks it against the
  latest anchor, detecting tail truncation and whole-chain rewrites.
* The application role has no `UPDATE`/`DELETE` on `audit_log`.
* Remaining gap: rows written *after* the last anchor can be silently removed
  by a superuser until the next anchor (window = anchor interval). Shipping
  audit rows to an external SIEM is not built in.

## 9. Software supply chain

* Releases: multi-arch images on GHCR, SBOMs (SPDX + CycloneDX) by syft,
  cosign keyless signatures, signed SBOM attestations, SLSA build provenance —
  see [VERIFY.md](VERIFY.md).
* CI runs lint and every service's test suite on each PR. Dependency and
  container scanning in CI are not yet enabled
  ([VULNERABILITY_MANAGEMENT.md](VULNERABILITY_MANAGEMENT.md)).

## 10. Secure development

Code review via pull requests; no exploit code accepted (SECURITY.md §6);
property-based and differential fuzzing of the scope invariant; adversarial
tests for auth, audit and scope; tenancy isolation tests that run as the
non-superuser application role.

## 11. Not provided (do not claim otherwise)

No SOC 2 report, no ISO 27001 certificate, no FIPS-validated crypto module, no
penetration-test report, no SSO/MFA, no built-in TLS, no at-rest encryption of
the database, no hosted service operated by the project. The
[SOC 2 mapping](SOC2_CONTROL_MAPPING.md) marks each gap.
