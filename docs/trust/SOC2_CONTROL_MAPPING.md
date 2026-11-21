# SOC 2 control mapping (Trust Services Criteria, Common Criteria CC1–CC9)

**Status: no SOC 2 report exists.** This is a readiness mapping for an
organisation that operates Paddock (self-hosted or as a service) and wants to
know what the product contributes to each criterion and what the operator's
own process must supply. SOC 2 attests an *organisation's* controls, never a
piece of software; product features only make some controls easier to
operate and evidence.

Legend — **P**: provided by the product (cite file). **O**: operator process
(policy/procedure the operating organisation must run). **GAP**: missing in
the product and called out honestly.

| Criterion | What it asks | How Paddock / the operator satisfies it | Status |
|---|---|---|---|
| **CC1 Control environment** | | | |
| CC1.1–1.2 integrity, ethics, board oversight | code of conduct, governance | `CODE_OF_CONDUCT.md`, authorised-use statement (SECURITY.md §12). Board oversight, HR policies | **O** |
| CC1.3 structure, authority | defined roles | product roles viewer/analyst/auditor/admin (`auth.py ROLE_CAPABILITIES`) map to org duties | **P** + **O** |
| CC1.4 competence | hiring, training | security training records | **O** |
| CC1.5 accountability | individual accountability | every mutation attributed to an actor in the audit chain (`audit.py`) | **P** + **O** |
| **CC2 Communication & information** | | | |
| CC2.1 quality information | reliable data for controls | provenance per fact (`provenance` table, `/v1/provenance`); hash-chained audit | **P** |
| CC2.2 internal communication | security responsibilities communicated | this `docs/trust/` set, SECURITY.md, runbooks (`hardening/RUNBOOK.md`) | **P** (docs) + **O** |
| CC2.3 external communication | customers, reporters | vulnerability reporting channel (SECURITY.md header, [VULNERABILITY_MANAGEMENT.md](VULNERABILITY_MANAGEMENT.md)); status page / customer notices | **O** |
| **CC3 Risk assessment** | | | |
| CC3.1–3.4 objectives, risk identification, fraud, change | documented risk assessment | threat model + known gaps (SECURITY.md §2, §10); the product itself is an ASM risk tool for customers' assets. Annual risk assessment, vendor risk | **O** |
| **CC4 Monitoring activities** | | | |
| CC4.1 ongoing evaluations | control monitoring | `GET /v1/audit/verify` (chain + anchor check), `make harden-check`, readiness/health endpoints | **P** + **O** (schedule + review the checks) |
| CC4.2 deficiency communication | remediation tracking | findings/tickets/SLA in-product; internal issue tracker | **P** + **O** |
| **CC5 Control activities** | | | |
| CC5.1–5.2 control selection, technology controls | policies implemented in tech | RBAC deny-closed default (`required_capability`), ABAC in SQL, scope allowlist enforced in 3 layers (SECURITY.md §3), RLS tenancy ([TENANCY.md](TENANCY.md)) | **P** |
| CC5.3 policies & procedures | written policies | [DATA_RETENTION.md](DATA_RETENTION.md), [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md), [VULNERABILITY_MANAGEMENT.md](VULNERABILITY_MANAGEMENT.md) are templates to adopt | **O** |
| **CC6 Logical & physical access** | | | |
| CC6.1 logical access security | authN, least privilege, segregation | JWT + hashed API keys, scope-narrowed keys, non-superuser DB role with no DDL and no audit rewrite (`099_tenancy.sql`), tenant RLS, network segmentation (compose) | **P** |
| CC6.1 encryption of data at rest | | integration secrets AES-256-GCM; **database volumes not encrypted by the product** | **P** partial / **GAP** → **O** (disk encryption) |
| CC6.2 user provisioning | registration/authorisation | admin-only key issuance; user creation by operator (`python -m app.tenancy create … --admin`) | **P** partial; **GAP**: no SCIM, no self-service user admin API |
| CC6.3 access modification/removal, least privilege | role changes take effect | live DB role/clearance re-read on every JWT request; API key revoke/expiry; suspended tenants locked out | **P**; periodic access reviews **O** |
| CC6.1/6.2 strong authentication | MFA/SSO | **GAP**: no MFA, no SAML/OIDC SSO | **GAP** |
| CC6.4 physical access | data centres | hosting provider's SOC 2 | **O** |
| CC6.5 disposal | secure deletion | tenant purge procedure ([DATA_RETENTION.md](DATA_RETENTION.md)); media disposal | **O**; **GAP**: no automated purge job |
| CC6.6 boundary protection | external threats | `internal: true` data network, only orchestrator/dashboard published, scope-gated egress, trusted-proxy XFF handling, CORS allowlist | **P**; TLS termination **O** |
| CC6.7 transmission | encryption in transit | outbound HTTPS; **no TLS inside the deployment** | **GAP** → **O** (reverse proxy / mesh) |
| CC6.8 malicious software | unauthorised software | signed images + SBOM + SLSA provenance ([VERIFY.md](VERIFY.md)); deploy-by-digest policy | **P** + **O** |
| **CC7 System operations** | | | |
| CC7.1 vulnerability detection | config + vuln scanning | the product scans customers' assets; for Paddock itself SBOMs per release, ruff + tests in CI; **GAP**: no dependency/container scanning in CI | **P** partial / **GAP** |
| CC7.2 anomaly monitoring | detect security events | audit log of denials (`action=deny`), `mlrisk` anomaly detection on assets; log shipping to SIEM | **P** partial; SIEM **O** |
| CC7.2 log integrity | tamper resistance | keyed HMAC chain, external anchors (Object Lock), fail-closed audit writes | **P** |
| CC7.3–7.5 incident evaluation, response, recovery | IR program | [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) template; audit + outbound logs as forensic sources; backups/DR | **O** (backups are not automated by the product: **GAP**) |
| **CC8 Change management** | | | |
| CC8.1 authorised, tested, approved changes | change control | PR workflow + CI (lint, per-service tests, dashboard tsc/vitest); tagged releases built only by `release.yml` with provenance binding image → commit | **P** + **O** (branch protection, required reviews) |
| **CC9 Risk mitigation** | | | |
| CC9.1 business disruption | continuity | health/readiness probes, restart policies; BCP/DR, backups | **O** |
| CC9.2 vendor management | subprocessors | [SUBPROCESSORS.md](SUBPROCESSORS.md) template; optional LLM provider is opt-in | **O** |

## Gap summary (product)

1. No MFA / SSO / SCIM (CC6.1–6.3).
2. No TLS inside the deployment; no at-rest encryption of database volumes
   (CC6.1, CC6.7) — operator must provide both.
3. Multi-tenant isolation covers the orchestrator API only; compute services
   and the scan pipeline are single-tenant ([TENANCY.md](TENANCY.md)).
4. No automated retention/purge jobs and no automated backups (CC6.5, CC7.5).
5. No dependency/container vulnerability scanning in CI; actions not SHA-pinned
   (CC7.1, CC8.1).
6. Audit rows newer than the last anchor can be deleted (tail truncation) by a
   database superuser without detection until the next anchor; without
   `AUDIT_HMAC_KEY` the chain can be rewritten up to the last anchor's id.
   No built-in SIEM export (CC7.2).
7. No third-party penetration test (CC4.1).
