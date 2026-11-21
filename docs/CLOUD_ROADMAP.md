# Cloud roadmap — the defensive counterpart to an autonomous pentester

Autonomous offensive agents (Strix and friends) find holes by acting like an
attacker. Paddock's cloud edition should be their mirror image: **agents
that continuously learn your surface, decide what actually matters, and close
it — with every action scope-proven, audited and reversible.**

This document ranks the features that benefit most from running as a managed
cloud service (shared compute, global vantage points, cross-tenant intel), and
lists the hardening still owed before multi-tenancy.

---

## 0. Prerequisites for any multi-tenant cloud (do these first)

| # | Item | Why it is non-negotiable in the cloud |
|---|------|------|
| P1 | **Proof-of-control for scope** — a tenant may only add a domain after a DNS `TXT` or `/.well-known/paddock/<token>` check (ACME-style), and IP ranges only via RDAP/WHOIS org match or a signed LOA upload. Re-verify on a schedule; auto-expire scope that loses proof. | Today scope is "an operator typed it in". In a SaaS, that is a scan-anyone-for-free service. Ownership proof is what makes a hosted scanner legal. |
| P2 | **Resolved-IP pinning in workers** — `/v1/scope/check` now returns a decision computed on resolved addresses; workers should connect to exactly those IPs (httpx transport / `--resolve` for Go tools). | Closes the DNS-rebinding TOCTOU between the scope check and the tool's own lookup. |
| P3 | **Isolated egress per tenant** — scanners in Firecracker/gVisor sandboxes with no route to the control plane or cloud metadata, published egress IP ranges per region. | The guardrails added to `scope.py` deny metadata/internal at decision time; the network must deny it too (defence in depth). |
| P4 | **Keyed, anchored audit chain** — HMAC the chain with a KMS-held key and anchor the head hourly to an append-only store (S3 Object Lock / a transparency log). Make audit writes fail-closed on mutating routes. | Today the chain is tamper-*evident* only against someone without DB superuser. Customers' auditors will ask. |
| P5 | **Tenant isolation in Postgres** — `tenant_id` on every row + RLS policies, a non-superuser app role, per-tenant encryption keys for evidence blobs. | The current schema is single-tenant by design. |

---

## 1. Highest-leverage features

### 1.1 Exposure Watch — "are we affected?" in minutes, not days ★★★
When a CVE lands in **CISA KEV** or crosses an **EPSS** threshold, query every
tenant's graph (CPE ↔ fingerprint, SBOM ↔ package) the moment it lands, and
push an alert with the exact affected assets and the attack path to each one.

*Why cloud:* intel is ingested and matched **once**, centrally, for all tenants;
a self-hosted box polls hourly at best. This is the "wow" moment for a buyer.

### 1.2 Farrier — the fix agent (defensive autofix) ★★★
For each high-value attack path, an agent drafts the fix where the fix lives:
a PR against the IaC repo (security group, bucket policy), the web-server config
(missing headers, TLS), or the lockfile (dependency bump) — then **re-probes in
scope to verify** and closes the ticket only when the path is actually gone.
Human approval gate on every PR; no direct production changes.

*Why cloud:* LLM inference, repo integrations (GitHub App) and the verify-loop
scheduler are naturally hosted. This is the strongest "Strix, but blue" story.

### 1.3 Multi-vantage continuous monitoring ★★★
Probe from several regions/ASNs on a schedule, diff the surface, and alert on
*changes* (new open port, new subdomain, cert about to expire, header dropped,
takeover-able CNAME appears). Geo-fenced or WAF-dependent exposures only show
up from some vantage points.

*Why cloud:* a self-hosted install has exactly one vantage point.

### 1.4 Cloud-account connectors → inside-out attack paths ★★☆
Read-only connectors (AWS IAM role, GCP SA, Azure app) pull inventory: load
balancers, instances, security groups, IAM roles, buckets, databases. Join it
onto the external graph so an attack path can read:
`internet → ALB → EC2 (CVE) → instance role → s3://customer-pii`.
That is the "crown jewel" half of the README's promise, made real.

### 1.5 Lookalike & brand-abuse watch ★★☆
Stream CT logs (CertStream) at fleet scale and match tenants' brands for
typosquats/IDN homoglyphs (the scope normaliser's IDNA handling already does the
hard part), newly-registered lookalike domains, and phishing kits on them.
Output: takedown-ready evidence packages. Purely defensive and very sticky.

### 1.6 Leaked-secret watch ★★☆
Watch public GitHub, gists and paste sites for the tenant's domains, key
prefixes and repo names; on a hit, open a rotation ticket with the owning team.
Never test the secret against the live service (hard rule: no credential use).

---

## 2. Strong follow-ons

- **PR gate (GitHub App):** on every PR, run SCA + IaC policy + reachability and
  comment with *attack-path impact* ("this opens 0.0.0.0/0:5432 on a host that
  reaches the payments DB").
- **Honeytokens / canaries:** seed decoy credentials, DNS names and documents
  into the surface; alert when touched. Cheap, high-signal, defensive.
- **Evidence & compliance packs:** map findings + the audit chain to SOC 2 /
  ISO 27001 / PCI controls and export auditor-ready reports.
- **MCP server for the graph (read-only):** let analysts' own agents (Claude,
  etc.) query assets, paths and findings with the caller's RBAC/ABAC applied.
- **Risk-model learning across tenants (privacy-preserving):** aggregate which
  finding types actually led to incidents to calibrate the cold-start ML model.
- **Status-page style "exposure score" for vendors:** third-party risk —
  passive-only assessment of a supplier's surface (no active probing without
  their proof-of-control).

---

## 3. What this release already hardened (and how it was tested)

- **Scope parser differentials:** fuzzed 10M hostile targets against WHATWG
  (Ada) and RFC 3986 parsers — 77,554 differentials per million before, **0**
  after (`python hardening/stress_scope.py --n 1000000 --baseline <rev>`).
  Includes a real bypass: `http://evil.com#@target.com` used to be allowed as
  `target.com` while httpx/nuclei connected to `evil.com`.
- **SSRF / rebinding guardrails:** cloud-metadata and reserved ranges are
  hard-denied; an in-scope hostname that resolves to a private address needs an
  explicit CIDR entry; every resolved address must be in scope.
- **Scope-entry validation:** no public-suffix wildcards, no CIDRs wider than
  /16 (v4) or /32 (v6), no protected ranges; values stored canonically.
- **Auth:** fail-closed `AUTH_MODE` default, API-key scopes narrow (never widen)
  roles, strict JWT claims, login throttling + constant-time unknown-user path,
  trusted-proxy-only `X-Forwarded-For`, CORS allowlist.
- **Audit:** NUL-byte and float handling so actions can't go unaudited and the
  chain can't be falsely "broken".

## 4. Still open (tracked for the next hardening pass)

1. Audit HMAC + external anchoring + fail-closed audit on mutating routes (P4).
2. Require `auth_doc_ref` on scope entries and take `added_by` from the
   authenticated principal instead of the request body.
3. Pin resolved IPs in the active worker (P2).
4. Don't log the generated bootstrap admin password; expose `/docs` only to
   authenticated users in enforce mode; add security headers (HSTS, nosniff,
   frame-ancestors).
5. Stream `audit.verify()` instead of loading the whole log into memory.
