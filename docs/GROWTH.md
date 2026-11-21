# Growth: exposure check, trust pages, supplier monitoring

Three features that show what Paddock does without asking anyone to hand over
access. All three are built on **passive data only**.

## What "passive" means here

Paddock sends **no packet to the assessed domain** and never connects to any
address it learns about. The engine (`orchestrator/app/growth/engine.py`) takes
exactly two injected clients:

| Source | Used for |
|---|---|
| A recursive DNS resolver (dnspython) | NS, A/AAAA, MX, TXT, CAA, DS, CNAME, `_dmarc`, `_mta-sts`, `_smtp._tls`, common DKIM selectors |
| Certificate-transparency rows (crt.sh) | Host names, expiry, wildcard and issuer sprawl, weak keys/signatures when the log supplies them |

DNS lookups go to your resolver (which may in turn query the domain's own
authoritative servers, as any lookup does). There is no HTTP, TLS handshake,
port probe or banner grab, so no proof-of-control is needed and the feature
cannot be used to attack a target. Tests run against a fake resolver and a
fake CT log with no network.

What it deliberately does **not** do: fetch the MTA-STS policy file, confirm a
takeover by loading a page, or infer software versions (there is no passive
version signal). Anything that would need a probe is reported as
`confidence: "possible"`, never as confirmed.

### Checks

* **Subdomains** from CT (capped at `GROWTH_MAX_HOSTS`, default 150), resolved via DNS.
* **Email authentication**: SPF (missing, `+all`, `?all`, no `all`, multiple records,
  `ptr`, >10 lookups counted across the include tree), DMARC (missing, `p=none`,
  partial `pct`, no `rua`), DKIM key strength at common selectors, MTA-STS and
  TLS-RPT records.
* **Dangling DNS**: CNAMEs whose target is NXDOMAIN. Targets on takeover-prone
  services (GitHub Pages, Heroku, Azure, S3, Fastly, Netlify and about 30 more)
  or on an apparently expired registrable domain are rated high and "possible".
  Delegated nameservers and MX hosts that do not resolve are flagged too.
* **Certificates**: expiry on live hosts that have no replacement logged (a renewed
  cert never alerts), wildcard sprawl, issuer sprawl, missing CAA, weak RSA/SHA-1
  when CT data includes them.
* **Exposure hygiene**: administrative or non-production names that resolve
  publicly; private addresses in public DNS.

Grade: start at 100, deduct per severity (low 2, medium 6, high 12, critical 25),
a repeated rule is capped, then A at 90+, B 80+, C 65+, D 50+, else F. A
critical finding caps the grade at D; a high finding means at best B. A CT
outage degrades gracefully: the certificates check shows "unknown" and is not
penalised.

## 1. Free exposure report (lead generation)

`POST /v1/public/exposure-report` `{domain, email?, consent?, captcha_token?}`
returns `202 {id, status, cached}`. `GET /v1/public/exposure-report/{id}` returns
the graded summary (grade, score, reasons, scorecard, counts, email posture), a
**teaser** of the top three findings with masked host names (`a***.example.com`)
and no remediation detail, a count of hidden findings, and a call to action to
sign up. The public page is `/check` (also `/check?id=...` for a shared result).

Jobs are rows in `exposure_reports` claimed by the runner loop with
`FOR UPDATE SKIP LOCKED`, so replicas cooperate and a crashed run is re-queued
(three attempts).

### Abuse controls

| Control | Default |
|---|---|
| Domain validation: registrable public domain only. Rejects IP literals in every spelling, internal/reserved TLDs, public suffixes, sub-domains, URLs, ports, wildcards, bad IDN/punycode, over-long names | always on |
| Per-IP requests (`GROWTH_IP_REQUESTS_PER_HOUR`) | 10 / hour |
| Per-domain fresh assessments | 5 / day |
| Global fresh assessments (`GROWTH_GLOBAL_DAILY_CAP`) | 500 / UTC day |
| Queue depth (`GROWTH_MAX_QUEUE_DEPTH`) | 200 then 503 |
| Cache | one assessment per domain per 24 h; repeats return the same report and spend no budget |
| CAPTCHA hook | no-op by default; `GROWTH_CAPTCHA_PROVIDER=turnstile` + `GROWTH_TURNSTILE_SECRET`, or `abuse.set_captcha_verifier()` |
| Limiter outage | fails closed (503) |

IP addresses are never stored, only a salted hash (set `GROWTH_IP_HASH_SALT`).
Behind a proxy, list it in `TRUSTED_PROXY_CIDRS` so the real client IP is used.

**Leads**: an email is stored in `exposure_leads` only when `consent` is true,
with the consent time and hashed IP. Without consent the email is discarded.

**No tenant data**: the public rows live in the platform (default) tenant and
RLS hides them from every customer tenant. Responses carry no tenant, queue or
internal state, and failures are reduced to `domain_not_found` or
`assessment_failed`. The only audit noise is the generic mutating-request
record for each `POST`.

## 2. Trust / posture pages

Admins manage links under **Reports → Share trust page** (`/reports/trust`) or
`POST/GET/DELETE /v1/trust-links` (admin only).

* Token: 256 random bits plus a 128-bit HMAC tag (`pt1.<body>.<tag>`). The tag
  is a cheap forgery filter before any database work. Set `PADDOCK_SECRET_KEY`
  to key it (rotation via `PADDOCK_SECRET_KEY_OLD`); otherwise the random body
  is the only secret.
* Only the SHA-256 of the token is stored. The URL is shown once at creation.
* Expiry (1 to 365 days), immediate revocation (history kept), optional
  password (bcrypt, 8+ characters, attempts throttled per link and IP).
* Sections: `grade`, `verified_fixes`, `sla`, `compliance`, `coverage`. The
  public API returns only those, and only aggregates: counts, percentages,
  grades. Never findings, host names, IPs or asset values.
* Expired, revoked, forged and unknown tokens all return the same 404.
* Every successful view is written to the owning tenant's audit chain with the
  running view count; wrong passwords are audited as denials.
* Cross-tenant lookup: the anonymous viewer has no tenant, so the hash is
  resolved under a narrow RLS policy (`trust_public_lookup`, schema 032) that
  can return exactly the one matching row. Everything after runs as the link's tenant.
* Aggregates are cached for 5 minutes per link. Public page: `/trust/:token`
  (`noindex`, `Cache-Control: no-store`).

## 3. Supplier monitoring

**Risk → Suppliers** (`/suppliers`, `/v1/suppliers`). Add a vendor's registrable
domain with a criticality and an interval (daily, weekly, monthly). The runner
claims due suppliers per tenant with a lease, runs the same engine, stores the
assessment (history capped at 120) and the diff against the previous one.
Failures back off exponentially (1 h, 2 h ... 24 h) and keep the last good grade.
"Check now" makes a supplier due immediately.

New integration events (see [Integrations](INTEGRATIONS.md)):

| Event | When | Severity |
|---|---|---|
| `supplier.grade_changed` | the letter grade moved | drop: medium, or high for D/F or a high/critical supplier; improvement: info |
| `supplier.dangling_dns` | a new possible-takeover or dangling record | high |
| `supplier.cert_expiring` | a new expired or expiring certificate | medium/high |

Event ids derive from the assessment, so replays never duplicate deliveries,
and an unchanged problem is announced once. The first assessment raises
dangling/certificate events for existing issues but no grade event.

## Configuration

All settings use the `GROWTH_` prefix (`orchestrator/app/growth/config.py`):
`CACHE_HOURS`, `IP_REQUESTS_PER_HOUR`, `DOMAIN_REQUESTS_PER_DAY`,
`GLOBAL_DAILY_CAP`, `MAX_HOSTS`, `DNS_NAMESERVERS`, `CT_URL`, `RUNNER_ENABLED`,
`SUPPLIER_INTERVAL_SEC`, `SIGNUP_URL`, and the CAPTCHA settings above. Set
`GROWTH_PUBLIC_ENABLED=false` to turn the public exposure endpoints off.
