# From open-source project to something businesses pay for

Status of the seven readiness areas as of this branch: what's built, what's
tested, and the gaps that remain. The previous version of this page was the
plan. This one records what was done against it.

## The scorecard

| Area | Before | Now | What's still missing |
|---|---|---|---|
| **Signal quality** | ★★☆☆☆ | ★★★★☆ | precision/recall measured on real customer data, not only seeded ranges |
| **Integrations** | ★☆☆☆☆ | ★★★★☆ | live tests against real SaaS tenants; UI for context sync and network actions |
| **Time to first value** | ★★☆☆☆ | ★★★★☆ | a successful run of the clean-machine job on GitHub |
| **Operations** | ★☆☆☆☆ | ★★★★☆ | Helm deployed on a real cluster; HA Postgres runbook exercised |
| **Enterprise trust** | ★★☆☆☆ | ★★★☆☆ | RLS for compute services, SOC 2 audit, third-party pen test |
| **Reporting** | ★☆☆☆☆ | ★★★★☆ | customer branding; report scheduling beyond the weekly digest |
| **Commercial plumbing** | ☆☆☆☆☆ | ★★★☆☆ | real prices, legal review of the CLA, billing provider, vendor signing key |

---

## 1. Signal quality ✅

- **Detection-quality gate** (`hardening/evals/`, [EVALS.md](EVALS.md)):
  207 seeded cases across 6 engines (true issues plus safe lookalikes).
  Precision/recall thresholds fail CI (`ci.yml`).
- **Finding lifecycle** (`app/lifecycle.py`, schema 019):
  - cross-engine dedupe fingerprint;
  - accept-risk and false-positive both require a reason, enforced by a DB
    constraint, with expiry;
  - suppressions with scope and expiry (dashboard **Suppressions** page);
  - per-severity SLA clocks;
  - automatic reopen on recurrence.
- **Explain every priority**: `priority_score` plus `why[]` on every finding
  (KEV, internet-facing, attack-path hops, owner), shown in the findings
  drawer.
- **Evidence** (non-destructive proof) is attached where the engines have it;
  exports and integrations carry a whitelisted subset.
- **SAST/SCA false-positive fixes** from earlier in the branch, now covered by
  the eval gate.

**Gap:** the ranges are synthetic. Calibrate the thresholds on data from the
first pilots.

## 2. Integrations ✅

One contract for every connector (`app/integrations/`,
[INTEGRATIONS.md](INTEGRATIONS.md)):

- `connect → test → sync → health`;
- secrets encrypted with AES-GCM and rotatable;
- an SSRF-safe outbound guard;
- a leased delivery worker with backoff and a dead-letter queue;
- a single **Integrations** page showing status, last delivery and errors.

| Priority | Delivered |
|---|---|
| P0 | **SSO**: OIDC with PKCE and SAML 2.0, plus **SCIM 2.0** users and groups, SSO-required mode with break-glass accounts ([SSO.md](SSO.md)) |
| P0 | **Signed webhooks**: HMAC with timestamps, retries, an event catalogue, replay protection |
| P0 | **Jira / ServiceNow / Linear** with two-way sync: closing the ticket closes the finding, recorded with a reason and the actor ([INTEGRATIONS-TICKETING.md](INTEGRATIONS-TICKETING.md)) |
| P0 | **Slack / Microsoft Teams / email / PagerDuty** for findings, digests and lifecycle events |
| P1 | **SIEM**: Splunk HEC, Microsoft Sentinel, Elastic and syslog/CEF, sending **OCSF 1.3** ([INTEGRATIONS-SIEM.md](INTEGRATIONS-SIEM.md)) |
| P1 | **API contract**: a versioned `/v1` OpenAPI spec checked for breaking changes in CI; Python and TypeScript SDKs; the `paddockctl` CLI ([API.md](API.md), [SDK.md](SDK.md)) |
| P1 | **Terraform provider** for scope entries, integrations, alert rules and owner rules, plus a findings data source (`terraform-provider-paddock/`) |
| P1 | **Cloud**: AWS read-only inventory connector |
| P2 | **EDR/MDM/CMDB context**: CrowdStrike, Microsoft Defender, ServiceNow CMDB ([INTEGRATIONS-CONTEXT.md](INTEGRATIONS-CONTEXT.md)) |
| P2 | **Network gear**: UniFi and Meraki quarantine, behind the approval gate |
| P2 | **CI**: a GitHub Action that emits **SARIF** (`.github/actions/paddock-scan`) |
| P2 | **Standards**: CycloneDX/SPDX in and out, VEX, SARIF, OCSF ([STANDARDS.md](STANDARDS.md)) |

**Gaps:**
- Every connector is tested against protocol-accurate fakes. None has run
  against a real tenant yet; ServiceNow, UniFi and Meraki were written from
  their API documentation only.
- The OCSF class placements haven't been validated against the official
  schema, and the schema isn't vendored.
- Chronicle, GCP and Azure aren't built yet.
- The dashboard doesn't have screens for context-connector sync or network
  actions yet. Both are API-only.

## 3. Time to first value ✅

- **Setup wizard** (dashboard `/setup`): add a domain → prove ownership →
  first results → invite a teammate → connect Slack or Jira.
- **Proof of control** for scope entries, by DNS TXT, an HTTPS file or a
  signed attestation. It's re-verified on a schedule; `REQUIRE_SCOPE_PROOF=true`
  makes unproven entries non-effective. The status is shown on the **Scope**
  page.
- **Single-node mode**: `docker-compose.lite.yml` runs 6 services instead of 17.
- **Clean-machine job** (`.github/workflows/install.yml`): runs
  `make quickstart` from scratch and asserts that findings appear.
  [getting-started.md](getting-started.md) walks through the same steps.

**Gap:** `install.yml` hasn't run on GitHub yet. Watch its first run.

## 4. Operations ✅

([OPERATIONS.md](OPERATIONS.md))

- **Versioned migrations** (`python -m app.migrate`): checksummed, run under
  an advisory lock, and safe with many replicas.
- **Helm chart** (`deploy/helm/`) with HA Postgres guidance.
- **Backup and restore** commands and a zero-downtime upgrade procedure.
- Prometheus `/metrics` with Grafana dashboards (`deploy/grafana`), plus alert
  rules.
- **Retention settings** with a scheduled purge.
- **Scale test** (`.github/workflows/scale.yml`, `hardening/scale_test.py`):
  100k findings checked against a latency budget.
- **Docs site** (mkdocs, `docs.yml`).

**Gaps:**
- Helm is linted in CI but hasn't been deployed to a real cluster.
- Scale is only measured for the orchestrator. 1M flows a day from Sentry is
  still untested.

## 5. Enterprise trust ◐

- **Multi-tenancy** with Postgres row-level security. The orchestrator connects
  as a non-superuser `paddock_app` role, and the full test suite also runs
  under it ([trust/TENANCY.md](trust/TENANCY.md)).
- **Audit chain**:
  - HMAC-keyed and anchored externally;
  - fail-closed: if the audit write fails, the action is refused with a 503;
  - exportable to the customer's SIEM.
- **Session revocation** and tenant suspension take effect on the next request.
- **Supply chain** (`release.yml`): keyless cosign signatures, SPDX and
  CycloneDX SBOMs as signed attestations, SLSA provenance
  ([trust/VERIFY.md](trust/VERIFY.md)).
- **Trust pack** (`docs/trust/`): security whitepaper, SOC 2 control mapping,
  DPA template, subprocessors, incident response, vulnerability management and
  data retention.

**Gaps:**
- **Tenancy covers the orchestrator's database only.** Compute services
  (correlation, graphsync, ML…) connect with their own credentials and bypass
  RLS, and workers don't propagate `tenant_id`. Don't sell a shared multi-tenant
  hosted edition until this is closed; one deployment per customer is safe
  today.
- Webhook and proof-of-control fetches validate the resolved IP but don't pin
  the connection to it (a DNS-rebinding TOCTOU).
- Entra ID group overage (more than 200 groups) isn't handled. SAML doesn't
  support encrypted assertions, signed AuthnRequests, IdP-initiated sign-on
  or single logout yet.
- `release.yml` hasn't run yet.
- SOC 2 Type I, a third-party pen test and data residency are business work,
  not code.

## 6. Reporting ✅

([REPORTS.md](REPORTS.md))

- **Weekly digest**, delivered through any NOTIFY integration. It's exactly-once
  across replicas and capped at `internal` clearance.
- **Executive report** in HTML or PDF (WeasyPrint, fonts embedded): exposure
  trend, MTTR by severity and team, SLA compliance, attack paths closed.
- **Compliance evidence packs**: PCI DSS 4.0, NIST CSF 2.0, CIS v8, ISO 27001,
  IEC 62443-3-3 and EU CRA. Claims are conservative: manual controls are always
  marked "requires attestation", and an empty install claims nothing.

## 7. Commercial plumbing ◐

([EDITIONS.md](EDITIONS.md))

- **CLA** in CONTRIBUTING plus a CLA-check workflow (`cla.yml`).
- **Editions and licensing**: Community, Team, Enterprise and Edge, enforced by
  Ed25519-signed offline license files (air-gap friendly). The API exposes the
  feature set and limits of the current edition.
- **Usage metering**: sites and monitored assets, matching the pricing metric
  (per site plus per 1,000 assets).

**Gaps:**
- Prices in EDITIONS.md are placeholders.
- The CLA text needs review by a lawyer.
- `licensing.VENDOR_PUBLIC_KEYS` is empty. Generate the vendor keypair
  (`scripts/issue_license.py keygen`) and embed the public key before the
  first paid release.
- Billing (e.g. Stripe), a status page and a support SLA aren't set up yet.

---

## Recommended next 30 days

1. **Run the unrun workflows**: `install.yml`, `release.yml` and `scale.yml` on
   GitHub. Fix whatever breaks.
2. **Live connector smoke tests** against sandbox tenants for Jira,
   ServiceNow, Slack, Teams, Splunk and Sentinel, then UniFi and Meraki
   hardware.
3. **Close the tenancy gap** in the compute services, or commit to
   single-tenant hosting for the first customers.
4. **Pin outbound connections** to the validated IP (the DNS-rebinding fix).
5. **Sentry pilot**: two sensors in real environments (an office and a small
   shop). Tune detector thresholds and the eval gate on real traffic.
6. **Legal and pricing**: CLA review, real prices, the vendor license key.
