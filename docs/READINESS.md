# From open-source project to something businesses pay for

Status as of this branch: what's built, what's tested, and the gaps that
remain. Each section links to the doc with the details.

## Positioning: find it, prove it, fix it, prove it's fixed

Most security tools stop at a list of possible problems. Paddock closes the
loop. For each finding it:

1. **Proves it's real** with a safe, non-destructive check, run only against
   systems the customer has proven they own
   ([VERIFICATION.md](VERIFICATION.md)).
2. **Writes the fix**: a pull request, config change or dependency bump, behind
   an approval gate (remediation service, `paddock fix`).
3. **Re-tests after the fix**, and reopens the finding if the fix didn't hold.
4. **Records evidence** that auditors, insurers and customers accept
   ([REPORTS.md](REPORTS.md), [GROWTH.md](GROWTH.md)).

## The scorecard

| Area | Now | What's still missing |
|---|---|---|
| **Signal quality** | ★★★★★ | calibrating thresholds on real customer data |
| **Integrations** | ★★★★★ | live tests against real SaaS tenants |
| **Time to first value** | ★★★★☆ | a first green run of the install workflow on GitHub; a Pi image built on real hardware |
| **Operations** | ★★★★☆ | Helm deployed on a real cluster; a 24 h soak test |
| **Enterprise trust** | ★★★★☆ | per-service keys; SOC 2 audit and a third-party pen test |
| **Reporting** | ★★★★☆ | customer branding; scheduled reports beyond the weekly digest |
| **Commercial plumbing** | ★★★★☆ | real prices, legal review of the CLA, the vendor licence key, a live Stripe account |

---

## 1. Signal quality

- **Detection gate** in CI: 207 seeded cases across 6 engines, with
  precision/recall thresholds ([EVALS.md](EVALS.md)).
- **Finding lifecycle**:
  - cross-engine dedupe;
  - accept-risk / false-positive with a required reason and expiry;
  - suppressions and SLA clocks;
  - automatic reopen when an issue comes back;
  - an explained priority on every finding.
- **Verified exploitability**: 11 safe checks (exposed files, admin panels, takeover,
  TLS, headers, open ports…).
  - Every connection is pinned to IPs the scope check vetted, so DNS
    rebinding can't redirect a check.
  - Redirects are followed only within the same host.
  - Checks run only against targets with proven ownership.
  - Verdicts move priority up or down; a verdict never closes a finding on its own.
- **Proof it's fixed**: marking a finding fixed, closing its ticket, or merging
  the fix PR schedules a re-check. Only the worker that ran the job can submit
  the result, so a "verified fix" can't be forged.

## 1a. Reachability, choke-points & the Proving Ground

The Wargame line (docs/WARGAME.md) turns the attack-path list into a remediation
plan and a provable number.

- **Choke points** (`correlation/app/engine/chokepoint.py`): a node-capacitated
  minimum cut (Dinic) over the asset graph computes the *fewest* assets whose
  removal cuts the most paths to crown jewels, ranked. "Cut these 3, close 86%."
- **Crown-jewel exposure** (`reachability.py`): per jewel, how many sources can
  reach it, over how many paths, in how few hops, and whether it is proven
  closed (no source reaches it in the model).
- **Path coverage** (`coverage.py`): the share of routes to crown jewels proven
  closed / risk-accepted / tripwired vs. open, plus a proven-vs-inferred label
  on every hop. The one board/insurer number.
- **Proving Ground** (`wargame/` service): for the hops that matter, rebuild the
  component as an isolated replica, run the *real* check on the copy, apply the
  fix, re-run, and emit a hash-chained, signed before/after proof. The
  `IsolationGuard` refuses any non-replica target and fails closed.

All of the above are computed by the correlation service after each attack-path
recompute, and by the (off-by-default) wargame service, behind the same tenant
isolation (verified: RLS forces per-tenant rows on every new table, least-
privilege `paddock_svc_wargame` role). Tests: choke-point/reachability/coverage
and the full pipeline are DB-tested in `correlation`; the wargame guard,
backends, scenarios, prover, signed proofs and persistence are tested with the
in-memory `fake` backend.

**Gaps:**
- The `docker` sandbox backend is written to the interface but is not exercised
  in CI (no docker-in-docker); it needs a real daemon + a soak on live images.
- The scenario library is three high-value scenarios (CVE repro, default
  credential, unauth endpoint); more coverage is the next step.
- HTTP/TCP probes assume the replica (or a future probe sidecar) carries the
  client tools; the version-identity signal does not.
- These artefacts are exposed on the correlation/wargame service APIs but are
  **not yet surfaced through the orchestrator `/v1` API or the dashboard** — UI
  wiring is the follow-up (the owner's dashboard design is authoritative).
- Proof signing uses an env-provided HMAC key; a KMS/HSM-bound key and a
  third-party-verifiable signature format are still to do.

## 2. Integrations: connect anything

- **The integrations framework**: 21 connectors behind one contract.
  - Secrets are encrypted.
  - Delivery is leased, retried and dead-lettered.
  - Outbound connections are pinned to the validated IP.
- **Connectors**:
  - Chat and alerting: Slack, Teams, email, PagerDuty, webhooks.
  - Ticketing: Jira, ServiceNow and Linear, with two-way sync.
  - SIEMs, in OCSF: Splunk, Sentinel, Elastic, syslog, Google SecOps.
  - Cloud: AWS, GCP, Azure.
  - Asset context: CrowdStrike, Defender, ServiceNow CMDB.
  - Network quarantine: UniFi and Meraki, behind an approval gate that
    requires a written reason.
- **Universal ingest** (`POST /v1/ingest`): SARIF, CycloneDX, SPDX, OCSF, Trivy,
  Grype, Semgrep, Nuclei, ZAP and CSV.
  - Each source gets its own ingest token.
  - Fuzzed against hostile input.
  - Handles a 20k-result upload in about 20 s.
- **MCP server** (`paddock-mcp`): Claude, Cursor and other assistants can query
  findings and posture. It is read-only unless explicitly allowed to write.
- **CI drop-ins** for GitHub Actions, GitLab, Bitbucket, Azure DevOps, CircleCI,
  Jenkins and pre-commit ([CONNECT.md](CONNECT.md)).
- **Open-source developer CLI**: `paddock scan` / `paddock fix` / `paddock init`.
  - Runs locally and needs no server.
  - Opens fix pull requests.
  - Outputs SARIF ([CLI.md](CLI.md)).
- **SSO and identity**:
  - OIDC + SAML: signed requests, encrypted assertions, single logout.
  - Entra group overage.
  - SCIM 2.0 with full filter support ([SSO.md](SSO.md)).
- **Developer surface**: API contract with breaking-change checks; Python and
  TypeScript SDKs; Terraform provider.

**Gap:** every connector is tested against protocol-accurate fakes, not real
tenants. ServiceNow, UniFi, Meraki, GCP, Azure and Google SecOps were built
from their API docs.

## 3. Time to first value

- **One-line install** (`scripts/install.sh`): generates secrets, starts the
  lite stack (6 services) and prints the login.
- **Setup wizard** and proof of ownership (DNS TXT record, HTTPS file, or
  attestation).
- **Free exposure check** (`/check`): a passive report on any domain, using
  DNS and certificate-transparency data only.
- **Sentry kit** ([SENTRY_KIT.md](SENTRY_KIT.md)):
  - one-time enrollment tokens;
  - a Raspberry Pi first-boot image;
  - mirror-port setup steps for common switches;
  - an offline upload buffer.

**Gaps:**
- The install workflow and the pi-gen image build haven't run outside this
  sandbox.
- The switch menu names in the kit guide haven't been checked against
  current firmware.

## 4. Operations

- Versioned migrations, which re-apply tenant isolation after any new table.
- Helm chart and backup/restore procedures.
- Prometheus metrics and Grafana dashboards.
- Retention settings, purged per tenant.
- **Scale tests**:
  - Findings: 100k findings across 5 tenants, with the hot findings queries
    under 25 ms p50 after the new tenant-leading indexes.
  - Ingest: a 20k-result upload (previously never finished).
  - Sentry: 1M flows/day from 100 sensors, with p95 of 41 ms steady and
    183 ms after a 50× burst ([ISOLATION_HARDENING.md](ISOLATION_HARDENING.md),
    [SENTRY.md](SENTRY.md)).
- **Public status endpoint** ([STATUS_PAGE.md](STATUS_PAGE.md)).

**Gaps:**
- Helm has never been deployed to a real cluster.
- No 24-hour soak test has been run.
- Ingest still makes one database round trip per result.

## 5. Enterprise trust

- **Tenant isolation everywhere**:
  - Postgres row-level security in the orchestrator **and** all 13 compute
    services, each connecting as its own least-privilege role.
  - Workers carry the tenant on every job and callback.
  - Results are rejected if their tenant doesn't match the job's.
- **Isolation tests that fail on a regression**:
  - every table must be tenant-scoped or explicitly global;
  - every API route is swept across tenants (~2,500 calls);
  - 900 interleaved concurrent requests are checked for leakage
    ([ISOLATION_HARDENING.md](ISOLATION_HARDENING.md)).
- **MSP console** ([MSP.md](MSP.md)):
  - delegated, short-lived access to child tenants;
  - nothing an MSP creates outlives its grant;
  - every action is recorded in both audit trails.
- **Audit and supply chain**:
  - a hash-chained, keyed, anchored audit log that fails closed;
  - signed releases with SBOMs and provenance;
  - a trust pack ([trust/](trust/SECURITY_WHITEPAPER.md)).
- **Security reviews done on this branch**:
  - an adversarial review of the public surface (13 bugs fixed);
  - a tenancy stress test (9 bugs fixed);
  - an independent security review (8 findings fixed or mitigated).

**Gaps:**
- **One shared service key.** In strict mode it is limited by route allow-lists
  and job binding. Per-service keys or per-job tokens are the real fix
  ([trust/TENANCY.md](trust/TENANCY.md)).
- **Graph sync and the fleet agent** are platform-tenant only.
- **Foreign keys bypass RLS** (documented).
- **External scanners still resolve DNS themselves**: `tlsx`, `nuclei` and the
  screenshot browser in the active worker don't get the pinned IPs. The
  verify loop's own checks are pinned.
- **Lead emails** from the free exposure check need double opt-in before any
  outreach.
- **Business work, not code**: SOC 2 Type I, a third-party pen test, and data
  residency.

## 6. Reporting

- **Weekly digest**: per tenant, exactly once.
- **Executive report** in HTML or PDF.
- **Compliance evidence packs**: PCI DSS 4.0, NIST CSF 2.0, CIS v8, ISO 27001,
  IEC 62443-3-3 and EU CRA ([REPORTS.md](REPORTS.md)).
- **Shareable trust page** for insurers and customers ([GROWTH.md](GROWTH.md)):
  - aggregates only;
  - signed, expiring and revocable links;
  - every view audited.
- **Supplier monitoring**: a passive grade for each supplier, with alerts when
  it changes.

## 7. Commercial plumbing

([BILLING.md](BILLING.md), [EDITIONS.md](EDITIONS.md))

- **Stripe billing**:
  - Checkout and the customer portal;
  - verified, replay-safe webhooks;
  - trials, dunning and usage metering.
- **One consistent upgrade gate**: an HTTP 402 response the dashboard turns
  into an upgrade prompt. Self-hosted installs enforce nothing by default;
  features that exist today stay free.
- **Signed offline licences** for self-hosted, plus a vendor key ceremony
  script. A CLA is in place.

**Gaps:**
- Prices are placeholders.
- The CLA needs a lawyer's review.
- The vendor licence key hasn't been generated or embedded.
- No live Stripe account exists yet.

---

## Recommended next 30 days

1. **Run the unrun workflows on GitHub**: install, release, scale and
   sentry-scale. Fix whatever breaks.
2. **Live connector smoke tests** with sandbox tenants: Jira, ServiceNow, Slack,
   Teams, Splunk, Sentinel, GCP and Azure.
3. **Per-service keys** (or per-job tokens) to retire the shared service key.
4. **Pilots**: 3–5 design partners. Two Sentry sites; tune the detectors and the
   eval gate on real traffic.
5. **Launch the free CLI and the exposure check** as the top of the funnel.
   Pin the installer and CI templates to a release tag first.
6. **Business**: legal review of the CLA, real prices, the vendor key, Stripe,
   and starting SOC 2 Type I.
