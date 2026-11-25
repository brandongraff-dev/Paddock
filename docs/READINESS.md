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
- **Graph sync** is platform-tenant only. (The fleet agent used to be too; since agent v2 it is per-tenant:
  per-tenant enrollment tokens, and row-level security on every fleet table.)
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

## 8. Host agent v2 and provable containment (P2)

([AGENT_V2.md](AGENT_V2.md), [ASSURANCE_P2.md](ASSURANCE_P2.md), [FLEET_WIRING.md](FLEET_WIRING.md))

A server can now be asked, and answer with evidence, whether SSH is hardened and whether the firewall denies
inbound by default. The verdict is "no counterexample under this evidence", at evidence tier `configured`.

**Built and tested**
- **Enrollment and identity**: per-tenant one-time tokens (hashed, atomic redemption, generic 401, rate limit and
  lockout); the agent proves possession of its own Ed25519 key; rotate, revoke (immediate) and re-key (a host
  that lost its state keeps its history); v1 agents are kept and told `403 re_enroll_required`.
- **Signed evidence**: ten ordered server checks (size, parse, agent, key, digest, signature, clock, atomic
  sequence claim, schema, persist), each refusal audited; a tampered or replayed envelope leaves the previous
  posture in place, and silence turns into `UNKNOWN`.
- **The agent**: standard library only, Python 3.8 or newer, a vendored RFC 8032 signer that is byte-identical to
  OpenSSL's, a write-ahead sequence counter, an offline outbox, and a fix for a hole in the old agent (it ran
  server-supplied revert commands verbatim).
- **Collectors**: sshd (with `Match` probes), listeners with process attribution, a firewall model for nft and
  iptables, patch state, self-health. Parsers are pure functions tested on real captures from Ubuntu 24.04.
- **Invariants**: a typed host-config predicate language with three-valued logic, two standard invariants, a
  brute-force oracle and mutation tests. The `host_fw` builder turns a posture into edges, coverage and facts.
- **End to end**: `orchestrator/tests/test_assurance_p2_e2e.py` runs the real agent against the real server (RLS
  role, two tenants): enrol, sign, `HOLDS`, a password flip to `VIOLATED` with a finding, tamper refused, replay 409,
  silence to `UNKNOWN`, a port conflict with the external scan, legacy credential refused, 20 concurrent
  redemptions with one winner, rotation, re-key and revoke.
- **Packaging**: a byte-reproducible single-file archive (same bytes on Python 3.8 to 3.13), a POSIX installer
  (shellcheck clean; checksum and cosign gates; the token never on argv) and a release job that signs it.

**Gaps (all of them are open work, not hidden)**
- **Never run on a real host.** Not run: the installer as root, the unit under a real systemd, `nft`/`iptables`
  applied for real, a real `sshd -T` (none was available to capture; the sshd fixtures are written from the
  manual), RHEL, SUSE or Alpine. The release workflow has not run on GitHub, and the cosign branch of the
  installer was tested only against a recording fake.
- **Signed is not true.** A compromised host signs whatever it likes; only ports the external scan or cloud
  configuration can see are cross-checked. The agent is one root process that talks to the network (decision O2);
  the privilege split is planned.
- **Precision loss on purpose**: ipset, marks, DNAT, Docker/Kubernetes dataplanes, a missing `nft` binary, a
  non-root agent and a container all give `UNKNOWN` rather than a guess.
- **A host that leaves the graph is not flagged.** A revoked or legacy agent, or a removed tag, drops the host out
  of the selector of "all hosts" invariants; unless it is a declared `server` (which reads `UNKNOWN: no_agent`)
  nothing says it went missing. Findings for a host that left the selector are closed as fixed although it was
  never proven.
- **No UI**: the dashboard's Fleet page does not mint tokens, rotate keys or show verdicts. The posture
  freshness limit (6 h) is not yet a setting.
- **Rate limits are per process**, so N orchestrator replicas allow N times the limit.
- No KEV matching or distro advisory data (patch state is collected, not judged), no Windows or macOS.

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
7. **Run agent v2 on three real hosts** (Ubuntu, RHEL 9, a Docker host): the installer as root, the unit under
   systemd, a real `sshd -T`, and a pre-release tag through the release workflow with cosign verification. Fix what
   the fixtures could not tell us.
