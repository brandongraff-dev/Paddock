# From open-source project to something businesses pay for

An honest assessment as of this branch, and the order to close the gaps.

## The scorecard

| Area | Today | What a paying customer expects |
|---|---|---|
| **Breadth of detection** | ★★★★☆ ASM, SCA/SBOM, SAST, threat intel, IoT/OT + Sentry behaviour, attack paths, risk ML, fleet agent, remediation | ✅ already a differentiator |
| **Signal quality** | ★★☆☆☆ engines work, but two (SAST, typosquat) shipped as silent no-ops and nobody noticed | measured precision/recall, gated in CI; triage workflow; low noise |
| **Time to first value** | ★★☆☆☆ `make quickstart`, never verified on a clean machine; ~17 containers | value in < 15 min, guided first run, a small "single-node" mode |
| **Integrations** | ★☆☆☆☆ Slack/webhook for change alerts, opt-in GitHub PRs | SSO, SIEM, ticketing, chat, cloud, EDR/MDM, API + SDKs, Terraform |
| **Operability** | ★☆☆☆☆ docker compose only, raw SQL schema files, no backups/upgrades | Helm/HA, migrations, backup/restore, metrics, upgrades without data loss |
| **Enterprise trust** | ★★☆☆☆ RBAC/ABAC + hash-chained audit (hardened this branch) | multi-tenancy, SSO/SCIM, SOC 2, pen test, signed releases, data residency |
| **Reporting** | ★☆☆☆☆ dashboard only | weekly digest, exec PDF, compliance evidence (PCI, IEC 62443, NIST CSF) |
| **Commercial plumbing** | ☆☆☆☆☆ | editions, pricing metric, licensing (CLA!), billing, support SLA, docs site |

**The short version:** the features are genuinely good. What's missing is
everything *around* the features that lets a business trust it, plug it into
what they already run, and operate it without you.

---

## 1. Signal quality: the thing that decides renewals

Security buyers churn on noise, not on missing features.

1. **Detection-quality CI gate.** A suite of seeded "ranges" (synthetic
   networks, repos and sites with known-true issues and known-safe lookalikes)
   that every engine runs against in CI, with precision/recall thresholds that
   fail the build. The scope fuzzer (77,554 → 0 disagreements per million) and
   the SAST self-scan (7 → 0 false positives) show the method works. Make it
   the rule for every detector.
2. **Finding lifecycle.**
   - Deduplicate across engines; one issue should not show up three times.
   - **Accept-risk / false-positive with expiry and a reason**, and feed that
     back into suppression.
   - SLA clocks per severity and owner (tickets exist; wire SLAs to them).
3. **Explain every priority.** "Critical because: KEV-listed · internet-facing ·
   2 hops from the payments DB · owner: payments-team". The attack-path engine
   has the data; surface it on every finding.
4. **Evidence on every finding** (the *Assessor* agent in `VISION.md`):
   non-destructive proof that the issue is real, or the finding auto-closes.

## 2. Integrations: meet customers where they already work

Ranked by how often they block a purchase:

| Priority | Integration | Why |
|---|---|---|
| P0 | **SSO (OIDC + SAML) and SCIM** | no enterprise buys without it; SCIM removes manual user admin |
| P0 | **Signed outbound webhooks** (HMAC, retries, event catalogue) | lets any customer wire Paddock into anything on day one |
| P0 | **Jira / ServiceNow / Linear** with two-way status sync | findings must become tickets in *their* system, and closing the ticket should close the finding |
| P0 | **Slack / Microsoft Teams** for findings, not just changes | where humans actually see alerts |
| P1 | **SIEM export**: Splunk HEC, Microsoft Sentinel, Elastic, syslog/CEF, in **OCSF** format | the SOC's system of record |
| P1 | **Public API contract + SDKs**: versioned `/v1` with OpenAPI, generated Python/TypeScript clients, a `paddock` CLI | partners and MSPs build on you |
| P1 | **Terraform provider**: scope, alert rules, owners as code | platform teams manage config in Git |
| P1 | **Cloud connectors** (AWS → GCP → Azure, read-only) | inside-out attack paths |
| P2 | **EDR/MDM context** (CrowdStrike, Defender, Intune, Jamf) | who owns a device, is it managed |
| P2 | **CMDB import** (ServiceNow) and owner sync from the IdP | routing findings to owners automatically |
| P2 | **Network gear** (UniFi, Meraki, Aruba, Fortinet, Palo Alto) | one-click Sentry quarantine through the approve gate |
| P2 | **GitHub/GitLab App** for PR checks (SCA + SAST + attack-path impact) and **SARIF** output | shift-left without another dashboard |
| P2 | **Standards**: CycloneDX/SPDX in+out, VEX, SARIF, STIX/TAXII (exists) | interoperability that procurement asks about |

**Design rule:** every integration is a plugin behind one interface
(`connect → test → sync → health`), shown in a single **Integrations** page
with status, last sync and errors. That page is what makes the product feel
"easy to integrate".

## 3. Time to first value and operability

1. **A clean-machine CI job** that runs `make quickstart` from scratch and
   asserts the dashboard shows findings. The README admits this has never
   been verified, and a broken first install loses the evaluator for good.
2. **Single-node mode**: one container (or three) for SMBs and evaluations,
   with the same code, fewer processes. Keep the 17-service layout for scale.
3. **First-run wizard**: add your domain → prove ownership (DNS TXT) → first
   passive results in minutes → "invite a teammate" → "connect Slack/Jira".
4. **Production operations**:
   - Helm chart with HA Postgres guidance.
   - Versioned migrations (Alembic or sqitch) instead of raw SQL files.
   - Backup/restore commands and zero-downtime upgrades.
   - Prometheus metrics, health dashboards and data-retention settings.
5. **Scale tests in CI**: 10k assets, 1M flows/day, 100 sensors. Know the
   limits before a customer finds them.

## 4. Enterprise trust

- **Multi-tenancy** with row-level security and **proof-of-control** for every
  scope entry (see `CLOUD_ROADMAP.md` §0).
- **Keyed and anchored audit chain** (HMAC + external anchoring); audit export
  to the customer's SIEM.
- **Supply-chain hygiene for Paddock itself**: signed releases (Sigstore),
  published SBOM, SLSA provenance, reproducible images. A security vendor will
  be audited on exactly what it audits.
- **SOC 2 Type II** (start the Type I now; tooling like Vanta/Drata shortens
  it), an annual third-party pen test, a security whitepaper, DPA/GDPR terms,
  and data residency (EU/US) for the hosted edition.

## 5. Reporting that a buyer can forward

- **Weekly digest email**: what changed, what's new and critical, what got
  fixed, exposure trend.
- **Executive PDF**: risk trend, top attack paths closed, MTTR by team.
- **Compliance evidence packs**: PCI DSS segmentation (Sentry), IEC 62443
  zones/conduits, NIST CSF 2.0, CIS Controls, and for device makers the
  **EU CRA** technical file (SBOM + vulnerability handling).

## 6. Commercial plumbing

- **Licensing: add a CLA (or switch to DCO + copyright assignment) now.**
  The AGPL open-core plan only works if you can also sell a commercial license,
  and you can't relicense contributions you don't own. Today CONTRIBUTING has
  neither.
- **Editions:**

  | Edition | For | Includes |
  |---|---|---|
  | Community | self-hosted, open source | everything that exists today |
  | Team | hosted | SSO, integrations, digests, 1–3 Sentry sites |
  | Enterprise | | SCIM, multi-tenant/MSP, audit export, SLA, compliance packs |
  | Edge | | air-gapped, federation, OT depth |

- **Pricing metric:** per *site* (Sentry) + per 1,000 monitored assets. Easy to
  predict, and it grows with the customer.
- **Docs site, status page, support SLA, trial**, plus usage metering hooks in
  the orchestrator.

---

## Recommended next 30 days

1. **Integrations framework + the P0 four**: signed webhooks, Slack/Teams,
   Jira/ServiceNow, OIDC SSO.
2. **Detection-quality gate** in CI for every engine (ranges + thresholds).
3. **Clean-machine install job** + single-node mode.
4. **CLA** in CONTRIBUTING + a CLA bot.
5. **Sentry pilot**: put two sensors in real environments (an office and a
   small shop) and tune thresholds on real traffic before broad launch.
