# Reports

Reports turn Paddock's data into something a buyer can forward: a weekly
digest, an executive summary (HTML / PDF), and compliance evidence packs.
Everything is computed from live data and filtered by the caller's clearance
(ABAC), so over-classified findings and assets never appear in a report the
reader isn't cleared for.

Code: `orchestrator/app/reports/` · Dashboard: **Operate → Reports** · Schema: `schema/023_reports.sql`

## API

All endpoints require the `read` capability unless noted.

| Endpoint | Returns |
|---|---|
| `GET /v1/reports/executive?period=30d&format=json\|html\|pdf[&end=ISO][&download=1]` | Executive report for the window (`Nd`, 1–366 days) ending now or at `end` |
| `GET /v1/reports/compliance` | One summary card per framework (satisfied / partial / gap / attestation counts) |
| `GET /v1/reports/compliance/{framework}?format=json\|html\|pdf` | Full evidence pack for one framework |
| `GET /v1/reports/digest/preview?period=7d&format=json\|text\|html` | The digest that *would* be sent now, without sending |
| `GET /v1/reports/digests` | History of sent digests |
| `POST /v1/reports/digest/send` | Send the digest now (**admin**) |

```bash
curl -H "X-API-Key: $KEY" "https://paddock.example/v1/reports/executive?period=30d&format=pdf" -o exec.pdf
```

PDF rendering uses **WeasyPrint** (Pango/HarfBuzz are installed in the
orchestrator image). On a host without Pango the PDF format answers `501`
with a hint; HTML and JSON always work. Fonts are embedded (OFL), so output
is identical on every machine.

## Metric definitions

All finding metrics are computed from one pass over `findings` per request.

| Metric | Definition |
|---|---|
| **closed_at** | When a finding left `open`/`triaged`: `finding_resolutions` (trigger-maintained, schema 023), else the ticket's `closed_at`, else the finding's `last_seen` (best effort for rows closed before 023) |
| **open at T** | `first_seen < T AND (closed_at IS NULL OR closed_at >= T)`, time-aware so historical reports aren't skewed by later events |
| **Exposure index** | Σ over open findings of the severity weight (critical 10, high 5, medium 2, low 1, info 0), the same formula as the Overview page. The trend is one point per day of the window |
| **Verified fix** | The asset was re-observed more than 60 s after the fix and the finding was not |
| **Regressed** | A fixed finding was re-observed after its fix |
| **SLA due** | The ticket's `sla_due`, else `first_seen + sla_policies.hours` for the severity |
| **SLA compliance** | met / (met + late + breached_open). *met*/*late* = fixed in the window before/after due. *breached_open* = still open at window end with its due time inside the window. `REPORTS_SLA_PASS_PCT` (default 90) is the pass line |
| **MTTR** | `closed_at − first_seen` over findings **fixed** in the window, by severity and by owner/team |
| **Attack paths** | Opened/closed in the window, from the attack-path ledger (schema 023 trigger) |

Exposure uses each finding's **current** severity: severity history is not
recorded.

## Weekly digest

The digest is delivered by the [integrations framework](INTEGRATIONS.md), not
by the reports module. Each scheduler tick calls `run_due_digests`. A slot is
the most recent `REPORTS_DIGEST_WEEKDAY` at `REPORTS_DIGEST_HOUR` (UTC). A
unique index on `report_digests` makes the claim atomic, so multiple
orchestrator replicas never send twice. Slots older than 36 h are skipped, so
a long outage doesn't produce a stale digest.

One `report.digest` event is emitted per workspace. Subscribe any NOTIFY
integration (Slack, Teams, email, webhook) to it. `data` carries ready-made
renderings, so connectors need no report logic:

```json
{
  "workspace": "default",
  "period": {"start": "…", "end": "…", "days": 7, "label": "14 – 21 Nov 2026"},
  "highlights": ["3 new critical findings", "…"],
  "metrics": {"exposure_index": 168, "new_critical": 3, "fixed": 11, "sla_compliance_pct": 92.0},
  "text": "plain-text body",
  "html": "email-safe HTML (inline styles, no SVG/JS)",
  "report_url": "https://paddock.example/reports"
}
```

Digests leave Paddock, so they are built at `REPORTS_DIGEST_CLEARANCE`
(default `internal`): confidential and restricted rows never reach a channel.

## Compliance evidence packs

Catalogues live in `orchestrator/app/reports/controls/` as data. Each control
lists the Paddock *evidence keys* that bear on it:

| Framework | File |
|---|---|
| PCI DSS v4.0 (incl. 1.x segmentation, 6.3, 11.3, 11.4.5) | `pci-dss-4.0.json` |
| NIST CSF 2.0 | `nist-csf-2.0.json` |
| CIS Controls v8 | `cis-v8.json` |
| ISO/IEC 27001:2022 Annex A (relevant subset) | `iso-27001-2022.json` |
| IEC 62443-3-3 (zones/conduits, inventory, segmentation SRs) | `iec-62443-3-3.json` |
| EU Cyber Resilience Act, Annex I (+ Art. 14 reporting) | `eu-cra.json` |

Each evidence key is computed once per request (SQL over live data,
ABAC-filtered), then folded into a per-control status:

| Status | Meaning |
|---|---|
| `satisfied` | Every evidence item passes. Capped at `partial` where the catalogue says Paddock can only ever partially evidence the control (`max_status: "partial"`), e.g. PCI 11.3.2 (Paddock is not an ASV) or 11.4.5 (Sentry's segmentation map supports, but doesn't replace, a segmentation pentest) |
| `partial` | Some evidence passes, or it's incomplete / stale (older than `REPORTS_EVIDENCE_FRESH_DAYS`) |
| `gap` | No supporting evidence in Paddock, or the evidence shows a failure (e.g. open segmentation violations). This is a gap *in evidence*, not an auditor's finding of non-compliance |
| `requires_attestation` | Manual control (policy, process, people). Paddock never claims these |

An empty install claims nothing; a test enforces this.

Evidence keys draw on: the asset inventory and scan freshness, findings by
class (exposure, TLS, CVE/KEV, SAST/SCA), SBOM coverage, ticket SLAs, the
hash-chained audit log, Sentry's observed segmentation map and behaviour
detectors, and threat-intel feed health (STIX/TAXII feeds + CISA KEV).

### Adding a control or framework

1. Add the control to the framework JSON with its `evidence` keys (and
   `max_status` if Paddock can only partially evidence it).
2. If you need a new evidence key, implement it in `compliance.py` (one SQL
   query, ABAC-filtered) and add a test that seeds data and asserts the status.
3. Keep claims conservative: when in doubt, `partial` or `requires_attestation`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `REPORTS_ORG_NAME` | `Your organization` | Name on report covers |
| `REPORTS_PUBLIC_URL` | — | Dashboard URL for links in digests |
| `REPORTS_PAGE_SIZE` | `A4` | `A4` or `Letter` |
| `REPORTS_DIGEST_ENABLED` | `true` | Weekly digest on/off |
| `REPORTS_DIGEST_WEEKDAY` | `0` | 0 = Monday … 6 = Sunday (UTC) |
| `REPORTS_DIGEST_HOUR` | `8` | Hour of day, UTC |
| `REPORTS_DIGEST_PERIOD_DAYS` | `7` | Digest window |
| `REPORTS_DIGEST_CLEARANCE` | `internal` | Highest classification allowed into a digest |
| `REPORTS_SLA_PASS_PCT` | `90` | SLA compliance pass line |
| `REPORTS_EVIDENCE_FRESH_DAYS` | `30` | Evidence older than this counts as stale |

## Schema 023

- `finding_resolutions`: trigger-maintained close/reopen times, for exact MTTR.
- Attack-path ledger: trigger-maintained opened/closed times for paths.
- `report_digests`: one row per (workspace, slot); its unique index is the send lock.
- Supporting indexes for the report queries.
