# Intel service notes

The intel service ingests public vulnerability feeds and matches CVEs to
assets. Code at `/intel`. It owns writes to `cves`, `cve_matches`, and
`intel_cursors`. It never writes to `findings` or `assets` directly —
those go through the orchestrator HTTP API.

## Matcher confidence table

The CPE matcher (`app/matchers/cpe.py`) returns a confidence score for
each CVE / asset candidate pair. Higher is a tighter match.

| Confidence | Condition |
|---|---|
| **100** | Exact CPE 2.3 string match (part, vendor, product, version all equal — version is a concrete value, not `*` or `-`). Alternatively: vendor+product match AND the CVE declares an exact version equal to the asset version. |
| **85**  | Vendor and product match AND the asset version falls inside the CVE's declared version range (`versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`). Also used when the CVE's `version` is a wildcard but vendor+product+asset-version all align. |
| **60**  | Vendor and product match but the asset carries no version info to narrow with. |
| **40**  | Product-name heuristic only — asset lacks a vendor, so we can't rule out false positives from name collisions (e.g. two different projects named "scanner"). |
| **0**   | No match (product mismatch, vendor mismatch when asset vendor is known, explicitly non-vulnerable CPE entry, version out of range, or version strings incomparable). |

`FINDING_MIN_CONFIDENCE` (default **60**) is the threshold below which no
finding is created — low-tier matches still land in `cve_matches` for
later tuning but do not alert.

### Severity derivation

Severity is attached to findings in `app/enrich/finding_writer.py`:

- `critical` — CVE is in CISA KEV, OR `cvss_v3 >= 9.0`
- `high`     — `cvss_v3 >= 7.0`
- `medium`   — `cvss_v3 >= 4.0`
- `low`      — `cvss_v3 < 4.0`, or score unknown and not KEV

## Orchestrator endpoints we consume

| Verb | Path | Used for |
|---|---|---|
| `GET`  | `/v1/assets?kind=technology&limit=&offset=` | Full page walk of technology assets. Expected to return `{"items":[…]}` or a bare list; the client tolerates both. |
| `GET`  | `/v1/assets/{id}` | Fetch one asset after an `asset_added` stream event. |
| `POST` | `/v1/findings/bulk` | Upsert `cve_match` findings; body `{"items":[{…}]}`. Each item carries `asset_id`, `rule_id` (CVE id), `rule_source="cve_match"`, `severity`, `title`, `description`, `impact`, `remediation`, `evidence`, `cvss`, `epss`, `references`, `metadata`. |

If the orchestrator later gains a vendor/product filter on
`GET /v1/assets`, `linker.reverse_match_cve` can be tightened to avoid
the full-tech-asset scan it currently performs.

## Redis events

- Subscribes to `stream:events` (`XREAD ... block=5000`).
- Triggers on `event=asset_added` with `kind=technology`.
- On a hit, fetches the asset via the orchestrator and runs
  `linker.match_one_asset` immediately.

## Ethics guardrails (hard-coded)

- Exploit URLs in a CVE's `references` list are **stored** (data) but
  **never fetched**. `tests/test_no_exploit_fetch.py` asserts this at
  the code-boundary level: outbound hosts are restricted to the four
  authoritative feeds.
- `remediation` text is generic (upgrade, mitigate, segment) — no
  payloads, no PoCs, no exploitation steps.
- All outbound traffic goes to one of:
  `services.nvd.nist.gov`, `epss.cyentia.com`, `www.cisa.gov`,
  `api.osv.dev`.

## Operational HTTP (port 8090)

- `GET /healthz` — liveness, always 200 when the process is up.
- `GET /readyz` — 200 only once the DB pool answers `SELECT 1`.
- `POST /sync/{nvd|epss|kev|linker}` — manual trigger; returns the
  stats dict that would have been written to `intel_cursors`.
- `GET /stats` — in-process counters plus `cves` / `cve_matches` /
  `KEV` counts and all stored cursors.
