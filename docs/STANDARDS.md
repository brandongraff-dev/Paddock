# Standards: OCSF, SARIF, CycloneDX, SPDX, VEX

Paddock reads and writes the formats that procurement checklists and other
tools ask for. The endpoints live in `orchestrator/app/routers/exports.py` and
the builders in `orchestrator/app/standards.py` (OCSF mapping:
`app/integrations/ocsf.py`).

| Endpoint | Format | Capability |
|---|---|---|
| `GET /v1/export/findings.ocsf` | OCSF 1.3, NDJSON | `read` |
| `GET /v1/export/sarif` | SARIF 2.1.0 | `read` |
| `GET /v1/export/sbom?project=…&format=cyclonedx\|spdx` | CycloneDX 1.5 / SPDX 2.3 JSON | `read` |
| `GET /v1/export/vex?project=…&format=cyclonedx\|openvex` | CycloneDX 1.5 VEX / OpenVEX 0.2.0 | `read` |
| `POST /v1/import/sbom` | CycloneDX or SPDX JSON in | `scan` |
| `POST /v1/import/lockfiles` | `{project, files: {path: content}}` → SCA service | `scan` |

Exports return attachments (`Content-Disposition`). Every export is written to
the hash-chained audit log, because it is a bulk data export. The findings
export is labeled `restricted` when restricted rows were in scope. ABAC
applies: findings above the caller's clearance never leave Postgres.
`project` accepts the project UUID or its name.

The examples below use:

```bash
export PADDOCK=https://paddock.example.com
export KEY=pak_xxxxxxxx_...           # an API key (see SECURITY.md)
```

## OCSF findings (NDJSON)

```bash
# everything high or worse that is still open, seen in the last 7 days
curl -sS -H "X-API-Key: $KEY" -G "$PADDOCK/v1/export/findings.ocsf" \
  --data-urlencode min_severity=high \
  --data-urlencode status=open --data-urlencode status=triaged \
  --data-urlencode since=2026-11-14T00:00:00Z \
  -o findings.ocsf.ndjson
```

The endpoint streams **one OCSF object per line**. Use this for a one-off load
into a data lake or a SIEM that doesn't have a push connector.

Parameters:

| parameter | meaning |
|---|---|
| `severity` | repeatable; exact severities to include |
| `min_severity` | include this severity and above |
| `status` | repeatable |
| `rule_source` | repeatable (`cve_match`, `sast`, `sca`, …) |
| `since` | include findings whose `last_seen` is at or after this time |
| `limit` | default 10 000, max 100 000 |

Findings that carry a CVE become **Vulnerability Finding 2002**, with NVD
CVSS/vector, EPSS and KEV joined in from the `cves` table. Everything else is
**Detection Finding 2004**. The full field table is in
[INTEGRATIONS-SIEM.md](INTEGRATIONS-SIEM.md#ocsf-mapping).

## SARIF 2.1.0

```bash
curl -sS -H "X-API-Key: $KEY" -G "$PADDOCK/v1/export/sarif" \
  --data-urlencode project=acme/web -o paddock.sarif
```

| parameter | default | meaning |
|---|---|---|
| `project` | all projects | id or name |
| `include_sca` | `true` | include dependency vulnerabilities, placed on their lockfile |
| `include_suppressed` | `false` | include accepted-risk, false-positive and won't-fix results with a SARIF `suppressions[]` entry |
| `min_severity` | — | drop results below this severity |
| `strip_prefix` | — | path prefix to strip so URIs are relative to the repository (for example `/src/repo`) |
| `limit` | 5000 (max 25 000, GitHub's per-run cap) | |

What goes into the log:

* **Code findings.** Rows from `code_findings` (written by the codeanalysis
  service), joined to their unified `findings` mirror for status and ABAC. Also
  any `rule_source='sast'` finding that has no `code_findings` row, located
  from `evidence.file` and `evidence.start_line`. Each result carries
  `ruleId`, `level`, `locations[].physicalLocation` (`artifactLocation.uri`
  relative to `%SRCROOT%`, plus `region.startLine`/`endLine`), CWE `taxa`
  (with a `CWE` taxonomy and rule `relationships`), and `codeFlows` built from
  the source-to-sink dataflow. Fixed findings are left out.
* **Dependency vulnerabilities** (`include_sca`). One result per
  (advisory, component). The rule id is the OSV/GHSA id and `helpUri` points
  to osv.dev. The location is the project's recorded lockfile for that
  ecosystem (from `POST /v1/import/lockfiles`). If none is recorded, the
  conventional lockfile name is used. A result graded *unreachable* by
  reachability analysis is downgraded to `level: note`, and every result
  carries `properties.reachability`.
* **Severity.** Critical and high become `error`, medium becomes `warning`,
  low and info become `note`. Each rule also carries
  `properties["security-severity"]`, which GitHub uses for its
  critical/high/medium/low label. It is the CVSS score when known, else 9.5,
  8.0, 5.5, 3.0 or 0.0 by severity.
* `partialFingerprints["paddock/v1"]` keeps alerts stable across uploads, and
  `automationDetails.id = paddock/<project>/`.

### GitHub code scanning (Action)

`.github/actions/paddock-scan` is a composite action. It does four things:

1. It finds the repo's lockfiles: `package-lock.json`, `yarn.lock`,
   `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`,
   `Cargo.lock`, `pom.xml`, `Gemfile.lock`, `go.sum`/`go.mod`. It skips
   `node_modules`, `vendor`, `.venv`, `dist`, `build` and `target`.
2. It uploads them to `POST /v1/import/lockfiles`.
3. It fetches `GET /v1/export/sarif` for the project.
4. Optionally, it uploads the SARIF with `github/codeql-action/upload-sarif`
   and fails the job above a severity threshold.

```yaml
# .github/workflows/paddock.yml
name: Paddock
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write      # required by upload-sarif
jobs:
  paddock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: brandongraff-dev/cybersec/.github/actions/paddock-scan@main   # pin a SHA in production
        with:
          paddock-url: https://paddock.example.com
          api-key: ${{ secrets.PADDOCK_API_KEY }}
          fail-on: critical          # optional: low|medium|high|critical
          # project: my-org/my-repo  # default: ${{ github.repository }}
          # include-sca: "true"
          # upload-sarif: "true"     # set "false" and upload yourself, see below
```

To upload the SARIF yourself, for example to merge it with other tools:

```yaml
      - id: paddock
        uses: brandongraff-dev/cybersec/.github/actions/paddock-scan@main
        with:
          paddock-url: https://paddock.example.com
          api-key: ${{ secrets.PADDOCK_API_KEY }}
          upload-sarif: "false"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.paddock.outputs.sarif-file }}
          category: paddock
```

Notes:

* The API key needs the `scan` capability (for the upload) and `read` (for the
  SARIF). An analyst's key works, and so does an admin key minted with scopes
  `["scan","read"]`. Store it as a repository or organization secret.
  Workflows triggered by pull requests from forks don't receive secrets, so
  run the action on `push` or on `pull_request` from branches in the same
  repository.
* The action only talks to `https://` URLs. For a Paddock behind a private CA,
  pass `ca-bundle: path/to/ca.pem`.
* Lockfile contents are sent to **your** Paddock instance and nowhere else.
  Paddock stores only each file's path, size and SHA-256 in
  `sca_project_manifests`, not its contents.
* Outputs are `sarif-file`, `results` and `components`.
* SAST results appear in the SARIF when the codeanalysis service has scanned the
  same project. The action itself only uploads lockfiles.

## SBOM export: CycloneDX 1.5 and SPDX 2.3

```bash
curl -sS -H "X-API-Key: $KEY" -G "$PADDOCK/v1/export/sbom" \
  --data-urlencode project=acme/web --data-urlencode format=cyclonedx -o acme-web.cdx.json
curl -sS -H "X-API-Key: $KEY" -G "$PADDOCK/v1/export/sbom" \
  --data-urlencode project=acme/web --data-urlencode format=spdx -o acme-web.spdx.json
```

* **CycloneDX 1.5.** `metadata.component` is the project as an `application`.
  The `components[]` are `library` entries with a `purl`, and Maven
  coordinates are split into `group`/`name`. Each component carries the
  properties `paddock:ecosystem`, `paddock:direct` and `paddock:depth`. The
  `dependencies[]` graph has the root depending on the direct dependencies,
  plus parent→child edges from the SCA dependency paths.
* **SPDX 2.3.** `SPDXRef-DOCUMENT DESCRIBES` the project package. Each component
  is a package with a `PACKAGE-MANAGER purl` external reference,
  `downloadLocation`/license fields set to `NOASSERTION` (Paddock does not
  resolve licenses), and `DEPENDS_ON` relationships that mirror the
  CycloneDX graph.

## VEX: CycloneDX and OpenVEX

```bash
curl -sS -H "X-API-Key: $KEY" -G "$PADDOCK/v1/export/vex" \
  --data-urlencode project=acme/web -o acme-web.vex.cdx.json
curl -sS -H "X-API-Key: $KEY" -G "$PADDOCK/v1/export/vex" \
  --data-urlencode project=acme/web --data-urlencode format=openvex -o acme-web.openvex.json
```

There is one statement per vulnerability match (`sbom_component_vulns`). The
status comes from the **reachability grade** computed by the codeanalysis
service:

| reachability | CycloneDX `analysis` | OpenVEX |
|---|---|---|
| `reachable` | `state: exploitable`, `response: [update]` (or `workaround_available`) | `affected` + `action_statement` (upgrade to the fixed version) |
| `unreachable` | `state: not_affected`, `justification: code_not_reachable`, version status `unaffected` | `not_affected`, `justification: vulnerable_code_not_in_execute_path` + `impact_statement` |
| `potential` / `unknown` | `state: in_triage` | `under_investigation` |

Every statement explains the call-path evidence in `detail` or
`status_notes`. The CycloneDX VEX document is self-contained: it includes the
affected components, so each `affects[].ref` resolves inside the same file.
The vulnerability `id` is the CVE when known, and the OSV/GHSA id goes in
`references` or `aliases`.

## Importing an SBOM

```bash
# CycloneDX (e.g. from syft/cdxgen); the project name defaults to metadata.component.name
curl -sS -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  --data-binary @bom.cdx.json "$PADDOCK/v1/import/sbom"

# SPDX, with an explicit project, replacing components no longer present
curl -sS -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  --data-binary @sbom.spdx.json "$PADDOCK/v1/import/sbom?project=acme/api&replace=true"
```

Response: `{project, project_id, format, components, ecosystems,
vulnerabilities, removed, sha256}` (HTTP 201).

* The format is detected from `bomFormat: "CycloneDX"` or
  `spdxVersion: "SPDX-2.x"`.
* Each component's ecosystem and name come from its `purl`. A purl type maps
  to the matching OSV ecosystem (`npm`, `PyPI`, `Go`, `crates.io`, `Maven`,
  `RubyGems`, `NuGet`, …). A component without a purl gets the `generic`
  ecosystem.
* Direct/transitive status and depth come from the CycloneDX `dependencies` or
  the SPDX `DEPENDS_ON`/`DEPENDENCY_OF` graph from the described root. With no
  graph, every component counts as direct.
* CycloneDX `vulnerabilities[]` whose `affects` resolve to an imported
  component are stored as matches. Severity comes from the worst rating.
  `analysis.state = not_affected` with `code_not_reachable` is stored as
  reachability `unreachable`, so VEX round-trips.
* Limits:
  * body size: `PADDOCK_SBOM_IMPORT_MAX_BYTES` (default 10 MiB) → 413;
  * at most 50 000 components → 422;
  * nested CycloneDX `components` are walked at most 32 levels deep;
  * deeply nested or invalid JSON → 400/422.

  Name, version and purl strings are truncated to their column budgets.
* Writes run in one transaction and upsert on the natural key (project,
  ecosystem, name, version), exactly like the SCA service.

## Uploading lockfiles

```bash
jq -n --rawfile lock package-lock.json \
  '{project: "acme/web", files: {"package-lock.json": $lock}}' |
curl -sS -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  --data-binary @- "$PADDOCK/v1/import/lockfiles"
```

The orchestrator forwards the files to the SCA service's `/scan`. The SCA
service parses them, builds the SBOM, runs OSV matching and the supply-chain
risk detectors, then writes its results. The orchestrator records each file's
path, ecosystem and SHA-256 in `sca_project_manifests`, which the SARIF export
uses to place results.

* Limits: 200 files and `PADDOCK_LOCKFILE_IMPORT_MAX_BYTES` (default 25 MiB)
  per request.
* Files with unsupported names, or paths containing `..`, are ignored and
  listed in `ignored`.
* The SCA service URL is `SCA_URL` (default `http://sca:8094`). If the service
  is unreachable you get 503; if the scan fails you get 502.

## Environment variables

| variable | default | used by |
|---|---|---|
| `SCA_URL` | `http://sca:8094` | `POST /v1/import/lockfiles` |
| `PADDOCK_SBOM_IMPORT_MAX_BYTES` | 10485760 | `POST /v1/import/sbom` |
| `PADDOCK_LOCKFILE_IMPORT_MAX_BYTES` | 26214400 | `POST /v1/import/lockfiles` |

## Validation status

The test suite (`orchestrator/tests/test_standards.py`,
`test_exports_api.py`, `standards_shapes.py`) checks every document
structurally. It covers the required fields, enums and internal references:

* SARIF: rule/ruleIndex consistency, levels, regions and CWE taxa;
* CycloneDX: bom-ref uniqueness and that every dependency and `affects` ref
  resolves, plus the VEX analysis enums;
* SPDX: SPDXID syntax and uniqueness, and that every relationship resolves;
* OpenVEX: statuses and justifications.

The official JSON schemas are **not vendored** yet. If you drop
`sarif-schema-2.1.0.json`, `bom-1.5.schema.json` (with `spdx.schema.json` and
`jsf-0.82.schema.json`), `spdx-schema.json` or `openvex_json_schema.json`
into `orchestrator/tests/fixtures/schemas/` and install `jsonschema`, the same
tests also run full schema validation.
