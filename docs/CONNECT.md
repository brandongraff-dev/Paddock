# Connect anything in 60 seconds

Three ways to get data into Paddock and Paddock into your tools, all without
writing an integration:

1. **Ingest**: send any scanner's output to `POST /v1/ingest`.
2. **CI/CD**: drop-in templates for GitLab, Bitbucket, Azure DevOps, CircleCI, Jenkins, pre-commit.
3. **AI assistants**: `paddock-mcp` lets Claude, Cursor and friends read your findings.

Plus a one-line installer if you do not have a Paddock yet.

## 0. Install (optional)

```bash
curl -fsSL https://raw.githubusercontent.com/brandongraff-dev/cybersec/main/scripts/install.sh | sh
```

Checks Docker, downloads Paddock to `~/paddock`, generates strong secrets into
`.env` (`JWT_SECRET`, `PADDOCK_SECRET_KEY`, `AUDIT_HMAC_KEY`, DB and admin
passwords), starts the lite stack, waits for health and prints the URL and admin
credentials. Safe to re-run (existing secrets are never overwritten). Options:
`--dir`, `--ref`, `--active`, `--upgrade`, `--no-start`, `--dry-run`,
`--uninstall` (keeps data) and `--uninstall --purge --yes` (deletes everything).
It needs no root unless your Docker setup does. Pin a release with `--ref v1.2.3`
and `PADDOCK_SHA256` for the tarball.

## 1. Ingest

In the dashboard open **Integrations > Connect anything**, create a source, copy the
token (shown once) and a snippet. Or via the API (admin):

```bash
curl -X POST $PADDOCK/v1/ingest/sources -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"ci-trivy","default_project":"acme/web"}'
# -> {"id": "...", "token": "pdi_...", "url": "https://.../v1/ingest", ...}
```

Send a report (format is auto-detected):

```bash
curl -fsS -X POST "$PADDOCK/v1/ingest?project=acme/web" \
  -H "X-Paddock-Ingest-Token: $PADDOCK_INGEST_TOKEN" \
  --data-binary @trivy.json
```

The token may also go in `Authorization: Bearer pdi_...` or `?token=` (header preferred:
query strings end up in logs). Callers with a normal API key holding `scan` can post
without a token (`?source=name` labels the upload).

### Formats

| format | what to send |
|---|---|
| `sarif` | SARIF 2.1 (CodeQL, Semgrep, Gitleaks, Trivy, ...) |
| `cyclonedx`, `spdx` | SBOMs (JSON) become components of a project |
| `trivy` | `trivy ... --format json` (vulnerabilities, misconfigurations, secrets) |
| `grype` | `grype -o json` |
| `semgrep` | `semgrep --json` |
| `nuclei` | `nuclei -jsonl` (also a JSON array) |
| `zap` | ZAP JSON report |
| `ocsf` | OCSF 1.x finding events (NDJSON, array or `{"events": [...]}`), including Paddock's own export |
| `csv` | see below |

**CSV columns.** Required: `asset`, `title`, `severity`. Optional: `rule_id`,
`description`, `cve`, `cvss`, `cwe`, `remediation`, `references`, `asset_kind`, `file`,
`line`, `component`, `version`, `tags`. Common aliases (`host`, `name`, `risk`, `solution`,
...) are accepted. `GET /v1/ingest/formats` lists them.

### What happens to it

* Assets are created or matched (`ingest` source); findings are upserted on
  `(asset, rule_id, rule_source)` so re-uploading the same report updates instead of duplicating.
* Findings go through the normal lifecycle: the cross-engine **fingerprint** collapses the
  same CVE on the same host reported by Trivy, Nuclei and Paddock's own scanners; suppression
  rules and SLAs apply.
* Every finding records where it came from in `metadata.ingest` (`source`, `format`, `tool`).
* Components (SBOMs, Trivy/Grype packages) land in the SCA views.
* Secrets are never stored: Trivy secret matches, Nuclei curl commands and requests/responses
  and Semgrep source lines are dropped; URL credentials are stripped.
* Ingest never touches a target, so it needs no scope check; it is data you already hold.

### Options and responses

`?format=` forces a format, `?project=` / `?asset=` / `?asset_kind=` override attribution,
`?dry_run=true` parses and validates without storing, `?strict=true` rejects the whole upload
if any record is invalid. The response reports `findings_new`, `findings_updated`,
`duplicates`, `components`, `assets`, `skipped` and up to 50 `errors`. Every upload (and
rejection) is in the ingest log: `GET /v1/ingest/log` and the dashboard.

### Limits and safety

* Body up to 25 MiB (`PADDOCK_INGEST_MAX_BYTES`), 50 000 findings (`PADDOCK_INGEST_MAX_FINDINGS`);
  gzip is accepted (`Content-Encoding: gzip`) with a hard cap on the inflated size.
* **XML is refused** (no entity expansion is ever attempted); JSON nesting is bounded; NDJSON and
  CSV are processed one record at a time; paths are made relative and traversal-free.
* Tokens are **ingest-only** (they authenticate nothing else), stored as a SHA-256 hash, shown
  once, revocable (`DELETE /v1/ingest/sources/{id}`), rotatable (`.../rotate`), rate-limited per
  source (default 60/min), restrictable to formats, and every accepted upload is written to the
  hash-chained audit log. Repeated bad tokens from one address are throttled.

## 2. CI/CD

Templates live in `integrations/ci/` ([README](https://github.com/brandongraff-dev/cybersec/tree/main/integrations/ci)):
GitLab CI, Bitbucket Pipelines, Azure DevOps, CircleCI, Jenkins and pre-commit. They call one
script, `paddock-ci.sh` (`ingest`, `lockfiles`, `gate`). For GitHub Actions use
`.github/actions/paddock-scan` (see [Standards](STANDARDS.md)), or:

```yaml
- run: trivy fs --quiet --format json --output trivy.json .
- run: |
    curl -fsS -X POST "$PADDOCK_URL/v1/ingest?project=$GITHUB_REPOSITORY" \
      -H "X-Paddock-Ingest-Token: $PADDOCK_INGEST_TOKEN" --data-binary @trivy.json
  env:
    PADDOCK_URL: ${{ vars.PADDOCK_URL }}
    PADDOCK_INGEST_TOKEN: ${{ secrets.PADDOCK_INGEST_TOKEN }}
```

## 3. AI assistants (MCP)

```bash
pip install paddock-mcp   # from the repository: pip install ./mcp
```

Claude Desktop (`claude_desktop_config.json`) or Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "paddock": {
      "command": "paddock-mcp",
      "env": { "PADDOCK_URL": "https://paddock.example.com", "PADDOCK_API_KEY": "pak_..." }
    }
  }
}
```

Tools: `list_findings`, `search_findings`, `get_finding` (with evidence), `explain_priority`,
`list_assets`, `check_scope`, `get_posture_summary`, `suggest_remediation`, and, only when enabled,
`trigger_scan` and `propose_remediation`.

* **Read-only by default.** Write tools need `--allow-write` (or `PADDOCK_MCP_ALLOW_WRITE=1`)
  *and* an API key holding the capability (`scan`, `admin`). Use a `read` key for assistants.
* Everything goes through the normal API, so scope, RBAC, ABAC and audit apply. Scans of
  out-of-scope targets are refused before anything is queued.
* Streamable HTTP: `paddock-mcp --transport http --port 8765` serves `/mcp` on loopback; any
  other bind requires `PADDOCK_MCP_HTTP_TOKEN` (clients send it as a bearer token).
* Finding text is untrusted data (it comes from scanned systems); the server tells the model so
  and caps field lengths.
