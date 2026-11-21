# SDKs, CLI and Terraform

All clients are generated from (or tested against) the committed OpenAPI spec,
[`docs/api/openapi.json`](api/openapi.json). Regenerate everything with one
command after changing the API:

```bash
make api-regen
```

## Python: `paddock-sdk`

```bash
pip install ./sdk/python          # from a checkout (PyPI publishing is not set up yet)
```

```python
from paddock_sdk import PaddockClient, FeatureNotLicensed

with PaddockClient("https://paddock.internal", api_key="pak_...") as pc:
    # every API operation is a typed method; models are TypedDicts
    entry = pc.add_scope({"kind": "domain", "value": "example.com",
                          "added_by": "ci", "auth_doc_ref": "SOW-2026-14"})

    # pagination works for both bare-list and {items,total} responses
    for f in pc.paginate(pc.list_findings_paged, severity="critical", status="open"):
        print(f["title"], f["asset_value"])

    pc.patch_finding(f["id"], {"status": "accepted_risk", "notes": "WAF rule 4411"})
```

- **Auth:** `api_key=` or `token=` (JWT); or `PADDOCK_URL` / `PADDOCK_API_KEY`
  / `PADDOCK_TOKEN` env vars; or `pc.login_with_password(user, pw)`.
- **Retries:** `RetryPolicy(max_retries=3, backoff_factor=0.5)` by default;
  pass `retry=NO_RETRY` to disable.
- **Errors:** `AuthenticationError` (401), `FeatureNotLicensed` (402),
  `PermissionDenied` (403), `NotFound` (404), `ValidationError` (422),
  `RateLimited` (429), `ServerError` (5xx), `TransportError` (network). All
  carry `.status`, `.detail`, `.request_id`.
- **Newer endpoints** (`export_format("sarif"|"sbom"|"ocsf")`,
  `integrations_list()`, `scope_verify(id)`) raise `NotFound` with a clear
  "this server does not provide ..." message on older servers.

Generated code: `sdk/python/paddock_sdk/_generated.py` (by
`sdk/python/codegen.py`, an in-repo, dependency-free generator). Tests run
against a mocked `httpx` transport: `cd sdk/python && pip install -e ".[test]" && pytest`.

## TypeScript: `@paddock/sdk`

Fetch-based (Node 18+, browsers, Deno, Bun), ESM, fully typed.

```ts
import { PaddockClient, FeatureNotLicensed } from "@paddock/sdk";

const pc = new PaddockClient({ baseUrl: "https://paddock.internal", apiKey: process.env.PADDOCK_API_KEY });

for await (const f of pc.paginate((q) => pc.listFindingsPaged({ ...q, severity: "critical" }))) {
  console.log(f.title);
}
await pc.patchFinding(id, { status: "accepted_risk", notes: "WAF rule 4411" });
```

Same retry/error model as Python (the 422 error class is `UnprocessableEntity`
because the spec already defines a `ValidationError` model).
`cd sdk/typescript && npm ci && npm run typecheck && npm test && npm run build`.

## `paddockctl` (CLI)

Installed with the Python SDK. (The host agent's CLI is `paddock`; this one
talks to the API.)

```bash
paddockctl login --url https://paddock.internal --api-key pak_... --profile prod
paddockctl login --url http://localhost:8080 --username admin --profile lab   # JWT, 1 h
paddockctl config profiles | config use lab | whoami

paddockctl scope list [--all]
paddockctl scope add domain example.com --auth-doc-ref "SOW-2026-14"
paddockctl scope check app.example.com          # exit 1 when out of scope
paddockctl scope verify 12                      # proof-of-control (newer servers)

paddockctl scan run full_recon example.com --wait
paddockctl scan status <id> | scan list --status running

paddockctl findings list --severity critical --status open [--all] -o json
paddockctl findings accept <id> --reason "compensating control" [--false-positive]

paddockctl export sarif --out paddock.sarif     # also: sbom, ocsf
paddockctl integrations list
paddockctl license show | license upload paddock.lic | usage
```

Profiles live in `~/.config/paddock/paddockctl.json` (mode 0600; override with
`PADDOCK_CONFIG`). `PADDOCK_URL`, `PADDOCK_API_KEY`, `PADDOCK_TOKEN` and
`PADDOCK_PROFILE` override the file. Every command takes `-o table|json`.
Exit codes: `0` ok, `1` API/transport error, `2` usage error, `3` the server
does not provide that endpoint yet.

## Terraform provider

`terraform-provider-paddock/` (Go, `terraform-plugin-framework`).

```hcl
provider "paddock" {
  url = "https://paddock.internal"   # or PADDOCK_URL
  # api_key via PADDOCK_API_KEY (admin scope)
}

resource "paddock_scope_entry" "corp" {
  kind         = "domain"
  value        = "example.com"
  auth_doc_ref = "SOW-2026-14"
}

resource "paddock_alert_rule" "new_hosts" {
  name         = "new internet-facing hosts"
  channel      = "slack"
  target       = var.slack_webhook_url      # sensitive
  change_types = ["subdomain_discovered", "port_opened"]
  min_severity = "medium"
}

resource "paddock_owner_rule" "payments" {
  name              = "payments"
  team              = "payments-team"
  contact           = "#payments-sec"
  priority          = 10
  match_kinds       = ["subdomain"]
  match_value_regex = "^pay\\."
}

resource "paddock_integration" "slack" {
  kind         = "slack"
  name         = "sec-alerts"
  config_json  = jsonencode({ channel = "#sec-alerts" })
  secrets      = { bot_token = var.slack_bot_token }   # write-only, sensitive
  events       = ["finding.opened", "attack_path.opened"]
  min_severity = "high"
}

data "paddock_findings" "open_criticals" {
  severity = "critical"
  status   = "open"
  limit    = 0
}

check "no_open_criticals" {
  assert {
    condition     = data.paddock_findings.open_criticals.total == 0
    error_message = "open critical findings: ${data.paddock_findings.open_criticals.total}"
  }
}
```

Notes:

- **Scope entries are immutable** in the API (one reviewable row per change),
  so any attribute change replaces the entry; destroy *deactivates* it and the
  audit trail is kept. An entry deactivated outside Terraform is re-created.
- **Integration secrets are write-only.** The API never returns them;
  Terraform keeps what you configured and cannot detect out-of-band changes.
  `paddock_integration` targets the `/v1/integrations` CRUD shape
  `{kind, name, enabled, config, secrets, events, min_severity, filters, allow_private}`.
- All resources support `terraform import <addr> <id>`.

Build and test: `cd terraform-provider-paddock && go build ./... && go test ./...`
(tests drive every resource through the framework against an in-memory mock of
the API; no Terraform binary needed). Publishing to the Terraform Registry
(GPG-signed release via GoReleaser) is not set up yet.
