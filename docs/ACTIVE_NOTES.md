# workers/active — integration notes

These are the orchestrator-side additions the active worker expects that are
not yet in `docs/CONTRACTS.md`. Treat this file as the proposal for those
additions; please update `CONTRACTS.md` when they land.

## Outbound audit (bulk)

Every outbound request from `workers/active` writes an audit row. The
worker emits them one-at-a-time at first, batched with:

- `POST /v1/outbound/bulk`
  - body: `{"entries": [<row>, ...]}`
  - row fields (all optional except `tool`, `target`, `scope_matched`,
    `started_at`):

    ```json
    {
      "worker": "active-1",
      "target": "https://example.com/.git/HEAD",
      "tool": "http_probe | naabu | nuclei | tlsx | katana | exposed_file | playwright | crawler",
      "method": "GET | HEAD | OPTIONS | tls_handshake | screenshot | ...",
      "request_summary": "optional string",
      "response_code": 200,
      "scope_matched": true,
      "scope_entry_id": 42,
      "started_at": 1731000000.1,
      "duration_ms": 123,
      "bytes_in": 1024,
      "bytes_out": 0,
      "error": null
    }
    ```

  Maps 1:1 to `outbound_log` rows in `schema/004_audit.sql`. A 2xx response
  is sufficient; the worker does not inspect the body.

## Child scan creation

`full_recon` orchestrates sub-steps under the parent. For each sub-step the
worker calls:

- `POST /v1/scans`
  - body: `{"kind": "...", "target": "...", "config": {...}, "parent_scan_id": "<uuid>"}`
  - response: `{"scan_id": "<uuid>"}`

`parent_scan_id` is already present in `schema/004_audit.sql` on the `scans`
table, so no schema change is required — only the request accepting it.

## Scan status endpoints

The worker POSTs lifecycle transitions as the dispatcher moves a job:

- `POST /v1/scans/{id}/start`     — body: `{"worker_id": "..."}` → status=running
- `POST /v1/scans/{id}/complete`  — body: `{"result_summary": {...}}` → status=completed
- `POST /v1/scans/{id}/fail`      — body: `{"error": "..."}` → status=failed

These are implied by the schema but not spelled out in `CONTRACTS.md`.

## Scope-check response shape

The worker's `scope_guard` consumes:

```json
{
  "allow": true,
  "normalized": "example.com",
  "matched_entry": 17,
  "reason": "ok"
}
```

`reason` is passed into `scope_decisions.reason`. This matches the request
shape already in `CONTRACTS.md`; this note just pins the response fields.

## Per-scope politeness overrides

If a scope entry's `metadata` (JSONB on `scope_entries` — proposed) carries
a `politeness` block:

```json
{"politeness": {"concurrency": 1, "delay_ms": 500}}
```

the worker calls `PolitenessLimiter.configure_host(host, concurrency=1, delay_ms=500)`
after the scope check returns. If this is not implemented server-side the
worker falls back to its defaults, so the field is optional.

## Event stream

Each completed job adds one row to `stream:events`:

```json
{"event": "scan_completed", "ts": "...", "scan_id": "...", "kind": "...", "target": "..."}
```

matching the shape in CONTRACTS.md.
