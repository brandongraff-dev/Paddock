# Passive discovery worker — notes to the orchestrator team

CONTRACTS.md covers scope-check, `POST /v1/assets/bulk`, and
`POST /v1/findings/bulk`. This worker needs one additional endpoint and
makes a couple of small assumptions about an existing one. Please wire
or confirm these before the first end-to-end run.

## 1. Scan status mutation — needed, not specified

`CONTRACTS.md` describes `POST /v1/scans` (create) and `GET /v1/scans/{id}`
(read) but not how a worker reports progress. The worker tries PATCH first
and falls back to a POST-based endpoint.

### Preferred: `PATCH /v1/scans/{id}`

```
PATCH /v1/scans/{scan_id}
Content-Type: application/json

{
  "status": "running" | "completed" | "failed",
  "result_summary": {
    "assets_added": 12,
    "edges_added": 7,
    "findings_added": 0,
    "dropped_out_of_scope": 3,
    "duration_ms": 4120,
    "per_module_counts": {
      "ct_logs": {...},
      "dns_enum": {...}
    }
  },
  "error": "ValueError: ..."    // only on status == failed
}
```

Response: `200 OK`, body ignored by the worker.

### Fallback: `POST /v1/scans/{id}/status`

Same body shape as above. Used only if PATCH returns 404/405.

The worker never relies on a 2xx from these; it logs and keeps going if
the orchestrator rejects the update. Scan rows will still reflect queue
ingestion; this call only promotes them through the status FSM.

## 2. `POST /v1/assets/bulk` request body shape

The worker sends:

```json
{
  "assets": [
    {
      "kind": "subdomain",
      "value": "api.example.com",
      "source": "crtsh",
      "metadata": {"apex": "example.com"}
    },
    ...
  ]
}
```

`canonical` is expected to be computed server-side (CONTRACTS.md:
"POST /v1/assets/bulk ... enforces canonicalization"). The worker does
light normalization (strip wildcards, lowercase, trailing-dot removal)
as a client-side convenience; the orchestrator's canonicalizer is the
source of truth.

Response the worker reads: `{"accepted": <int>, "ids": [<uuid>...]}`.
If the response doesn't carry `accepted`, the worker falls back to
`len(request.assets)` for its summary counter.

## 3. Edges — piggybacked on `assets/bulk`

Because CONTRACTS.md doesn't define `/v1/edges/bulk`, the worker sends
edges through the same bulk endpoint with a sentinel kind:

```json
{
  "kind": "_edge",
  "value": "subdomain:api.example.com->domain:example.com:contains",
  "source": "ct_logs",
  "metadata": {
    "src_kind": "subdomain",
    "src_value": "api.example.com",
    "dst_kind": "domain",
    "dst_value": "example.com",
    "kind": "contains"
  }
}
```

Suggested orchestrator handling: detect `kind == "_edge"`, materialize
the edge into `asset_edges` by looking up (kind, canonical) for src/dst.
If a dedicated `POST /v1/edges/bulk` is added, the worker is a one-line
change to use it.

## 4. `POST /v1/findings/bulk` request body shape

```json
{
  "findings": [
    {
      "asset_value": "api.example.com",
      "asset_kind": "subdomain",
      "rule_id": "ct.cert_expiring",
      "rule_source": "policy",
      "severity": "low",
      "title": "...",
      "description": "...",
      "evidence": {...}
    }
  ]
}
```

The passive worker rarely produces findings directly (it's a discovery
layer, not a check layer); most findings come from correlation. The
scope-filter passes are keyed on `asset_value`, so that field must be
set on every finding payload.

## 5. Scope-check caveats

The worker caches `scope_check` decisions (allow AND deny) for
`SCOPE_CACHE_TTL_S` seconds, default 60. If the orchestrator revokes a
scope entry, the worker could continue pushing assets for that target
for up to 60s. For tight revocation semantics, drop the TTL or expose
a pub-sub revocation channel on `stream:events`.

If `POST /v1/scope/check` 5xx's or times out, the worker **fails
closed** — the asset is dropped, no retry. This is intentional. The
worker emits a `scope_check_error` reason the scope-service team can
grep for.
