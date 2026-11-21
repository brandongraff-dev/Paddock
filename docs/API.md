# The Paddock API

Paddock is API-first: the dashboard, the workers, `paddockctl`, the SDKs and
the Terraform provider all use the same REST API served by the orchestrator.

- **Spec:** [`docs/api/openapi.json`](api/openapi.json) (OpenAPI 3.1, committed,
  regenerated from code). A running instance also serves it at `/openapi.json`
  with interactive docs at `/docs`.
- **Clients:** Python (`paddock-sdk`), TypeScript (`@paddock/sdk`), the
  `paddockctl` CLI and the Terraform provider. See [SDKs, CLI and Terraform](SDK.md).

## Authentication

Every `/v1` call needs a credential unless the server runs `AUTH_MODE=dev`.

| Credential | How to get it | How to send it |
|---|---|---|
| API key (`pak_<prefix>_<secret>`) | `POST /v1/auth/apikeys` (admin), shown once | `Authorization: Bearer pak_...` or `X-API-Key: pak_...` |
| JWT (1 h) | `POST /v1/auth/login` with username + password | `Authorization: Bearer eyJ...` |

API-key scopes (`read`, `triage`, `scan`, `ask`, `write`, `audit`, `admin`)
can only **narrow** the owning user's role. Use a dedicated, least-privilege
key per automation (a CI pipeline that reads findings needs `read` only;
Terraform managing scope needs `admin`).

## Conventions

- **JSON in, JSON out.** Timestamps are RFC 3339 in UTC.
- **Pagination** is `limit` + `offset`. Most list endpoints return a bare
  array; newer ones return a page object `{items, total, limit, offset}`. The
  SDKs' `paginate()` helpers handle both.
- **Errors** use FastAPI's shape: `{"detail": "..."}` (or a structured
  `detail` object). Status codes:

  | Code | Meaning |
  |---|---|
  | 401 | missing / invalid / expired credential |
  | 402 | the feature needs a higher edition (`detail.error = "feature_not_licensed"`, see [Editions](EDITIONS.md)) |
  | 403 | authenticated, but the role or key scope lacks the capability |
  | 404 | no such object (or, for a whole route, an older server) |
  | 409 / 422 | conflict / validation failure |
  | 429 | rate limited; honour `Retry-After` |
  | 5xx | server or upstream-service error |

- **Request IDs.** Every response carries `X-Request-ID`; quote it in bug
  reports. Mutating requests are written to the hash-chained audit log.
- **Retries.** Clients may retry `GET`/`PUT`/`DELETE` on 502/503/504 and any
  method on 429, with exponential backoff and jitter. The SDKs do this by
  default (3 retries).

## Versioning and deprecation

### The stability promise for `/v1`

Everything under `/v1` is a **stable, public contract**. Within `/v1` we only
make **additive** changes:

- new endpoints, new optional query parameters, new optional request fields;
- new fields in responses (clients must ignore unknown fields);
- new enum values in responses (clients must tolerate unknown values).

We do **not**, within `/v1`:

- remove or rename an endpoint, method, parameter or response field;
- add a *required* parameter or request field;
- change a field's type or make a guaranteed response field optional/nullable;
- narrow what a request accepts (e.g. drop an enum value).

Endpoints outside `/v1` (`/healthz`, `/readyz`, `/openapi.json`, `/docs`) are
operational and not covered.

### How this is enforced

CI's **API contract** job (`.github/workflows/ci.yml`):

1. regenerates the spec with `scripts/export_openapi.py --check` and fails if
   the committed `docs/api/openapi.json` is stale;
2. checks the generated SDKs are in sync with the spec;
3. diffs the PR's spec against the base branch with
   `scripts/openapi_diff.py` and **fails on any breaking change** listed
   above, printing a report to the job summary.

A maintainer can approve a deliberate break by adding the **`api-breaking`**
label to the PR — only for removals that completed the deprecation process
below, or for a security fix that cannot be done compatibly.

### Deprecation process

1. **Announce.** Mark the operation `deprecated=True` in its FastAPI route and
   attach `Depends(deprecated(sunset=..., successor=...))` from
   `orchestrator/app/api_lifecycle.py`. Note it in the changelog.
2. **Signal on every response.** Deprecated operations return
   - `Deprecation: @<unix-time>` (or `true`) — RFC 9745,
   - `Sunset: <HTTP-date>` — RFC 8594, **at least 6 months** after the
     deprecation date (the helper refuses a shorter window),
   - `Link: <successor>; rel="successor-version", </docs/API.md>; rel="deprecation"`.

   The SDKs surface these as a one-time warning per operation (Python
   `DeprecationWarning`, TypeScript `onDeprecation` callback).
3. **Remove** only after the Sunset date, in a release whose notes say so,
   with the `api-breaking` label on the PR.

### `/v2`

A new major version is introduced only when a change cannot be made
additively. `/v1` and `/v2` then run side by side for at least 12 months.

## Working on the API

```bash
make api-regen        # spec -> docs/api/openapi.json -> Python + TypeScript SDKs
python scripts/openapi_diff.py old.json docs/api/openapi.json   # local breaking-change check
```

Commit the regenerated spec and SDKs with the code change that caused them.
