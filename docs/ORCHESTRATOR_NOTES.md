# Orchestrator notes for sibling services

This is the implementation notebook the orchestrator keeps for other
services building against it. If something below conflicts with
`CONTRACTS.md`, treat `CONTRACTS.md` as authoritative and open a PR
against this file.

## How a worker talks to this service

1. **Every** outbound request starts with `POST /v1/scope/check` and is
   abandoned if `allow` is false. This endpoint always writes a
   `scope_decisions` row, allow or deny. The cache is 60s; a scope
   mutation through this API invalidates it.
2. On allow, the worker does its work, then POSTs findings via
   `/v1/findings/bulk` and new assets via `/v1/assets/bulk`. Both
   endpoints are idempotent and safe to retry.
3. Finished work is reported by `PATCH /v1/scans/{id}` ... wait — that
   endpoint is intentionally *not* wired yet. Scan state is advanced by
   the worker writing directly to the `scans` row today; a future
   version will accept a callback.

## Queueing contract

Jobs are published on Redis Streams, not Redis Lists, so workers should
use `XREADGROUP`:

| Scan kind prefix / alias       | Stream             |
| ------------------------------ | ------------------ |
| `passive_*` / `shodan` / `ct_logs` / `github_search` / `wayback` / `dns` | `queue:passive`    |
| `active_*` / `nuclei*` / `httpx` / `naabu` / `katana` / `tlsx` / `playwright` | `queue:active`     |
| `correlate_*`                  | `queue:correlate`  |

Job payload shape (in a single `job` field of the stream entry, JSON-encoded):

```json
{
  "scan_id": "<uuid>",
  "kind": "passive_subdomains",
  "target": "normalized.host.name",
  "config": { ... },
  "scope_matched_entry": 42
}
```

`target` is **already normalized** by the orchestrator before enqueue
(scheme / port / path stripped, case-folded, trailing dot gone). Workers
should still re-check scope before every outbound request.

## Event stream

`stream:events` (Redis Stream) carries fan-out events:

- `asset_added` — one per *new* insert from `/v1/assets/bulk`. Updates
  do not re-emit.
- `finding_opened` — one per *new* insert from `/v1/findings/bulk`.
- `finding_closed` — emitted on `PATCH /v1/findings/{id}` when status
  transitions to any terminal state (`fixed`, `wontfix`,
  `false_positive`, `accepted_risk`).

SSE mirror of the stream is at `GET /v1/events?since=<stream-id-or-$>`.

## Normalization rules you can rely on

- URL -> host (scheme, userinfo, port, path and query stripped)
- `[ipv6]:port` -> canonical IPv6 string
- bare IPv4/IPv6 passed through canonically
- trailing dots trimmed, case-folded

If normalization yields empty, the scope check is **deny-fail-closed**
and audit-logged.

## Subdomain-wildcard semantics (clarified)

The spec said `subdomain_wildcard` should match the base AND any depth.
We store the base domain (e.g. `example.com`) in `scope_entries.value`;
an entry with a `*.` prefix is accepted and the prefix is stripped at
match time. Matches:

- `example.com` -> MATCH
- `api.example.com` -> MATCH
- `a.b.c.example.com` -> MATCH
- `notexample.com` -> NO
- `example.com.evil.com` -> NO

## ASN matching

Not implemented in the MVP. ASN scope entries are stored and listed but
return deny at check-time (logged at DEBUG). When ASN resolution lands
(team/iptoasn), `_match_ip_rules` is the only call site that needs to
grow.

## Hostname-to-IP resolution on scope check

If the target is a hostname and no `domain`/`subdomain_wildcard` entry
matches, we resolve via `socket.getaddrinfo` (60s TTL cache,
fail-closed on error) and try `ipv*_cidr` entries against each resolved
address. Numeric IP targets skip resolution and only try CIDR entries.

## Insert-vs-update detection

Bulk upserts use `RETURNING ..., (xmax = 0) AS was_inserted` to tell
the two apart. This is a Postgres-specific quirk that works across
MVCC, including transaction-local inserts. Workers do not need to care.

## Contract defect worked around

`schema/003_findings.sql` declares `references TEXT[]` without quoting.
`references` is a reserved keyword in Postgres 16 and the schema file
does not load as-is. Our test harness (`tests/conftest.py`) patches the
schema in memory at load time to quote the column. The orchestrator's
own SQL already uses the quoted form (`"references"`), so no
code-level change is required anywhere else. **Recommendation**: quote
the column in the schema file to remove the workaround.

## Hard do-not-build list (enforced in `routers/scans.py`)

`POST /v1/scans` refuses `kind` values in `_REFUSED_KINDS` with 400
before any scope-check runs, so no audit row is written for them.
Current list:

`exploit`, `exploit_launch`, `cred_stuff`, `credential_stuffing`,
`password_spray`, `brute_force`, `waf_bypass`, `stealth_scan`,
`fragment_scan`, `session_hijack`, `exfil`.

Extend the list; don't remove from it.

## Local run

```bash
docker compose up -d postgres redis
cd orchestrator && python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

## Tests

```bash
cd orchestrator && make test
```

Tests use `pytest-postgresql` (a real pg16 process per session, one
temp DB per test) and `fakeredis`. No live Redis or external Postgres
is required. `make test` will drop to the `postgres` OS user if run as
root, because `pg_ctl` refuses to run as root.
