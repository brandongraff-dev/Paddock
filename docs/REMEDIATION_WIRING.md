# Remediation service — wiring

The auto-remediation engine ships as a new service `remediation/` (HTTP `:8102`)
plus an orchestrator router, a dashboard page, and a `docker-compose` block.
Everything below is **WIRING** — the feature code is already written; these are
the small edits that mount it. Nothing here auto-merges anything; PRs are
proposed only, and PR-opening is off by default.

---

## 1. Orchestrator router

`orchestrator/app/routers/remediation.py` already exists (router prefix
`/v1/remediation`, inline models, degrade-if-down propose proxy). Mount it in
`orchestrator/app/main.py` exactly like the other routers.

Add the import near the other `from .routers import ...` lines:

```python
from .routers import remediation as remediation_router
```

And include it where the other routers are wired (next to `threatintel_router`):

```python
app.include_router(remediation_router.router)
```

Optional (the router already falls back via `getattr(settings, "remediation_url",
"http://remediation:8102")`, so this is not required): add a typed setting to
`orchestrator/app/config.py` `Settings` alongside the other proxy targets:

```python
    # Auto-remediation service (schema 014). Read/proxy only; degrade gracefully.
    remediation_url: str = "http://remediation:8102"
```

Endpoints exposed:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/remediation/propose` | `{finding_id}` → proxy to the service; degrades to `{ok:false, note}` (never 5xx) when down |
| `GET` | `/v1/remediation?status=&limit=&offset=` | paged list, newest first, with verifier + injection **summaries** |
| `GET` | `/v1/remediation/{id}` | full record incl. the diff and the full verifier/injection reports |

---

## 2. Dashboard route + nav entry

`dashboard/src/pages/Remediation.tsx`, `dashboard/src/api/remediation.ts` and
`dashboard/src/styles/remediation.css` already exist. Wire the route and nav in
`App.tsx` and `Shell.tsx` (both are WIRING — do not otherwise edit them).

### `dashboard/src/App.tsx`

Add the import with the other page imports:

```tsx
import RemediationPage from "./pages/Remediation";
```

Add the route inside `<Routes>` (next to the `/threat-intel` route):

```tsx
<Route path="/remediation" element={<Shell><RemediationPage /></Shell>} />
```

### `dashboard/src/components/Shell.tsx`

Add a wrench/patch icon to the `Icon` map:

```tsx
  Remediation: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M14.5 5.5 a3.5 3.5 0 0 0-4.6 4.2 L4 15.6 L5 18 L8.4 14.1 a3.5 3.5 0 0 0 4.2-4.6 L10.5 11.5 L9 10 L11 8 Z" />
      <path d="M13 13 L19 19" />
    </svg>
  ),
```

Add the nav entry to `navEntries` (a good home is right after Threat Intel):

```tsx
  { to: "/remediation", label: "Remediation", icon: Icon.Remediation },
```

The page shows the list of proposed fixes (finding, change-class + status chip),
each expandable to the read-only **diff**, the **verifier verdict** and the
**injection-check results**, under a banner that proposed fixes are never
auto-merged.

---

## 3. docker-compose block

Mirror the `intel` block. Add this under `services:` (it belongs near `intel` /
`brain` / `threatintel`). By default it is on the **`internal`** network only —
no egress, no host-published port — because with `REMEDIATION_OPEN_PR=false` the
service only produces verified diffs + reports and never reaches GitHub.

```yaml
  remediation:
    build: ./remediation
    <<: *hardened-py
    environment:
      DATABASE_URL: postgresql+asyncpg://asm:${POSTGRES_PASSWORD}@postgres:5432/asm
      ORCHESTRATOR_URL: http://orchestrator:8080
      # Optional LLM (explanation + stricter-only second-opinion verify). The
      # deterministic generators + gate + rule verifier work fully without it.
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
      # PRs are PROPOSED, never auto-merged. Opening a real PR is OFF by default;
      # with it off the service produces the verified diff + reports and pushes
      # nothing. Turn it on ONLY together with GITHUB_TOKEN + GITHUB_REPO AND by
      # adding `egress` to this service's networks (see below).
      REMEDIATION_OPEN_PR: "false"
      # GITHUB_TOKEN: ${GITHUB_TOKEN:-}      # only needed when REMEDIATION_OPEN_PR=true
      # GITHUB_REPO: ${GITHUB_REPO:-}        # e.g. your-org/your-repo
      LOG_LEVEL: INFO
    tmpfs:
      - /tmp
    networks: [internal]                     # add `egress` ONLY if opening PRs
    depends_on:
      postgres: {condition: service_healthy}
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8102), 3).close()"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 30s
```

### Enabling PR-opening (opt-in, egress required)

When — and only when — you want the service to open a **proposed** PR:

1. set `REMEDIATION_OPEN_PR: "true"`,
2. provide `GITHUB_TOKEN` + `GITHUB_REPO` (via `.env`; never bake secrets in),
3. change the network line to `networks: [internal, egress]` so it can reach
   `api.github.com`,
4. install the `gh` CLI in `remediation/Dockerfile` (add
   `gh` to the apt/package step; it is intentionally omitted from the default
   image since the default profile never opens PRs).

Even then the service only runs `gh pr create` on a new branch, labels the PR
`automated-fix`, and puts the verification summary in the body. It has **no
merge path** and never enables auto-merge — a human always approves.

No new network entry is needed in the `networks:` section; `internal` and
`egress` already exist.
