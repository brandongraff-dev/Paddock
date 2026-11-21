# Ontology / semantic layer — wiring

Everything below is additive. The ontology build deliberately did **not** touch
`orchestrator/app/main.py`, `dashboard/src/App.tsx`, `Shell.tsx`, the shared
`models.py` / `types.ts`, `global.css`, or `docker-compose.yml`. Wire it with
the four edits in this file.

New pieces delivered:

- `ontology/` — the projector service (HTTP :8099). Reads the raw tables,
  writes only the `ontology_*` tables. Projects on startup, every
  `ONTOLOGY_INTERVAL_MIN` (default 15), and on `POST /project`.
- `orchestrator/app/routers/ontology.py` — read API, `router` with prefix
  `/v1/ontology` (ABAC-filtered, paged envelopes).
- `dashboard/src/pages/Explore.tsx`, `src/api/ontology.ts`,
  `src/styles/ontology.css` — the Explore page.

The schema (`schema/012_ontology.sql`) already exists and applies after 001–011.

---

## 1. Orchestrator — include the router

In `orchestrator/app/main.py`, next to the other `from .routers import …`
lines:

```python
from .routers import ontology as ontology_router
```

and inside `create_app()`, next to the other `app.include_router(...)` calls:

```python
app.include_router(ontology_router.router)
```

That is the only orchestrator edit. The router defines its own Pydantic
response models in-file (no `models.py` change) and reuses the existing
`classification_rank_sql` / `current_principal` ABAC pattern — if the auth layer
is absent the dependency resolves a full-clearance dev principal, so the filter
is a no-op.

Endpoints exposed:

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/v1/ontology/types` | object types (+ live object counts) + link types |
| GET | `/v1/ontology/objects?type=&q=&limit=&offset=` | paged typed objects |
| GET | `/v1/ontology/objects/{id}` | object view: entity + neighbours grouped by link type/direction |
| GET | `/v1/ontology/search?q=` | cross-type title search |

---

## 2. Dashboard — route + nav entry

### 2a. Route (`dashboard/src/App.tsx`)

Add the import beside the other page imports:

```tsx
import ExplorePage from "./pages/Explore";
```

Add the route inside `<Routes>` (anywhere among the authed routes, e.g. after
`/graph`):

```tsx
<Route path="/explore" element={<Shell><ExplorePage /></Shell>} />
```

The Explore page uses `@tanstack/react-query` (already the app's data layer) and
the shared `ClassificationChip`. No provider changes needed.

### 2b. Nav entry (`dashboard/src/components/Shell.tsx`)

Add an icon to the `Icon` object (a simple "entities/graph" glyph):

```tsx
  Explore: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="12" cy="5" r="2.2" />
      <circle cx="5" cy="17" r="2.2" />
      <circle cx="19" cy="17" r="2.2" />
      <path d="M11 6.6 L6 15 M13 6.6 L18 15 M7 17 L17 17" />
    </svg>
  ),
```

Then add an entry to `navEntries` (a good slot is right after Graph):

```tsx
  { to: "/explore", label: "Explore", icon: Icon.Explore },
```

---

## 3. docker-compose — the `ontology` service

Add this block under `services:` in `docker-compose.yml`, mirroring `intel`.
Unlike intel it is **internal-only** (no `egress`): the projector never reaches
the network — it only reads the DB and writes the `ontology_*` tables.

```yaml
  ontology:
    build: ./ontology
    <<: *hardened-py
    environment:
      DATABASE_URL: postgresql+asyncpg://asm:${POSTGRES_PASSWORD}@postgres:5432/asm
      ORCHESTRATOR_URL: http://orchestrator:8080
      ONTOLOGY_INTERVAL_MIN: "15"
    tmpfs:
      - /tmp
    networks: [internal]
    depends_on:
      postgres: {condition: service_healthy}
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8099), 3).close()"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 30s
```

If you want the port published for local dev, add the matching stanza to
`docker-compose.override.yml` the same way the other services do, e.g.:

```yaml
  ontology:
    ports:
      - "8099:8099"
```

`ORCHESTRATOR_URL` is passed only for parity/health; the projector does **not**
call the orchestrator — it writes the ontology straight to the shared DB.

---

## 4. Orchestrator config — `ontology_url` (optional / probably unnecessary)

The orchestrator reads the ontology directly from its own database
(`ontology_*` tables), so it does **not** need to know the service's URL. You
can skip this entirely.

If you want a handle for a health/trigger proxy later, add to
`orchestrator/app/config.py` (`class Settings`):

```python
    # Ontology projector service. The orchestrator reads the ontology from the
    # shared DB directly, so this is only for an optional health/trigger proxy.
    ontology_url: str = "http://ontology:8099"
```

No router or startup code depends on it today.

---

## Tests

- Service: `cd ontology && pip install -e .[test] && pytest -q`
  (pure mapping + type-system tests always run; the DB-backed projection test
  runs only when `TEST_DATABASE_URL` points at a reachable Postgres).
- Orchestrator: `cd orchestrator && make test` (adds `tests/test_ontology.py`).
