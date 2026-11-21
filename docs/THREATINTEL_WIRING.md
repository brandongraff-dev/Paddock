# Threat-Intel Fusion — Wiring

Schema `013_threatintel.sql` + a new `threatintel/` service (HTTP :8100), an
orchestrator router (`/v1/ti`), and a dashboard page. Everything below is the
**manual wiring** into files this change intentionally did **not** edit
(`orchestrator/app/main.py`, `orchestrator/app/config.py`, `dashboard/src/App.tsx`,
`dashboard/src/components/Shell.tsx`, `docker-compose.yml`).

The feature is **defensive**: it ingests IOCs (STIX 2.1 / TAXII 2.1) and matches
them against the owner's **own** assets + findings. Outbound HTTP only ever hits
**user-configured feed URLs**; matching is read-only over the owner's tables.

---

## 1. Orchestrator router include

File: `orchestrator/app/main.py`

Add the import alongside the other router imports:

```python
from .routers import threatintel as threatintel_router
```

Register it in `create_app()` (next to the other Tier routers, e.g. after the
ML routers):

```python
    # Threat-intel fusion (schema 013): IOC feeds, indicators, matches, summary.
    app.include_router(threatintel_router.router)
```

The router's prefix is `/v1/ti` and it owns:

| Method | Path                       | Notes                                        |
| ------ | -------------------------- | -------------------------------------------- |
| GET    | `/v1/ti/feeds`             | list configured feeds                        |
| POST   | `/v1/ti/feeds`             | register a TAXII / STIX_URL feed             |
| DELETE | `/v1/ti/feeds/{id}`        | remove a feed                                |
| POST   | `/v1/ti/feeds/{id}/poll`   | **proxy** to threatintel; degrades if down   |
| GET    | `/v1/ti/indicators`        | paged; `?type=&label=&q=&limit=&offset=`     |
| GET    | `/v1/ti/matches`           | paged; joins indicator + subject summary     |
| POST   | `/v1/ti/ingest`            | **proxy** a STIX bundle; degrades if down    |
| GET    | `/v1/ti/summary`           | counts by indicator type + match + feed count|

---

## 2. Orchestrator config

File: `orchestrator/app/config.py` — add one field to the `Settings` class
(next to `mlrisk_url` / `codeanalysis_url`):

```python
    # Threat-intel fusion service (threatintel/, HTTP :8100). The orchestrator
    # only reads/proxies it and must degrade gracefully when it is down.
    threatintel_url: str = "http://threatintel:8100"
```

> The router already falls back to `http://threatintel:8100` via
> `getattr(settings, "threatintel_url", ...)`, so it works before this field is
> added; adding it just makes the target configurable (env `THREATINTEL_URL`).

---

## 3. Dashboard route + nav entry

### Route — `dashboard/src/App.tsx`

Add the import with the other page imports:

```tsx
import ThreatIntelPage from "./pages/ThreatIntel";
```

Add the route inside `<Routes>` (anywhere among the authed routes):

```tsx
        <Route path="/threat-intel" element={<Shell><ThreatIntelPage /></Shell>} />
```

### Nav entry — `dashboard/src/components/Shell.tsx`

Add an icon to the `Icon` map (any inline SVG; a shield pairs well with the
existing Posture icon), then add an entry to `navEntries` — e.g. after
`/dependencies`:

```tsx
  { to: "/threat-intel", label: "Threat Intel", icon: Icon.ThreatIntel },
```

Example icon (shield + crosshair), add to the `Icon` object:

```tsx
  ThreatIntel: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 3 L19 6 L19 11 Q19 18 12 21 Q5 18 5 11 L5 6 Z" />
      <circle cx="12" cy="11" r="2.4" />
      <path d="M12 6 L12 8.2 M12 13.8 L12 16 M7.4 11 L9.6 11 M14.4 11 L16.6 11" />
    </svg>
  ),
```

No change to `types.ts` is needed — the page + `src/api/ti.ts` carry their own
local TS types.

---

## 4. docker-compose service block

File: `docker-compose.yml`. Add this service (mirrors the `intel` block;
reuses the `*hardened-py` anchor). It sits on `internal` (to reach the
orchestrator + Postgres) and `egress` (to reach user-configured feed URLs):

```yaml
  threatintel:
    build: ./threatintel
    <<: *hardened-py
    environment:
      DATABASE_URL: postgresql+asyncpg://asm:${POSTGRES_PASSWORD}@postgres:5432/asm
      REDIS_URL: redis://redis:6379/0
      ORCHESTRATOR_URL: http://orchestrator:8080
      TI_POLL_INTERVAL_MIN: "60"
      LOG_LEVEL: INFO
    tmpfs:
      - /tmp
    networks: [internal, egress]
    depends_on:
      postgres: {condition: service_healthy}
      orchestrator: {condition: service_started}
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8100), 3).close()"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 30s
```

And give the orchestrator the service URL (optional; it defaults correctly).
Add to the `orchestrator` service's `environment:`:

```yaml
      THREATINTEL_URL: http://threatintel:8100
```

> `threatintel` has **no published host port** (hardened profile) — the
> orchestrator reaches it over the `internal` network and proxies the two
> network actions (`/poll/{id}`, `/ingest/stix`). Outbound to feed URLs goes
> over `egress`.

---

## 5. Smoke test after wiring

```bash
# service
cd threatintel && pip install -e .[test] && pytest -q
# orchestrator (includes tests/test_threatintel.py)
cd ../orchestrator && make test
# dashboard typecheck
cd ../dashboard && npx tsc --noEmit -p tsconfig.json
```

Then, with the stack up:

```bash
# register a feed, ingest a bundle, see matches
curl -s localhost:8080/v1/ti/summary
curl -s -XPOST localhost:8080/v1/ti/ingest -H 'content-type: application/json' \
     --data-binary @threatintel/tests/fixtures/stix_bundle.json
curl -s 'localhost:8080/v1/ti/indicators?type=domain'
curl -s localhost:8080/v1/ti/matches
```
