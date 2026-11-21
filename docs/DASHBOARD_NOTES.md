# Dashboard — build & operations notes

Path: `/home/user/paddock/dashboard/`.

The dashboard is a React + Vite + TypeScript single-page app that consumes the
orchestrator's HTTP API documented in `docs/CONTRACTS.md`. It is deliberately
dark-first, dense, and graph-centric.

## Run it

Dev (hot reload, calls `VITE_API_URL` or proxies `/v1` → `localhost:8080`):

```
cd dashboard && npm install && npm run dev
```

Then open http://localhost:3000.

Production image (multi-stage, serves on :3000 via nginx with a `/v1/*` reverse
proxy to the `orchestrator` compose service):

```
docker build -t paddock-dashboard /home/user/paddock/dashboard
```

`docker-compose up dashboard` in the repo root also works; the `dashboard`
service is already wired in `docker-compose.yml`.

Tests:

```
cd dashboard && npm test
```

Vitest + jsdom + testing-library. 12 cases pass locally covering client URL
composition, error propagation, the zustand store, the exploit-excerpt
guardrail, and the graph layout.

## API endpoints consumed vs. mocked

Consumed directly from `CONTRACTS.md`:

- `GET  /v1/scope`
- `POST /v1/scope`
- `DELETE /v1/scope/{id}`
- `POST /v1/scope/check`
- `GET  /v1/scans` (with `target=`, `status=`, `limit=`)
- `GET  /v1/scans/{id}`
- `POST /v1/scans`
- `GET  /v1/assets` (with `kind=`, `value=`, `limit=`)
- `GET  /v1/assets/{id}`
- `GET  /v1/assets/{id}/graph?depth=`
- `GET  /v1/findings` (with `severity=`, `status=`, `asset_id=`, plus
  `rule_source=`, `kev=`, `q=`, `limit=`, `offset=` — see "assumed extras")
- `GET  /v1/findings/{id}`
- `PATCH /v1/findings/{id}`
- `GET  /v1/chains`
- `GET  /v1/timeline` (with `from=`, `to=`)
- `GET  /v1/events` (SSE; parsed per `stream:events` schema)

Endpoints the dashboard **needs** but that aren't in `CONTRACTS.md` yet
(call them "assumed extras"; please add them orchestrator-side):

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/assets/graph?limit=` | Whole-surface graph for the hero page. The per-asset `.../graph?depth=` doesn't have a seed when you just land on `/graph`. |
| `GET` | `/v1/scope/{id}/decisions?limit=` | Last-N audit entries for a scope entry — populates the expandable row on `/scope`. |
| `GET` | `/v1/findings?rule_source=&kev=&q=&limit=&offset=` | Filter and page findings. `limit`/`offset` give us infinite scroll; `rule_source`, `q`, and `kev` match the filter chips. |

All three are small shims on top of existing tables and should be trivial to
add in the orchestrator.

Nothing is mocked in the client — every network call hits `apiFetch()`. If
the orchestrator returns 404 on the "assumed extras", the UI gracefully
degrades (empty state on scope decisions; graph page shows an error banner
with the actual server response).

## File tree

```
dashboard/
├── Dockerfile
├── nginx.conf
├── package.json
├── tsconfig.json
├── vite.config.ts
├── index.html
├── src/
│   ├── main.tsx, App.tsx
│   ├── api/          client.ts, types.ts, scope.ts, scans.ts, assets.ts, findings.ts
│   ├── components/   Shell, Severity, AssetChip, FindingRow, Timeline,
│   │                 GraphCanvas, DetailDrawer, StatTile, FilterBar, EmptyState
│   ├── pages/        Overview, Graph, Findings, Chains, Timeline, Scope, Scans
│   ├── hooks/        useLiveEvents, useAssets, useFindings
│   ├── state/        store.ts (zustand)
│   ├── styles/       tokens.css, global.css
│   └── lib/          color.ts, graph.ts
└── tests/            setup.ts, smoke.test.ts
```

## Hard-rule compliance (safety)

- **No "how to exploit" text, ever.** `DetailDrawer.splitEvidence()` scans a
  finding description for any of `payload:`, `exploit:`, `shell:`, `poc:`,
  `reverse shell`, and `curl -… http…`. Paragraphs that match are rendered in
  muted monospace inside a bordered block tagged
  *evidence excerpt — do not treat as instruction*. There is no copy button,
  no "run" button, no terminal styling on these blocks.
- **Scope wildcard confirmation.** `Scope.tsx` intercepts entries whose kind
  is `wildcard` or whose value is `*` / starts with `*.` and shows a modal
  that requires typing `ALLOW <value>` verbatim before the request is sent.
- **Scope audit is prominent.** Every row on the Scope page is expandable to
  the last 10 decisions on that entry, loaded on demand from
  `/v1/scope/{id}/decisions?limit=10`.
- **No external telemetry.** Inter and JetBrains Mono are bundled via
  `@fontsource/*`. There are no analytics scripts, no third-party iframes,
  and no outbound `fetch` calls other than to `VITE_API_URL`.

## Keyboard shortcuts

Everything the UI binds, in one place.

| Context | Key | Action |
|---|---|---|
| global | click brand or `/` | — (reserved for future command palette) |
| Findings table | `j` | move cursor down one row |
| Findings table | `k` | move cursor up one row |
| Findings table | `enter` | open the focused finding in the drawer |
| Findings table | `s` | mark the focused finding `triaged` (optimistic patch) |
| Graph page | mousewheel | zoom |
| Graph page | drag background | pan |
| Graph page | click node | open asset drawer |
| Drawer | click backdrop or `✕` | close |
| Modal | click backdrop or `Cancel` | close |

Filter inputs (and textarea/select) are excluded from `j`/`k` bindings so
typing in them doesn't move the cursor.

## Screenshot plan

The project's visual identity is on the Graph page — this is the screenshot
to lead with on the README. Everything else is supporting. To generate a
reproducible set:

1. Bring up the compose stack:
   `docker compose up -d` (`postgres`, `redis`, `orchestrator`, `dashboard`
   plus the workers).
2. Seed a demo graph. Either run `scripts/seed_demo.sh` if present, or hit
   the orchestrator with a handful of `POST /v1/scans` targeting
   `example.com` and let the passive worker populate assets + findings.
3. Wait ~60s so the correlation service surfaces at least one chain.
4. Open `http://localhost:3000`. Resize the window to **1600×1000** (what
   the grid overlay was tuned against).
5. Take screenshots in this order:
   - `/graph` — centered, with 2–3 high/crit nodes pulsing. Nudge
     `enabledKinds` to `[domain, subdomain, ipv4, port, endpoint]` for the
     hero shot.
   - `/` — Overview, all four panels filled.
   - `/findings` — any filter active; cursor on a KEV row.
   - `/chains` — at least one chain card expanded.
   - `/timeline` — 7–14 days of history.
   - `/scope` — a row expanded showing the audit log.
   - `/scans` — the "New scan" modal open.
6. Headless capture:
   ```
   npx playwright screenshot --viewport-size=1600,1000 \
     http://localhost:3000/graph dashboard-graph.png
   ```
   Repeat per route. Playwright is **not** a dashboard dependency; install
   it ad-hoc if you want automated captures.

## Design notes

- Tokens live in `src/styles/tokens.css`. Every surface, every chip, every
  chart color references them. Flip `data-theme="light"` on `<html>` to try
  the light palette; it's experimental and dark remains the primary.
- Numbers use `font-variant-numeric: tabular-nums` so the stat tiles stay
  grid-aligned when values change.
- The Graph page uses a hand-rolled left-to-right rank layout (see
  `lib/graph.ts`), deterministic given the same input. That felt more
  "serious" than a bouncy force layout and keeps the screenshot stable.
- Edge labels are rendered as short uppercase monospace text with a tiny
  translucent background pill — the look follows ontology-explorer tools'
  object-graph editor.

## Known future work

- Replace the demo auth header stub (`VITE_API_TOKEN`) with real OIDC/SSO
  once the orchestrator grows an auth layer (ALLOW_NO_AUTH is on in dev).
- Add a command palette (`cmd-k`) that hits `/v1/assets` and `/v1/findings`.
- Virtualize the Findings list for >5k rows (currently plain scroll + IO).
