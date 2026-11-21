# Device Discovery (IoT/OT) — wiring

The passive IoT/OT device-discovery feature ships three new surfaces plus a new
service. Per the build constraints, the shared entrypoints (`orchestrator`
`main.py`, dashboard `App.tsx` / `Shell.tsx` / `types.ts`, `docker-compose.yml`)
were **not** edited. The small, mechanical edits to wire everything up live
here. Each is additive.

The new service **otdiscovery** (`/otdiscovery`, HTTP `:8101`) is a sibling of
the passive worker. It is *passive-only*: it parses provided observations
(pcap / mDNS-SSDP-UPnP announcements / DHCP fingerprints / flows) and **never
initiates a connection to a discovered device** (see
`otdiscovery/app/__init__.py` and `tests/test_safety.py`).

---

## 1. Orchestrator router include

`orchestrator/app/routers/devices.py` defines `router` (prefix `/v1/devices`).
Wire it into `orchestrator/app/main.py` exactly like the other routers:

```python
# with the other `from .routers import ... as ..._router` lines:
from .routers import devices as devices_router

# inside create_app(), alongside the other app.include_router(...) calls:
app.include_router(devices_router.router)
```

Endpoints exposed:

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/v1/devices?type=&role=&vendor=&limit=&offset=` | paged inventory (iot_device + ot_device) |
| `GET` | `/v1/devices/summary` | counts by role/type/vendor, # exposed OT, # IT/OT violations |
| `GET` | `/v1/devices/{id}` | one device + its findings + its segment |

The router is read-only, reuses the ABAC clearance filter used by the other
routers, and declares its response models inline (the shared `models.py`
contract is unchanged). `/summary` is declared before `/{device_id}` so the
literal path wins.

> Tests (`orchestrator/tests/test_devices.py`) mount the router onto the test
> app themselves, so they pass before `main.py` is edited; wire it in for the
> running service.

---

## 2. Dashboard route + nav entry

Three new files were added (no edits to existing ones):

- `dashboard/src/pages/Devices.tsx`
- `dashboard/src/api/devices.ts`
- `dashboard/src/styles/devices.css`

### `dashboard/src/App.tsx`

```tsx
// with the other page imports:
import DevicesPage from "./pages/Devices";

// with the other <Route> entries inside <Routes>:
<Route path="/devices" element={<Shell><DevicesPage /></Shell>} />
```

### `dashboard/src/components/Shell.tsx`

Add a chip/cpu icon to the `Icon` object:

```tsx
Devices: (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
    <rect x="7" y="7" width="10" height="10" rx="1.5" />
    <rect x="10" y="10" width="4" height="4" rx="0.5" />
    <path d="M9 4 L9 7 M12 4 L12 7 M15 4 L15 7 M9 17 L9 20 M12 17 L12 20 M15 17 L15 20 M4 9 L7 9 M4 12 L7 12 M4 15 L7 15 M17 9 L20 9 M17 12 L20 12 M17 15 L20 15" />
  </svg>
),
```

Then add a nav entry (a good slot is right after Dependencies):

```tsx
{ to: "/devices", label: "Devices", icon: Icon.Devices },
```

The page renders header tiles (devices, OT devices, exposed OT, IT/OT
violations), a prominent "OT exposed to IT / internet" panel, a filterable
table (type icon, vendor/model, role chip, address, protocols, exposure badge)
and a device drawer (fingerprint evidence, findings, segment). It is dark/dense
and reuses the global tokens; `devices.css` adds only `--ot` / `--iot` accents.

---

## 3. docker-compose `otdiscovery` service

Mirror the passive worker / `sca` service but keep it **internal-only** — it
ingests provided data and talks only to the orchestrator and Postgres, so it
needs no `egress`. Add under `services:` in `docker-compose.yml`:

```yaml
  otdiscovery:
    build: ./otdiscovery
    <<: *hardened-py
    environment:
      DATABASE_URL: postgresql+asyncpg://asm:${POSTGRES_PASSWORD}@postgres:5432/asm
      ORCHESTRATOR_URL: http://orchestrator:8080
      OTDISCOVERY_HTTP_PORT: "8101"
      LOG_LEVEL: INFO
    tmpfs:
      - /tmp
    networks: [internal]           # no egress: it never reaches the public net
    depends_on: [orchestrator]
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8101), 3).close()"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 30s
```

Notes:
- `*hardened-py` applies `no-new-privileges`, `cap_drop: ALL`, `read_only`,
  `restart: unless-stopped` (the Dockerfile already runs as a non-root `USER`).
- The DB is used **read-only** to match discovered devices against the `cves`
  feed (KEV included); it is optional — if Postgres is unreachable the service
  still ingests and projects devices, and CVE matching simply yields nothing.
- No host port is published (hardened profile); reach it over `internal`, e.g.
  the orchestrator or an operator shell:
  `curl -s http://otdiscovery:8101/healthz`.

### Feeding it

```bash
# raw pcap upload
curl -s --data-binary @capture.pcap http://otdiscovery:8101/ingest

# or JSON observations (packets/flows, mDNS/SSDP, DHCP fingerprints, MACs)
curl -s -H 'content-type: application/json' \
  -d '{"observations":[{"kind":"packet","proto":"tcp","src_ip":"10.0.1.5","dst_ip":"10.0.5.10","dst_port":502,"dst_mac":"00:1b:1b:00:00:10","payload_hex":"000100000006010300000001"}]}' \
  http://otdiscovery:8101/ingest

# re-run fingerprint + exposure over everything ingested so far
curl -s -X POST http://otdiscovery:8101/analyze
```

Ingest/analyze fingerprint the devices, upsert them as `iot_device` /
`ot_device` assets (+ `network_segment` assets and `member_of` edges) through
`POST /v1/assets/bulk` and `/v1/edges/bulk`, and emit exposure
(`ot_it_exposure`, `ot_public_exposure`) and `cve_match` findings through
`POST /v1/findings/bulk` — all of which then surface on `/v1/devices` and the
dashboard **Devices** page.
