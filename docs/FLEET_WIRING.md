# Fleet Agent + Gated Enforcement — Wiring

Schema `014_fleet_remediation.sql` (`fleet_agents`, `agent_inventory`,
`agent_actions`) + a new **host agent** (`agent/`), an orchestrator router
(`/v1/fleet`), and a dashboard page. Everything below is the **manual wiring**
into files this change intentionally did **not** edit
(`orchestrator/app/main.py`, `orchestrator/app/auth.py`, `dashboard/src/App.tsx`,
`dashboard/src/components/Shell.tsx`, `dashboard/src/api/types.ts`,
`docker-compose.yml`, `schema/*`).

The feature is **defensive and gated**. An agent runs **on a host**, enrolls,
reports inventory, and can apply **host-local** blocks — but only through
**propose → approve → apply**:

```
  propose ──(admin approve, four-eyes)──▶ approved ──(agent applies)──▶ applied
     │                                       │                             │
     └──(admin deny)──▶ denied               └──▶ failed      (revert) ◀────┘  ──▶ reverted
```

- **Host-local only** — an agent acts only on the host it runs on. There is no
  field, anywhere, that names a remote host to act on.
- **Propose first** — nothing leaves `proposed` without an explicit human
  `approved_by`. No auto-apply.
- **Dry-run by default** — a real apply requires `dry_run=false` (granted only
  when an admin approves with `apply_for_real=true`) **and** the agent not
  running dry.
- **Reversible** — every applied block records its revert plan; `revert` is a
  first-class action; `quarantine_file` *moves* files (never deletes).
- **Audited** — every transition is written to the tamper-evident audit log.
- **Allowed actions only** — `block_ip`, `block_domain`, `quarantine_file`,
  `firewall_rule`, `revert`. Nothing else.

---

## 1. Orchestrator router include

File: `orchestrator/app/main.py`

Add the import alongside the other router imports:

```python
from .routers import fleet as fleet_router
```

Register it in `create_app()` (next to the other Tier routers, e.g. after
`threatintel_router`):

```python
    # Fleet agents + gated host-local enforcement (schema 014).
    app.include_router(fleet_router.router)
```

The router's prefix is `/v1/fleet` and it owns:

| Method | Path                               | Auth            | Notes                                              |
| ------ | ---------------------------------- | --------------- | -------------------------------------------------- |
| POST   | `/v1/fleet/enroll`                 | enroll token    | mint agent + one-time credential (sha256 stored)   |
| POST   | `/v1/fleet/{id}/heartbeat`         | `X-Agent-Token` | last_seen + returns approved **real** work          |
| POST   | `/v1/fleet/{id}/inventory`         | `X-Agent-Token` | os/packages/listeners/posture snapshot             |
| GET    | `/v1/fleet/agents`                 | read            | list + status (stale if last_seen old)             |
| GET    | `/v1/fleet/agents/{id}`            | read            | agent + latest inventory + action counts           |
| POST   | `/v1/fleet/actions`                | requester       | **propose** — status `proposed`, `dry_run=true`    |
| POST   | `/v1/fleet/actions/{id}/approve`   | **admin**       | `proposed→approved`; four-eyes; `apply_for_real`   |
| POST   | `/v1/fleet/actions/{id}/deny`      | **admin**       | `proposed→denied`                                  |
| GET    | `/v1/fleet/actions?agent=&status=` | read            | list/filter                                        |
| POST   | `/v1/fleet/actions/{id}/result`    | `X-Agent-Token` | agent reports `applied`/`failed`                   |
| POST   | `/v1/fleet/actions/{id}/revert`    | admin/requester | mint a first-class `revert` action                 |

Every transition calls `audit.record()`.

### RBAC note (production / `AUTH_MODE=enforce`)

The governance middleware (`auth.py`) is **deny-closed**: an unclassified `POST`
defaults to the `admin` capability and a `GET` to `read`. The router enforces
admin-only approve/deny with its own `require("admin")` dependency and
authenticates agents with the minted credential (`X-Agent-Token`), so it is
correct as-is in `dev` mode and for the test-suite.

For `enforce` mode you will want to add RBAC rules to `auth.py` so the agent and
operator flows are not forced through `admin` (mirrors how the existing TI
POSTs are handled). Suggested `_rule(...)` additions:

```python
# Fleet: agent + operator surface (schema 014)
_rule("POST", r"/v1/fleet/enroll", None)                                # token-gated, public route
_rule("POST", rf"/v1/fleet/{_ANY}/heartbeat", None)                     # X-Agent-Token validated in-router
_rule("POST", rf"/v1/fleet/{_ANY}/inventory", None)                     # X-Agent-Token validated in-router
_rule("POST", rf"/v1/fleet/actions/{_ANY}/result", None)               # X-Agent-Token validated in-router
_rule("POST", r"/v1/fleet/actions", "triage")                           # propose = analyst+admin
_rule("POST", rf"/v1/fleet/actions/{_ANY}/(approve|deny)", "admin")    # gate stays admin
_rule("POST", rf"/v1/fleet/actions/{_ANY}/revert", "triage")
```

`enroll`, `heartbeat`, `inventory`, and `result` are marked public at the
middleware layer because they carry their **own** credential (the enrollment
bootstrap token / the minted `X-Agent-Token`) that the router validates — the
agent credential is not a DB user, so it cannot resolve to a `Principal`.

### Enrollment secret

Set a shared enrollment bootstrap secret in the orchestrator's environment:

```yaml
      FLEET_ENROLL_TOKEN: ${FLEET_ENROLL_TOKEN}   # agents must present exactly this
      # FLEET_ALLOW_SELF_APPROVE: "false"          # default; keep four-eyes on
```

When `FLEET_ENROLL_TOKEN` is unset the router accepts any non-empty token and
logs a warning (dev only). Four-eyes (approver must differ from requester) is on
by default; `FLEET_ALLOW_SELF_APPROVE=1` relaxes it (not recommended).

---

## 2. Dashboard route + nav entry

### Route — `dashboard/src/App.tsx`

Add the import with the other page imports:

```tsx
import FleetPage from "./pages/Fleet";
```

Add the route inside `<Routes>` (anywhere among the authed routes):

```tsx
        <Route path="/fleet" element={<Shell><FleetPage /></Shell>} />
```

### Nav entry — `dashboard/src/components/Shell.tsx`

Add a server/shield icon to the `Icon` map, then add an entry to `navEntries`
(e.g. after `/threat-intel`):

```tsx
  { to: "/fleet", label: "Fleet", icon: Icon.Fleet },
```

Example icon (server rack + shield), add to the `Icon` object:

```tsx
  Fleet: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="4" y="4" width="16" height="6" rx="1.5" />
      <rect x="4" y="13" width="16" height="6" rx="1.5" />
      <circle cx="7.5" cy="7" r="0.9" fill="currentColor" />
      <circle cx="7.5" cy="16" r="0.9" fill="currentColor" />
      <path d="M15 14.5 L18.5 14.5 L18.5 17 Q18.5 18.6 16.75 19.2 Q15 18.6 15 17 Z" />
    </svg>
  ),
```

No change to `types.ts` is needed — `src/pages/Fleet.tsx` + `src/api/fleet.ts`
carry their own local TS types. Approve/Deny/Revert controls are wrapped in the
existing `<Gate need="admin">` so they are admin-gated in the UI too.

---

## 3. The agent is NOT a compose service

The agent runs **on target hosts**, opt-in — do **not** add it to
`docker-compose.yml`. It is built/installed per host:

```bash
cd agent
pip install -e .            # provides the `pasm` console script
# or: docker build -t palantir-asm/agent .
```

Enroll + run on a host (dry-run by default):

```bash
pasm enroll --server https://orchestrator.internal:8080 --token "$FLEET_ENROLL_TOKEN"
pasm run        # heartbeat + inventory loop; applies only approved, real work
```

Or as a container, opt-in, on a target **Linux** host:

```bash
docker run --rm \
  --network host --cap-add NET_ADMIN \
  -e PASM_SERVER=https://orchestrator.internal:8080 \
  -e PASM_DRY_RUN=true \
  -v pasm-agent-cred:/root/.config/palantir-agent \
  -v pasm-quarantine:/var/lib/palantir-agent/quarantine \
  palantir-asm/agent pasm enroll --token "$FLEET_ENROLL_TOKEN"
```

### Required capabilities (why it's opt-in)

The agent runs fine in **inventory / dry-run** mode with **no** special
privileges. To actually **apply** host-local blocks on Linux it needs:

- **host networking** (`--network host`) so iptables/nft rules affect the real
  host;
- the **`NET_ADMIN`** capability (`--cap-add NET_ADMIN`) to edit firewall rules;
- write access to `/etc/hosts` (domain sinkhole) and to the quarantine dir
  (`quarantine_file`).

Because those are elevated, deploying the agent is a deliberate per-host
decision. **Windows / macOS are dry-run only** (explicit `NotImplemented`
stubs): they simulate a plan but never apply.

---

## 4. Smoke test after wiring

```bash
# agent (state machine, platform dry-run, inventory, host-local guard)
cd agent && pip install -e .[test] && pytest -q
# orchestrator (includes tests/test_fleet.py)
cd ../orchestrator && make test
# dashboard typecheck
cd ../dashboard && npx tsc -b
```

With the stack up and an agent enrolled (dry-run):

```bash
curl -s localhost:8080/v1/fleet/agents
# propose (dry-run), approve for real as a DIFFERENT admin, watch it apply
curl -s -XPOST localhost:8080/v1/fleet/actions -H 'content-type: application/json' \
     -d '{"agent_id":"<id>","action_type":"block_ip","target":"203.0.113.10","reason":"ti match"}'
curl -s -XPOST localhost:8080/v1/fleet/actions/<action-id>/approve \
     -H 'content-type: application/json' -d '{"apply_for_real":true}'
curl -s 'localhost:8080/v1/fleet/actions?status=applied'
```
