# Fleet Agent + Gated Enforcement: Wiring

Schema `014_fleet_remediation.sql` (`fleet_agents`, `agent_inventory`, `agent_actions`) and
`041_agent_v2.sql` (keys, enrollment tokens, signed postures), a **host agent** (`agent/`), an orchestrator
router (`/v1/fleet`), and a dashboard page.

> **Agent v2 (this release).** The agent now enrolls with a per-tenant one-time token and its own Ed25519 key and
> signs everything it sends; the shared `FLEET_ENROLL_TOKEN`, hostname-upsert enrollment and the unsigned
> heartbeat are **gone** (a hard cut: v1 agents get `403 re_enroll_required` and need a re-key token). Install,
> enroll, rotate, revoke and the threat model are in [AGENT_V2.md](AGENT_V2.md); the evidence it produces is
> described in [ASSURANCE_P2.md](ASSURANCE_P2.md). This page keeps the **enforcement gate** (propose, approve,
> apply), which is unchanged, and the wiring of the router and the dashboard.

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

## 1. Orchestrator router (already registered)

`orchestrator/app/main.py` includes `routers/fleet.py` (prefix `/v1/fleet`) and starts the agent liveness monitor
(`fleet_monitor.fleet_agent_monitor_loop`). Nothing to wire by hand.

| Method | Path | Auth | Notes |
| ------ | ---- | ---- | ----- |
| POST | `/v1/fleet/enroll` | the `fet_` token in the body | redeem a one-time token, bind an Ed25519 key (proof of possession), receive the `fat_` credential once; every token failure is the same generic 401 |
| POST/GET/DELETE | `/v1/fleet/enroll-tokens[/{id}]` | admin | mint (shown once), list (prefix only), revoke; `for_agent` mints a re-key token |
| POST | `/v1/fleet/{id}/heartbeat` | `X-Agent-Token` + signed envelope | proof of life; the reply carries the agent's approved **real** work |
| POST | `/v1/fleet/{id}/posture` | `X-Agent-Token` + signed envelope | the signed host posture (evidence) |
| POST | `/v1/fleet/{id}/keys/rotate` | `X-Agent-Token` + envelope signed by the current key | key rotation |
| POST | `/v1/fleet/{id}/inventory` | `X-Agent-Token` | v1 inventory for the Fleet page: **unsigned, never evidence**, refused for legacy agents |
| POST | `/v1/fleet/actions/{id}/result` | `X-Agent-Token` | the agent reports `applied`/`failed`; bound to the agent the action belongs to |
| GET | `/v1/fleet/agents`, `/agents/{id}` | read | list and detail (viewer-safe: no machine id hash, no peer address) |
| GET | `/v1/fleet/agents/{id}/posture` | `triage` | the full stored posture; audited |
| POST | `/v1/fleet/agents/{id}/revoke`, `/agents/{id}/keys/{key_id}/revoke` | admin | immediate; nothing is cached |
| POST | `/v1/fleet/actions` | requester | **propose**: status `proposed`, `dry_run=true` |
| POST | `/v1/fleet/actions/{id}/approve` | **admin** | `proposed` to `approved`; four-eyes; `apply_for_real` |
| POST | `/v1/fleet/actions/{id}/deny` | **admin** | `proposed` to `denied` |
| GET | `/v1/fleet/actions?agent=&status=` | read | list/filter |
| POST | `/v1/fleet/actions/{id}/revert` | admin/requester | mint a first-class `revert` action |

Every transition calls `audit.record()`.

### RBAC (enforce mode)

The agent is **a principal of its own** (`kind="agent"`, capability `agent`, never a role). `auth.py` resolves the
`X-Agent-Token` credential by its 12-hex prefix, compares the sha256 in constant time, and refuses revoked agents
(`403 agent_revoked`), legacy agents (`403 re_enroll_required`) and suspended tenants. The route rules are
anchored on a UUID path segment, so they cannot shadow `/v1/fleet/actions/...`, and the agent id in the path must be
the principal's own. Agent routes work in `AUTH_MODE=enforce` and outside the default tenant; the old rules that
made every fleet route admin-only (so agents could only work in dev mode) are gone. No other credential, not even
an admin's, is accepted on an agent route.

### Enrollment

There is no shared enrollment secret any more. An admin mints a per-tenant token (single use by default; up to 50
uses with a ttl of at most 24 h for cloud-init fleets); see [AGENT_V2.md](AGENT_V2.md). Four-eyes on action approval
(the approver must differ from the requester) is on by default; `FLEET_ALLOW_SELF_APPROVE=1` relaxes it (not
recommended).

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

The agent runs **on target hosts**, opt-in. Do **not** add it to `docker-compose.yml`. Install it with the
signed release installer (see [AGENT_V2.md](AGENT_V2.md)):

```bash
printf %s "$ENROLL_TOKEN" | sudo sh ./install-agent.sh --server https://paddock.example.com --require-cosign
```

(Run it with `sh ./install-agent.sh`: a downloaded file is not executable. Never put the token after `sudo`
as `VAR=...`; that is visible in the process list.)

That installs a single-file archive (`paddock-agent.pyz`, standard library only, Python 3.8 or newer), a hardened
systemd unit (one root process; `NoNewPrivileges`, `ProtectSystem=strict`, a capability bounding set of
`CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN`, and more) and enrolls the host. The token is never an argument.
Re-running it upgrades the agent (it restarts the service) and keeps your other `agent.env` settings. That
capability set reaches nftables / `iptables-nft` over netlink but has no `CAP_NET_RAW`, so on a host whose
firewall is **legacy iptables** the agent cannot read or change it: its firewall facts read `UNKNOWN` and
`block_ip` / `firewall_rule` fail ([AGENT_V2.md](AGENT_V2.md) section 3).
For development: `cd agent && pip install -e .` provides the `paddock` command.

A container image exists for trying the agent on a Linux host (`docker build -t paddock/agent agent/`). Give the
token on stdin, not with `-e` (which `docker inspect` shows):

```bash
printf %s "$ENROLL_TOKEN" | docker run --rm -i --network host --cap-add NET_ADMIN \
  -e PADDOCK_SERVER=https://orchestrator.internal:8080 \
  -v paddock-agent-state:/var/lib/paddock-agent \
  paddock/agent paddock enroll --token-stdin
```

A containerised agent cannot see the host's binaries, so those facts are reported as
`unavailable(containerised_agent)`, which Paddock reads as `UNKNOWN`, never as a pass.

### Required capabilities (why it's opt-in)

Collection is read-only and needs root (or `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, plus
`CAP_NET_RAW` to read legacy iptables tables, which the shipped unit does not grant). To actually
**apply** host-local blocks on Linux the agent needs:

- the **`NET_ADMIN`** capability to edit firewall rules over netlink (nft, `iptables-nft`; legacy iptables also
  needs `CAP_NET_RAW`, and a writable `/run/xtables.lock`), and host networking in a container;
- write access to `/etc/hosts` (domain sinkhole) and to the quarantine dir (`quarantine_file`). **The shipped
  systemd unit makes those read-only** (`ProtectSystem=strict`), so `block_domain` and `quarantine_file` fail
  under it until you widen `ReadWritePaths=` on purpose.

Because those are elevated, deploying the agent is a deliberate per-host decision. **Windows / macOS are dry-run
only** (explicit `NotImplemented` stubs): they simulate a plan but never apply. IPv6 `block_ip` is refused loudly
(`ipv6_not_supported`) rather than silently doing nothing. A revert plan from the server is treated as data: the
agent re-derives the only command it could have produced from the original typed action and refuses anything
else.

The agent is in **dry-run unless you set `PADDOCK_DRY_RUN=false`** in `/etc/paddock-agent/agent.env`, and even
then it applies only what the server marked approved for real. On the host it also refuses a block that would cut
it off from its own server (`self_lockout`: the server's addresses, loopback, outbound to the server's port,
DNS when the server is a name), and it removes a `block_ip` / `firewall_rule` itself when no successful round
trip to the server follows within `PADDOCK_NETBLOCK_DEADMAN_MIN` minutes (default 10, `0` = off). That dead-man
removal is local only: the server is not told, so its record of the action can lag. Details in
[AGENT_V2.md](AGENT_V2.md) section 3.

---

## 4. Smoke test after wiring

```bash
# agent (state machine, signing, collectors, platform dry-run, host-local guard); no server needed
cd agent && pip install -e .[test] && pytest -q
# orchestrator (tests/test_fleet*.py, the P2 end-to-end test and the wire vectors)
cd ../orchestrator && make test
# dashboard typecheck
cd ../dashboard && npx tsc -b
```

With the stack up and an agent enrolled (dry-run):

```bash
curl -s -H "Authorization: Bearer $KEY" localhost:8080/v1/fleet/agents
# propose (dry-run), approve for real as a DIFFERENT admin, watch it apply
curl -s -XPOST localhost:8080/v1/fleet/actions -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
     -d '{"agent_id":"<id>","action_type":"block_ip","target":"203.0.113.10","reason":"ti match"}'
curl -s -XPOST localhost:8080/v1/fleet/actions/<action-id>/approve -H "Authorization: Bearer $ADMIN_KEY" \
     -H 'content-type: application/json' -d '{"apply_for_real":true}'
curl -s -H "Authorization: Bearer $KEY" 'localhost:8080/v1/fleet/actions?status=applied'
```

The Fleet page in the dashboard still shows the v1 fields (status, last seen, unsigned inventory). It has no
screen for enrollment tokens, key rotation or posture verdicts yet: use the API ([AGENT_V2.md](AGENT_V2.md)).
