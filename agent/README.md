# palantir-asm fleet host agent

A small, **opt-in** agent that runs **on a host**. It enrolls with the
orchestrator, reports inventory, and can apply **host-local** defensive blocks —
but only through the orchestrator's **propose → approve → apply** gate,
**dry-run by default**, **reversible**, and **fully audited**.

The agent has **no offensive capability**. It blocks inbound/outbound traffic on
its **own** machine and never scans, probes, or acts on any other host. There is
structurally no field anywhere in the agent that names another machine to act
on.

## Install

```bash
cd agent
pip install -e .            # provides the `pasm` console script
pip install -e .[test]      # + test deps
```

## Operator CLI

```bash
pasm enroll  --server https://orchestrator:8080 --token "$FLEET_ENROLL_TOKEN"
pasm status                 # agent + server view
pasm inventory              # collect inventory (add --send to upload)
pasm actions                # list this host's proposed/approved/applied actions
pasm simulate block_ip 203.0.113.10     # DRY-RUN preview — touches nothing
pasm apply <action-id>      # apply a SERVER-APPROVED action, after confirmation
pasm run                    # heartbeat + inventory loop; applies approved work
```

- `simulate` never mutates — it prints the exact plan the enforcer *would* run.
- `apply` refuses unless the server already has the action in status `approved`
  with `dry_run=false`, and the operator confirms. **The CLI never applies an
  action the server has not approved.**
- The autonomous `run` loop only applies actions the server returns as approved
  **and** real (`dry_run=false`); everything else is simulated and logged.

## Safety rails (enforced, not aspirational)

1. **Host-local only.** `actions.assert_host_local` validates every target as a
   thing to block/quarantine on *this* host; there is no remote-host parameter.
2. **Propose → approve → apply.** The agent refuses to apply anything whose
   server status is not `approved`.
3. **Dry-run by default** (`PASM_DRY_RUN=true`). A real apply requires the
   server's `dry_run=false` **and** the agent not running dry.
4. **Audited.** Every transition is recorded server-side in the tamper-evident
   audit log (the agent reports results; the orchestrator writes the chain).
5. **Reversible.** Every applied block records its revert plan; `revert` is a
   first-class action and `quarantine_file` *moves* files (never deletes).
6. **Allowed actions only:** `block_ip`, `block_domain`, `quarantine_file`,
   `firewall_rule`, `revert`. Nothing else ever reaches the enforcer.

## Required capabilities (and why it's opt-in)

The agent runs in **dry-run / inventory** mode with no special privileges. To
actually apply firewall rules on Linux it needs:

- **host networking** (`--network host`) so iptables/nft rules affect the real
  host, and
- the **`NET_ADMIN`** capability (`--cap-add NET_ADMIN`) to edit firewall rules;
  domain sinkholing additionally needs write access to `/etc/hosts`, and
  `quarantine_file` needs write access to the quarantine dir.

Because those are elevated privileges, deploying the agent is a deliberate,
opt-in decision per host — it is **not** a `docker-compose` service of the
platform. Windows and macOS are **dry-run only** (explicit `NotImplemented`
stubs): they can simulate a plan but never apply.

## Configuration (environment)

| Var | Default | Meaning |
|-----|---------|---------|
| `PASM_SERVER` | `http://localhost:8080` | orchestrator base URL |
| `PASM_DRY_RUN` | `true` | force simulate-only; a real apply needs this off |
| `PASM_AGENT_CRED` | `~/.config/palantir-agent/credentials.json` | credential file (chmod 600) |
| `PASM_QUARANTINE_DIR` | `/var/lib/palantir-agent/quarantine` | where quarantined files are moved |
| `PASM_HEARTBEAT_SEC` | `30` | heartbeat interval |
| `PASM_INVENTORY_SEC` | `300` | inventory interval |
| `PASM_OPERATOR_TOKEN` | — | operator bearer token for read/propose CLI calls |
| `FLEET_ENROLL_TOKEN` | — | enrollment bootstrap secret (set server-side too) |
