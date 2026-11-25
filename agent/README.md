# Paddock fleet host agent (v2)

A small, **opt-in** agent that runs **on a server**. It enrolls with the orchestrator using a one-time
token and its **own Ed25519 key**, then sends a **signed host posture** (sshd, listeners, firewall, patch
state, self-health) that the assurance engine can evaluate (`docs/ASSURANCE_P2.md`). It can also apply
**host-local** defensive blocks, but only through the orchestrator's **propose, approve, apply** gate:
**dry-run by default**, **reversible**, **fully audited**.

The agent has **no offensive capability**. It blocks traffic on its **own** machine and never scans,
probes, or acts on any other host.

* **Standard library only, Python >= 3.8.** No `httpx`, no `psutil`. Ed25519 uses the `cryptography`
  package when it can be imported and otherwise a vendored pure-Python RFC 8032 signer
  (`paddock_agent/ed25519_pure.py`); both give byte-identical keys and signatures (tested).
* **One root process** (owner decision O2). Read-only collectors run in the same service as the network
  client; the unprivileged-agent-plus-root-helper split is deferred to P4. A network-facing process that
  holds root is a documented risk, which is why the unit below is sandboxed.

## Install and enroll

```bash
cd agent && pip install .          # provides the `paddock` command (WP7 adds a signed zipapp + installer)
```

An admin mints a **one-time enrollment token** (`fet_<12 hex>_<secret>`, single use by default) through
the API (`POST /v1/fleet/enroll-tokens`). **The token is never accepted as a command-line argument** (argv is visible to every
local user in `ps` and `/proc`); give it on stdin or in the environment:

```bash
export PADDOCK_SERVER=https://paddock.example.com
read -rs PADDOCK_ENROLL_TOKEN && export PADDOCK_ENROLL_TOKEN      # or: printf %s "$TOKEN" | paddock enroll --token-stdin
sudo -E paddock enroll             # generates a NEW key, proves possession of it, spends the token
paddock status
sudo systemctl enable --now paddock-agent
```

Enrollment generates the key on the host (it never leaves it), signs
`b"paddock-enroll/v1\n" + token_prefix + "\n" + hostname` with it as proof of possession, and stores the
returned `fat_` credential (shown once by the server). `--server` / `PADDOCK_SERVER` must be `https://`;
plain `http://` is accepted only for a loopback server.

**Wiped or lost state** (reinstalled host, deleted `/var/lib/paddock-agent`): the old key is gone, so the
agent cannot prove it is the same host. Ask an admin for a **re-key token** for this agent and run
`paddock enroll --force`. The server revokes the old key with a reason and keeps the history. The agent
never reuses a key.

**Rotate the key** any time (also after any suspicion of key exposure): `paddock rotate-key`. The new
key signs a proof of possession; the **current** key signs the hand-over; the old key becomes `rotated`.
If the reply is lost the new key stays *pending* on disk and the next start settles it by probing the
server, so a crash can never lock the agent out.

## What goes over the wire

| Call | Auth | Body |
|---|---|---|
| `POST /v1/fleet/enroll` | token in the body | `{token, hostname, public_key_b64, proof_b64, agent_version, capabilities}` |
| `POST /v1/fleet/{id}/heartbeat` | `X-Agent-Token` | signed envelope, `kind=heartbeat`; the reply lists approved actions |
| `POST /v1/fleet/{id}/posture` | `X-Agent-Token` | signed envelope, `kind=posture`, payload = `paddock.host.posture/v2` |
| `POST /v1/fleet/{id}/keys/rotate` | `X-Agent-Token` | signed envelope, `kind=rotate`, payload = new key + proof |
| `POST /v1/fleet/actions/{id}/result` | `X-Agent-Token` | `{status, output, revert}` |
| `POST /v1/fleet/{id}/inventory` | `X-Agent-Token` | v1 inventory, **unsigned, never evidence** (Fleet page only) |

The envelope is exactly `docs/ASSURANCE_P2.md` section 2 (`paddock_agent/envelope.py`). Deterministic test
vectors the server side can reuse are in `tests/vectors/envelope_v1.json` (regenerate:
`python -m tests.vector_gen --write`; a test fails if the file and the code drift).

**What a signature proves, and what it does not.** A valid envelope proves that the enrolled key sent
exactly these bytes, once, in order, at about `issued_at`. It does **not** prove the host is honest: a
compromised host can sign lies. The server therefore treats agent facts as `configured`, never
`observed`, and a tampered or missing posture means **silence, which is `UNKNOWN`, never a pass**.

Details that matter:

* **Sequence numbers are write-ahead.** `seq` is incremented and fsynced **before** anything is signed or
  sent, so a crash can skip a number but never reuse one. A single counter spans key rotations.
  A server `409 {expected_min}` can only move it *up*.
* **Retries are byte-identical.** An envelope that could not be delivered is queued (gzip, 0600, bounded,
  oldest evicted first) and re-sent unchanged with `Idempotency-Key = seq`; one older than 480 s is dropped
  (the server's window is 600 s) and the next posture replaces it.
* **A collector that crashes sends nothing**; the agent never signs a partial or invented posture, and the
  broken posture does not slow the heartbeat (silence is what the server turns into `UNKNOWN`).
* **Collection is sequential with the heartbeat** (the payload reports the `seq` it will carry, so the
  counter cannot be shared with a concurrent heartbeat). A posture collection can take up to the collectors'
  240 s total budget, so the heartbeat gap can approach 270 s, just under the default `silent_after_s` of 300.
* **No transport error escapes.** DNS, refused, reset, timeout, TLS, malformed replies all become one
  `FleetClientError`; the loop backs off with jitter (5 s doubling, **capped at 300 s**) and carries on.
  Redirects are never followed (credentials never leave for another host).
* **Exit status 7 = re-enrollment required** (`403 re_enroll_required`, or ten consecutive 401/403): the
  daemon stops instead of hammering a server that has refused it.

## State directory (`/var/lib/paddock-agent`, mode 0700, owned by the agent user)

```
keys/ed25519.key       active key (0600)          credentials.json  agent id, tenant id, fat_ token (0600)
keys/ed25519.pending   key being enrolled/rotated seq               write-ahead counter (0600)
outbox/                queued envelopes/results   handled.json      server actions already carried out
quarantine/            quarantined files + the host's own manifest
```

Every secret is written `mkstemp` + `fchmod 0600` + `fsync` + `os.replace`, and **refused on read** if it
is group/world accessible, owned by another user, a symlink, or inside a state directory other users can
write to. Delete the directory and the agent is a different (unenrolled) host.

## Commands

```
paddock enroll [--token-stdin] [--hostname H] [--force]
paddock status | collect [--raw] | posture | rotate-key | inventory [--send] | actions
paddock simulate TYPE TARGET      # DRY-RUN preview of a host-local action
paddock apply ACTION_ID           # apply a SERVER-APPROVED action, after confirmation
paddock run                       # heartbeat + posture loop; carries out approved real actions
```

Exit status: 0 ok, 1 aborted / no posture produced, 2 usage / not enrolled / refused target, 3 refused by a safety rail, 4 apply failed,
5 server error, 6 unusable state directory, 7 re-enrollment required.

## Configuration (environment)

| Var | Default | Meaning |
|-----|---------|---------|
| `PADDOCK_SERVER` | the server recorded at enrollment | orchestrator base URL (`https://`; `http://` only for loopback) |
| `PADDOCK_ENROLL_TOKEN` | none | one-time enrollment token (read once, then removed from the environment) |
| `PADDOCK_STATE_DIR` | `/var/lib/paddock-agent` | state directory |
| `PADDOCK_DRY_RUN` | `true` | force simulate-only; a real apply needs this off |
| `PADDOCK_HEARTBEAT_SEC` | `30` (min 5) | signed heartbeat interval (also the action poll) |
| `PADDOCK_POSTURE_SEC` | `300` (min 60) | signed posture interval |
| `PADDOCK_INVENTORY_SEC` | `3600` (`0` off) | v1 unsigned inventory for the Fleet page |
| `PADDOCK_HTTP_TIMEOUT` | `20` | seconds per request |
| `PADDOCK_OUTBOX_MAX_MB` | `64` | outbox cap; the oldest items are evicted first |
| `PADDOCK_ENABLE_IMDS` | `false` | allow the cloud metadata request (off by default, E6) |
| `PADDOCK_CA_FILE` | system store | CA bundle for a private TLS server |
| `PADDOCK_QUARANTINE_DIR` | `<state>/quarantine` | where quarantined files are moved |
| `PADDOCK_ED25519_BACKEND` | `auto` | `auto`, `pure` or `cryptography` (a forced unavailable backend is an error) |
| `PADDOCK_OPERATOR_TOKEN` | none | operator bearer token for the read-only CLI calls (`status`, `actions`) |

`FLEET_ENROLL_TOKEN` and hostname-upsert enrollment are **gone** (hard cut, owner decision O3). A v1
credential file is rejected on read; v1 agents get `403 re_enroll_required` from the server.

## Safety rails (enforced, not aspirational)

1. **Host-local only.** `actions.assert_host_local` validates and canonicalises every target; there is no
   remote-host parameter anywhere. Control characters, ports outside 1-65535, zone ids, CIDRs and
   newline-injected targets are refused.
2. **Propose, approve, apply.** The agent refuses to apply (or revert) anything whose server status is not
   `approved`.
3. **Dry-run by default.** A real apply requires the server's `dry_run=false` **and** the agent not running
   dry. A dry run simulates, reports nothing and changes no server state.
4. **Audited.** The agent reports results; the orchestrator writes the tamper-evident chain. The agent
   remembers what it already did (`handled.json`), so a lost reply never makes it apply an action twice.
5. **Reversible, and a revert plan is data, not a program** (audit 7.4). The server hands the plan back;
   the old agent ran its argv verbatim (an `rm -rf` plan was demonstrated). Now the Linux enforcer
   recovers the original *typed* action from the plan, re-validates it with the host-local guard, and
   rebuilds the one fixed command, hosts line or move it could have produced. **Anything else is refused
   and nothing runs.** A quarantine restore additionally needs this host's own manifest entry, so the
   server cannot choose where a file lands, and it never overwrites an existing file.
6. **Allowed actions only:** `block_ip`, `block_domain`, `quarantine_file`, `firewall_rule`, `revert`.
7. **IPv6 `block_ip` is refused loudly** (`ipv6_not_supported`): the enforcer drives IPv4 `iptables`, so
   the block would never take effect. Previously this failed silently.

## The systemd unit (one root process, hardened)

The unit file itself ships with WP7 (`scripts/install-agent.sh`); this is the contract it implements
(`docs/ASSURANCE_P2.md` section 8). The enrollment token is **never** in the unit.

```ini
[Unit]
Description=Paddock fleet host agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/paddock run
EnvironmentFile=-/etc/paddock-agent/agent.env     # PADDOCK_SERVER=..., mode 0600
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=7                         # 7 = the server requires re-enrollment: do not spin
StateDirectory=paddock-agent
StateDirectoryMode=0700
# --- sandboxing (docs/ASSURANCE_P2.md section 8) ---
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/paddock-agent
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ProtectKernelTunables=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

Consequences you should know about (not hidden): under `ProtectSystem=strict` only the state directory is
writable, so with this unit **`block_domain` (writes `/etc/hosts`) and `quarantine_file` (moves a file out of
its directory) fail with a read-only filesystem error** and are reported as `failed`; firewall actions use
netlink via `CAP_NET_ADMIN`. Widen `ReadWritePaths=` deliberately if you want those, knowing it widens what a
compromised agent can write. The legacy `iptables` binary may also need `CAP_NET_RAW`, which is not in the
bounding set. Neither was exercised against a real systemd in this repository's tests.

## Container

`Dockerfile` builds an image for trying the agent on a host (host networking, `NET_ADMIN`). Containers are
detected: host-binary facts (sshd binary, listeners' executables) are reported as
`unavailable(containerised_agent)`, i.e. `UNKNOWN`, never as a pass. Give the token on stdin
(`printf %s "$TOKEN" | docker run -i ... paddock enroll --token-stdin`), not with `-e`, which `docker inspect`
shows.

## Tests

```bash
cd agent && pip install -e .[test] && pytest -q && ruff check .
```

The suite includes the RFC 8032 vectors for both signer backends and a byte-identity test between them,
the shared envelope vectors, a fake orchestrator that enforces the contract's server checks in order, the
`rm -rf` revert regression, and a static Python 3.8 gate (`tests/test_py38_core.py`; there is no 3.8
interpreter in CI images here, so 3.8 is checked by AST and a banned-API scan, not by running it).
