# Host agent v2: signed posture for servers

The host agent runs **on a server**, enrolls once with a one-time token and its own Ed25519 key, and then sends
a **signed host posture** (sshd configuration, listening sockets, the firewall model, patch state, its own
health) to Paddock. The assurance engine reads that posture as `configured` evidence and evaluates host
invariants over it. Two ship in the box:

* `std:server-ssh-hardened`: either no SSH server, or no password login, no root login, empty passwords
  refused, public keys on, `MaxAuthTries <= 4`.
* `std:server-default-deny-inbound`: every enabled IP family drops or rejects inbound by default.

This page is the operator's guide. The design, the wire protocol and the decisions behind it are in
[ASSURANCE_P2.md](ASSURANCE_P2.md); the older propose / approve / apply enforcement path is in
[FLEET_WIRING.md](FLEET_WIRING.md).

The agent has **no offensive capability**. It never scans or probes anything, never listens on a port and
talks to one place only: your Paddock orchestrator.

## 1. Quick start

**1. Mint a one-time enrollment token** (admin API key; the token is shown once and only its hash is stored):

```bash
curl -s -X POST "$PADDOCK/v1/fleet/enroll-tokens" -H "Authorization: Bearer $ADMIN_KEY" \
     -H 'content-type: application/json' -d '{"label":"web-1","ttl_minutes":60}'
# -> {"token":"fet_<12 hex>_<secret>", "state":"pending", ...}
```

A token is single use by default. A cloud-init fleet can use `"max_uses": 20, "ttl_minutes": 120`
(at most 50 uses, and a ttl of at most 24 h when `max_uses` > 1). There is no dashboard screen for tokens
in this release: use the API.

**2. Install on the host** (root, Linux with systemd, Python 3.8 or newer). The installer is attached to every
release, pinned to that release's tag, and checked against a signed checksum list:

```bash
TAG=v0.2.0
BASE=https://github.com/brandongraff-dev/paddock/releases/download/$TAG
curl -fsSLO $BASE/install-agent.sh && curl -fsSLO $BASE/SHA256SUMS && curl -fsSLO $BASE/SHA256SUMS.sigstore.json
# verify the installer itself (needs cosign; otherwise compare the digest with the release notes)
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/brandongraff-dev/paddock/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
./install-agent.sh --server https://paddock.example.com --dry-run          # read what it will do
printf %s "$TOKEN" | sudo ./install-agent.sh --server https://paddock.example.com
```

(`printf` is a shell builtin, so the token is not in any process list. Never put it after a command name.)

**3. Check it.** `sudo paddock status` shows the agent id, key id and sequence. In Paddock,
`GET /v1/fleet/agents` lists the host; enable the two standard invariants
(`POST /v1/invariants/std/std:server-ssh-hardened/enable`, same for `std:server-default-deny-inbound`) and the next
evaluation reports one verdict per host. A violation opens a finding titled with the host name.

## 2. What the installer does

`scripts/install-agent.sh` is POSIX `sh` and stops at the first check that fails:

1. Requires root, Linux, systemd and a Python of at least 3.8 (`--dry-run` needs none of that and changes nothing).
2. Downloads `paddock-agent.pyz` and `SHA256SUMS` for the **pinned** tag. There is no "latest": `--version latest`
   is refused.
3. With `cosign` installed it verifies the keyless sigstore bundle over `SHA256SUMS` against this repository's
   release workflow identity and refuses to continue if that fails. Without `cosign` it warns loudly that only
   the checksum from the same release was checked, which does **not** protect against a compromised release.
   `--require-cosign` turns that warning into an error, and `--sha256 <hex>` pins the archive's digest out of band.
4. Checks the archive's sha256, runs `--version` on it, then installs it root-owned to
   `/usr/local/lib/paddock-agent/paddock-agent.pyz` with a `paddock` symlink in `/usr/local/bin`.
5. Writes `/etc/paddock-agent/agent.env` (mode 0600, only `PADDOCK_SERVER=...`) and the systemd unit.
6. Enrolls with the token from `$PADDOCK_ENROLL_TOKEN`, stdin or a hidden prompt, **never from an argument**
   (`--token` is refused and the value is never echoed), and hands it to the agent on stdin.
7. `systemctl enable --now paddock-agent`.

Other options: `--no-enroll`, `--no-start`, `--hostname`, `--reenroll` (with a re-key token), `--prefix`,
`--python`, `--base-url` (a mirror; `https://` or `file://`), `--root DIR` (stage into a directory, touch no
system state). Re-running the installer on an enrolled host keeps its credentials.

`--uninstall` stops and removes the service, unit and archive and **keeps the signing key and credentials**;
`--uninstall --purge --yes` deletes those too. Uninstalling does not revoke the agent on the server: see
section 5.

If you build the archive yourself: `python agent/packaging/build_zipapp.py --out dist/paddock-agent.pyz`
produces byte-identical output on every Python from 3.8 to 3.13.

## 3. What runs on the host

One root process, sandboxed by systemd (`agent/systemd/paddock-agent.service`, written by the installer):

```
User=root                                  Restart=on-failure   RestartPreventExitStatus=7
NoNewPrivileges=yes                        ProtectSystem=strict ProtectHome=yes PrivateTmp=yes
ReadWritePaths=/var/lib/paddock-agent      ProtectKernelTunables=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN
```

* **Collectors** (read-only, pure parsers over command output): `sshd -T` plus a probe matrix for `Match` blocks,
  `/proc/net/*` listeners with process attribution, the firewall (`nft -j list ruleset`, legacy `iptables-save`,
  ufw/firewalld recorded as hints only), package manifest and pending security updates, and the agent's own
  health. Fingerprints, counts and unit names only: **never** command lines, environment, key material or file
  contents. The cloud metadata request is off unless you set `PADDOCK_ENABLE_IMDS=true`.
* **Cadence**: a signed heartbeat every 30 s, a signed posture every 300 s (both configurable). The server
  stores a new posture only when its content changed or at least hourly.
* **State** in `/var/lib/paddock-agent` (0700): the key, the credential, a write-ahead sequence counter and a
  bounded on-disk outbox for when the network is down. Secrets are written atomically, mode 0600, and refused on
  read if anyone else could read or replace them.
* **Exit status 7** means the server told this agent to re-enroll (or refused it ten times in a row). systemd does
  not restart it; see section 5.

Because `ProtectSystem=strict` makes everything but the state directory read-only, the optional enforcement
actions `block_domain` (writes `/etc/hosts`) and `quarantine_file` fail with a read-only error under this unit and
are reported as failed. Firewall actions use netlink. Widen `ReadWritePaths=` only deliberately: it widens what a
compromised agent can write. Enforcement is unchanged from before: dry-run by default, propose then approve then
apply, reversible, audited ([FLEET_WIRING.md](FLEET_WIRING.md)).

## 4. How the evidence is used

A posture that passes the server's checks becomes facts on a node `agent:<uuid>` in the reach graph (or the cloud
instance's own node once the agent's addresses and its peer address prove it is that instance). The invariants
then evaluate each host as true, false or unknown, and a fact is **unusable** (the host reads unknown, never
fine) when it is unsigned, from a revoked key, stale, partial, approximate, from an agent that went silent, below
the invariant's evidence tier, or contradicted by another source.

| Situation | Verdict |
|---|---|
| fresh signed posture, exact collectors, config passes | `HOLDS`, evidence tier `configured` |
| any host fails the predicate | `VIOLATED`, a finding per host |
| host silent more than `silent_after_s` (default 300 s) | `UNKNOWN`; an open finding stays open |
| tampered envelope, bad signature, replay | rejected (401 / 409); the previous posture stays; silence follows if it persists |
| the external scan saw an open port the agent says is closed | `UNKNOWN`, no coverage, a conflict recorded on the host |
| firewall uses ipset, marks, DNAT, Docker publishing, or `sshd -T` could not run | `UNKNOWN` (approximate is never a pass) |
| agent revoked | the host leaves the graph; the selector may be empty, which is `UNKNOWN` |
| a declared `server` with no agent | `UNKNOWN: no_agent` |

Read the stored posture with `GET /v1/fleet/agents/{id}/posture` (analyst role and above; it is audited).
Rejected envelopes are audit rows `fleet.evidence.rejected` with the reason; liveness changes are
`fleet.agent.offline` / `fleet.agent.online`.

## 5. Operating the fleet

**Rotate the key** (routinely, or on any suspicion the key file was read): `sudo paddock rotate-key`. The new key
signs a proof of possession, the current key signs the hand-over, the old key becomes `rotated` and is refused
from then on. If the reply is lost the new key stays pending on disk and the next start settles it.

**A host lost its state** (reinstall, deleted `/var/lib/paddock-agent`): it cannot prove it is the same host, and
a plain token cannot take its hostname over (409, token not spent). An admin mints a **re-key token** for that
agent and the host runs `paddock enroll --force` (or the installer with `--reenroll`):

```bash
curl -s -X POST "$PADDOCK/v1/fleet/enroll-tokens" -H "Authorization: Bearer $ADMIN_KEY" \
     -H 'content-type: application/json' -d '{"for_agent":"<agent uuid>"}'
```

The server revokes the old key with a reason, keeps the agent row and its history, and issues a new credential.
A re-key token minted before the agent was revoked cannot bring a revoked agent back.

**Agents from before this release** (v1, no key) are kept with their history but marked `legacy`: every agent
route answers `403 re_enroll_required`, the old agent stops with exit status 7, and the host needs a re-key token.

**Revoke** (immediate, nothing is cached):

```bash
curl -s -X POST "$PADDOCK/v1/fleet/agents/$ID/revoke" -H "Authorization: Bearer $ADMIN_KEY" -H 'content-type: application/json' -d '{"reason":"host retired"}'
curl -s -X POST "$PADDOCK/v1/fleet/agents/$ID/keys/$KEY_ID/revoke" ...      # one key only; the agent then needs a re-key token
curl -s -X DELETE "$PADDOCK/v1/fleet/enroll-tokens/$TOKEN_ID" ...            # a token that was minted but not used
```

**Limits** (per agent, per minute unless noted; in-process, so multiply by replicas): heartbeat 60, posture 20,
rotate 10/hour, inventory 6; enrollment 20 per client per minute with a lockout after 5 failures in 10 minutes.
Environment overrides: `FLEET_HEARTBEAT_PER_MIN`, `FLEET_POSTURE_PER_MIN`, `FLEET_ROTATE_PER_HOUR`,
`FLEET_INVENTORY_PER_MIN`, `FLEET_ENROLL_PER_MIN`, `FLEET_ENROLL_FAILS`, `FLEET_AGENT_MONITOR_SEC`. Retention:
signed postures 90 days (`RETENTION_AGENT_POSTURE_DAYS`), v1 inventory 30 days (`RETENTION_AGENT_INVENTORY_DAYS`).

**Time**: an envelope is accepted only within 10 minutes of the server's clock (`422` with `server_now`
otherwise). Keep hosts on NTP.

**Troubleshooting**: `journalctl -u paddock-agent`, `sudo paddock status`, `sudo paddock collect` (collect and
print locally, no network). Exit status: 0 ok, 1 no posture produced, 2 usage or not enrolled, 3 safety rail,
4 apply failed, 5 server error, 6 unusable state directory, 7 re-enrollment required.

## 6. Threat model

### What a signature proves, and what it does not

A valid envelope proves that **the holder of enrolled key K for tenant T sent exactly these bytes, once, in
order, at about the time it says**. It proves nothing about the host being honest or uncompromised. Someone with
root on the host holds the key and can sign any posture they like, including a clean one. So:

* Agent facts are tier `configured`, never `observed`, and Paddock never lifts the tier.
* The only independent check is cross-validation: if the agent says a port is closed and the external scan (or
  cloud configuration) saw it open, the host gets no coverage and the verdict is `UNKNOWN`. That catches a lie
  only about what an outside observer can see. A host that lies about its sshd configuration, or about a port the
  scanner cannot reach, is not caught.
* Silence, errors, staleness and partial data are `UNKNOWN`, never a pass.
* A `HOLDS` from this agent means **no counterexample under this evidence**, not that the host is secure.

### Attacks and what happens

| Attack | Outcome |
|---|---|
| Steal an enrollment token before use | The thief can enroll one host as that hostname until the token is revoked or expires. Tokens are single use, short-lived, rate limited, and every failure is the same generic 401. The enrolling key signs a proof bound to the token and hostname. |
| Steal a used token | Worthless: spent. |
| Steal the agent credential (`fat_...`) | Alone it cannot send evidence: every envelope must also be signed by the enrolled key. It is hashed on the server and never logged. |
| Steal the key file | Impersonates that one host until `revoke` or `rotate-key`. The file is 0600 root in a 0700 directory; a copy elsewhere cannot be detected by the server. |
| Man in the middle | The client refuses `http://` to anything but loopback, never follows redirects and validates TLS. A MITM who cannot break TLS sees ciphertext; one who can still cannot forge a signature. |
| Modify a posture in flight | 401 `bad_signature` or 400 digest/length mismatch, an audit row, the previous posture stays, the sequence does not advance. |
| Replay an old envelope | 409 `replayed_seq` (the sequence must increase per key); an identical resend of the last one is a harmless idempotent 200. |
| Send two different payloads under one sequence | 409 `equivocation`, audited. |
| Compromised host signs lies | Not detectable beyond cross-validation (above). Revoke the agent on suspicion. |
| Server-side attacker sends a malicious "revert" or action | Actions are typed and host-local only (no remote target field exists). A revert plan from the server is treated as data: the agent recovers the typed action from it, re-validates it and rebuilds the one command it could have produced; anything else is refused and nothing runs. Real apply additionally needs the server's `dry_run=false` and the agent not in dry-run (the default). |
| Attacker holding only the old key after rotation | 401 `key_not_active`. |
| Another tenant | Every table is row-level-security scoped; an agent token resolves to exactly one tenant and one agent id, and cross-tenant reads return 404. |

### Risk accepted: a network-facing process that holds root (decision O2)

The agent is **one root process that also makes network calls**. A memory-safety or parsing bug in that process
(or in Python, TLS or a parser it uses) would run as root, and a root attacker on a host can also read the key and
sign. Why it is built this way: the collectors need root to read `sshd -T`, other processes' sockets and the
firewall; splitting an unprivileged network client from a root helper is planned for a later release.

What limits it today: standard library only (no third-party code unless `cryptography` is already installed; the
vendored signer is used otherwise), no listening socket, outbound to one server, the sandbox above, and typed
host-local actions behind a human approval gate. What the sandbox does **not** do: `CAP_DAC_READ_SEARCH` lets the
process read any file and `CAP_SYS_PTRACE` lets it inspect other processes, so a compromised agent can read
secrets on the host, and it can write anywhere you add to `ReadWritePaths`. The vendored pure-Python signer is not
constant-time, which matters only to a local attacker timing signatures on the same machine; installing
`cryptography` removes that. None of this was tested under a real systemd and a real attacker in this repository's
tests; see "Not verified" in [ASSURANCE_P2.md](ASSURANCE_P2.md).

## 7. Kill switches

| To stop | Do | Effect |
|---|---|---|
| One host's evidence, now | `POST /v1/fleet/agents/{id}/revoke` | credential and every key refused on the next call; pending re-key tokens revoked; coverage and facts dropped |
| One key | `POST /v1/fleet/agents/{id}/keys/{key_id}/revoke` | that key's evidence refused; the agent needs a re-key token |
| New enrollments | `DELETE /v1/fleet/enroll-tokens/{id}` for each open token (list them with `GET`) | nothing can enroll without a new token; suspending the tenant also refuses enrollment and every agent call |
| The agent on a host | `systemctl disable --now paddock-agent` or `install-agent.sh --uninstall` | nothing is sent; the server sees silence and the host reads `UNKNOWN` after `silent_after_s` |
| Any host change | leave `PADDOCK_DRY_RUN=true` (the default) | the agent only simulates actions |
| Host invariants | `PUT /v1/invariants/{id}` with `enabled: false` on the two std invariants | no verdicts or findings from host evidence |
| The whole assurance loop | `ASSURANCE_ENABLED=false` on the orchestrator | no builds or evaluations at all |

There is no single switch that disables only the `host_fw` builder.

## 8. Known gaps

The full list is in [ASSURANCE_P2.md](ASSURANCE_P2.md) (sections 11 and 13). The ones that matter operationally:
no distro advisory data and no KEV matching (patch state is collected, not judged); Linux only; Debian and RPM
families only for patches; a firewall using ipset, marks, DNAT or Docker publishing stays `UNKNOWN`; a host
without root or without `sshd -T` is `UNKNOWN`; AWS instance identity is matched by address overlap, not verified
cryptographically; RHEL 8's default Python 3.6 is unsupported (install the `python39` module); the rate limits are
per process; and the installer, the unit and a real release have not been run on a live host or a real GitHub
release yet.
