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
release, pinned to that release's tag, and checked against a signed checksum list. A downloaded file is not
executable, so run it through `sh` as below, not by executing the file directly:

```bash
TAG=v0.2.0
BASE=https://github.com/brandongraff-dev/paddock/releases/download/$TAG
curl -fsSLO $BASE/install-agent.sh && curl -fsSLO $BASE/SHA256SUMS && curl -fsSLO $BASE/SHA256SUMS.sigstore.json
# verify the installer itself (needs cosign 2.4 or newer)
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/brandongraff-dev/paddock/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
sh ./install-agent.sh --server https://paddock.example.com --dry-run          # read what it will do
printf %s "$TOKEN" | sudo sh ./install-agent.sh --server https://paddock.example.com --require-cosign
```

(`printf` is a shell builtin, so the token is not in any process list. Never put it after a command name, and do
not write `sudo PADDOCK_ENROLL_TOKEN=... sh ...`: sudo's own command line is visible to every local user.)

**Without cosign on the host** the checksums are only as trustworthy as the download: `SHA256SUMS` comes from
the same release as the archive, and so do the digests printed in the release notes, so neither proves the
release is genuine. `--require-cosign` (used above) is the documented default for that reason: it refuses to
install when cosign is missing. If a host cannot have cosign, either run the `cosign verify-blob` command above
on a machine that has it and pass the digest it vouched for to the host with `--sha256 <hex>`, or rebuild the
archive yourself from the tag (end of section 2) and pin that digest. The release was signed with cosign
2.5.2; use 2.4 or newer to verify (older versions may not read the bundle, and the installer then refuses to
continue rather than skipping the check).

**What the release signature does not prove.** The keyless signature says the `release.yml` of this repository ran
at `refs/tags/<tag>`. It does not prove the tagged commit was reviewed: the workflow that runs is the file in the
tagged commit, so someone who can push a tag could tag a commit that removes the workflow's own `gate` job (it
checks that the tag is on the default branch and runs in the `release` environment). The controls that stop that live in the repository
settings, not in the workflow: a tag ruleset restricting who may create `v*.*.*` tags, required reviewers and a
deployment-tag rule on the `release` environment, and branch protection on the default branch. Until those are
configured, treat a release as trusted only as far as you trust everyone who can push tags.

**Repository settings the owner must apply before the first release.** These are GitHub settings, not code, so
nothing in this repository can enforce them; until every box is ticked, trust a release only as far as you trust
everyone who can push tags. The release workflow (`.github/workflows/release.yml`) has never been run.

- [ ] **Environment `release`** (Settings, Environments): required reviewers (not the person who pushes the tag),
      and a deployment-branches-and-tags rule that allows only the `v*.*.*` tag pattern. The `gate` job runs in
      this environment, so every release job waits for the approval.
- [ ] **Tag ruleset** (Settings, Rules, Rulesets, target: tags, pattern `v*.*.*`): restrict creation, update and
      deletion to the release maintainers, and block force-pushes. This is the control that stops "someone who can
      push a tag" from tagging a commit that deletes the `gate` job.
- [ ] **Branch protection on the default branch**: require pull requests with review and the CI checks, and block
      force-pushes and deletion. The `gate` job refuses a tag whose commit is not on the default branch; that
      only means something while the branch itself is protected.
- [ ] **Actions pinned**: every third-party action is pinned to a commit SHA and cosign to an exact version in
      `release.yml`; keep it that way when refreshing them.
- [ ] After the first release, verify it with `cosign verify-blob` (section 1) and rebuild the archive yourself
      (end of section 2) before telling anyone to install it.

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
   `/usr/local/lib/paddock-agent/paddock-agent.pyz`, after checking that the directories it writes into are
   real directories, owned by the installing user and not world-writable (the ones it creates for itself also
   not group-writable). `/usr/local/bin/paddock` becomes a small wrapper that runs the archive with the
   interpreter the installer verified (not whatever `python3` is first on `PATH`). An existing `paddock` that is
   not ours, such as the Paddock CLI, is **never overwritten**: the installer warns and skips the wrapper, and
   `--uninstall` removes only a `paddock` that is our own wrapper (or the symlink an older installer made).
5. Sets `PADDOCK_SERVER` in `/etc/paddock-agent/agent.env` (mode 0600) and writes the systemd unit. Every other
   line already in `agent.env` (`PADDOCK_CA_FILE`, `PADDOCK_ENABLE_IMDS`, intervals, `PADDOCK_DRY_RUN`, ...) is
   kept, so a re-run does not discard your settings; edit that file, not the unit, to configure the agent.
6. Enrolls with the token from `$PADDOCK_ENROLL_TOKEN`, stdin or a hidden prompt, **never from an argument**
   (`--token` is refused and the value is never echoed), and hands it to the agent on stdin. The token is read
   first, before anything is downloaded or written, so a missing or malformed token leaves the host untouched; a
   token in the environment is removed from it before any other program runs (the installer also unsets any
   `ENV_TOKEN` / `TOKEN` the caller exported, so the token is never re-exported under those names). Ctrl-C or
   SIGTERM at the hidden token prompt gives the terminal its echo back and exits (130 / 143). A token piped
   without a trailing newline (`printf %s`) works.
7. `systemctl enable` then `systemctl restart paddock-agent`, so a re-run is also the upgrade: the running agent
   is restarted onto the new archive and unit (replacing the archive under a live process is never relied on).
   After a short wait the installer checks `systemctl is-active` and exits non-zero, pointing at
   `journalctl -u paddock-agent`, if the service is not up. A crash after that wait is not caught here: look at
   `systemctl status`. With `--no-start`, or when the host is not enrolled, nothing is restarted, and the
   installer warns if an agent is still running the previous version.

Other options: `--no-enroll`, `--no-start`, `--hostname`, `--reenroll` (with a re-key token; the installer stops
the service first, because `enroll --force` refuses while a daemon holds the state directory), `--prefix`,
`--python`, `--base-url` (a mirror; `https://` or `file://`), `--root DIR` (stage into a directory, touch no
system state). Re-running the installer on an enrolled host keeps its credentials.

`--uninstall` stops and removes the service, unit and archive and **keeps the signing key and credentials**;
`--uninstall --purge --yes` deletes those too. Uninstalling does not revoke the agent on the server: see
section 5.

**Rebuild a release yourself** (the check that does not depend on GitHub's copy, or on cosign). The archive is
byte-for-byte reproducible: the same sources give the same bytes on every Python from 3.8 to 3.13, whatever the
time zone, umask or checkout path. The release builds with the constant epoch 1980-01-01 (`315532800`), so from
a checkout of the tag:

```bash
git checkout "$TAG"
SOURCE_DATE_EPOCH=315532800 python3 agent/packaging/build_zipapp.py --out dist/paddock-agent.pyz
sha256sum dist/paddock-agent.pyz                  # must equal the paddock-agent.pyz line of SHA256SUMS
sed "s/^PINNED_TAG=.*/PINNED_TAG=\"$TAG\"/" scripts/install-agent.sh | sha256sum   # the install-agent.sh line
```

Use a clean checkout: the build packs every `.py` under `paddock_agent/`, tracked or not, so an untracked or
generated file changes the digest. Without `SOURCE_DATE_EPOCH=315532800` the build falls back to `$SOURCE_DATE_EPOCH` from your environment if one
is set, so state it explicitly.

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

What the capability set means, exactly: `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` read root-only host state
(`sshd -T`, other processes' sockets); `CAP_NET_ADMIN` lets the agent talk to **nftables over netlink**, which is
all that `nft` and `iptables-nft` need. `CAP_NET_RAW` is deliberately **not** in the set, and the set is the
maximum the process can ever hold. **Legacy iptables (`iptables-legacy`) opens a raw socket and so cannot run
under this unit**: on a host whose firewall lives in legacy iptables tables, the firewall collector cannot read
them, reports the facts as partial and approximate, and `std:server-default-deny-inbound` reads `UNKNOWN` for
that host (never `HOLDS`). This is an **owner decision** (ASSURANCE_P2.md section 8): keeping `CAP_NET_RAW` out of
the bounding set of a root process is worth more than supporting legacy iptables, so those hosts read `UNKNOWN`
rather than getting a wider unit. `block_ip` and `firewall_rule` fail there too, and a legacy `iptables` that has to
create `/run/xtables.lock` also fails because `/run` is read-only under `ProtectSystem=strict`. The fix on such a
host is to move its firewall to nft. If you accept the wider surface (a compromised agent could then open raw
sockets) you can add `CAP_NET_RAW` in a systemd drop-in
(`/etc/systemd/system/paddock-agent.service.d/legacy-iptables.conf` with `CapabilityBoundingSet=` followed by the
four capabilities, and, for the lock file, `ReadWritePaths=/run/xtables.lock` (that path must already exist or the
unit fails to start; create it with `touch` first), then `systemctl daemon-reload && systemctl restart paddock-agent`); that is your decision and
is not tested by this project. Upgrading with the installer rewrites the unit file but not a drop-in.

* **Collectors** (read-only, pure parsers over command output): `sshd -T` plus a probe matrix for `Match` blocks,
  `/proc/net/*` listeners with process attribution, the firewall (`nft -j list ruleset`; legacy `iptables-save`
  only where the unit allows it, see above; ufw/firewalld recorded as hints only), package manifest and pending security updates, and the agent's own
  health. Fingerprints, counts and unit names only: **never** command lines, environment, key material or file
  contents. The cloud metadata request is off unless you set `PADDOCK_ENABLE_IMDS=true`.
* **Cadence**: a signed heartbeat every 30 s, a signed posture every 300 s (both configurable). The server
  stores a new posture only when its content changed or at least hourly.
* **State** in `/var/lib/paddock-agent` (0700): the key, the credential, a write-ahead sequence counter and a
  bounded on-disk outbox for when the network is down. Secrets are written atomically, mode 0600, and refused on
  read if anyone else could read or replace them. Two lock files there (`.instance.lock`, one daemon per state
  directory; `.state.lock`, every read-modify-write of the counter, keys and ledger) let a CLI command such as
  `paddock status` or `rotate-key` run beside the daemon without reusing a sequence number.
  The installer refuses to install through a symlink at `/var/lib/paddock-agent` (and at the archive and config
  directories), because whoever controls the link controls what a root service reads. To keep state on another
  disk use a bind mount (`mount --bind`, or a mount unit) on the real directory instead of a symlink.
* **Exit status 7** means the server said, explicitly, that this agent may not talk to it any more: a JSON answer
  carrying `agent_revoked` or `re_enroll_required`. systemd does not restart it; see section 5. A bare
  401/403/404 (a proxy, WAF or gateway in the way) never ends the agent: it keeps retrying at the capped backoff
  (300 s) and recovers by itself when the server answers again. The other side of that: an agent whose row was
  deleted on the server, behind something that answers a bare 404, never exits by itself and logs an error every
  few minutes until an operator runs `systemctl disable --now paddock-agent`. A host whose agent exited 7 or went
  silent stays in the graph as a tombstone that reads `UNKNOWN`, and its open finding stays open until an
  operator closes it or the host is evaluated `HOLDS` again.

Because `ProtectSystem=strict` makes everything but the state directory read-only, the optional enforcement
actions `block_domain` (writes `/etc/hosts`) and `quarantine_file` fail with a read-only error under this unit and
are reported as failed (a symlinked `/etc/hosts` is written through only when it points at a regular file in
`/etc`; otherwise `block_domain` is refused, never replacing the link with a regular file; a quarantined
setuid/setgid file keeps its bits across filesystems or the quarantine is refused). The firewall actions `block_ip` and `firewall_rule` reach nftables and `iptables-nft` over
netlink (`CAP_NET_ADMIN`) and fail under legacy iptables, see above. Widen `ReadWritePaths=` only deliberately: it
widens what a compromised agent can write. Enforcement is unchanged from before: dry-run by default
(`PADDOCK_DRY_RUN`, true unless you set it to false), propose then approve then apply, reversible, audited
([FLEET_WIRING.md](FLEET_WIRING.md)).

Safety rails the agent applies on the host, whatever the server says:

* **Self-lockout**: `block_ip` is refused for loopback, the unspecified and broadcast addresses, any address the
  server's name resolves to, any address the agent's client actually connected to, and the address of every proxy
  the agent's environment names (`https_proxy`, `http_proxy`, `all_proxy`, either case; `no_proxy` is ignored on
  purpose, refusing more is the safe side). If the server or a proxy cannot be resolved the target cannot be proven
  safe, so IP blocks are refused. `block_domain` is refused for the server's or a proxy's host name;
  `firewall_rule` for outbound traffic to the server's (or a proxy's) port, and to port 53 when the server is a
  name. The action fails with `self_lockout` and nothing is applied.
* **Dead-man timer**: a `block_ip` or `firewall_rule` that is not followed by one successful round trip to the
  server within `PADDOCK_NETBLOCK_DEADMAN_MIN` minutes (default 10, `0` turns it off) is removed by the agent
  itself, so a block that cut the host off cannot last for good. `block_domain` and `quarantine_file` are not
  covered. The removal is written to the local ledger (`handled.json`: `reverted_by: "dead-man timer"`,
  `deadman_reverted_at`, the record rewritten to a failed apply) and logged at ERROR, and the **server is told on
  the next round trip**, through the existing result route and no new one: a `failed` result with
  `output.error = "deadman_reverted"`. It can never be reported as `applied`: a result queued earlier is
  replaced by that truth when it is sent. This only reaches an action the server still holds as `approved`, which
  is exactly the case the timer fires in (the result that would have confirmed the block never got through). If
  that report is lost for good, the server keeps showing the action as approved until the agent next hears it
  offered, and the host's next posture shows the firewall without the rule.
* **Reverts are bound to a local ledger**: the agent reverts only a rule it recorded as applied and not yet
  reverted, and its iptables rules carry a `paddock:<action id>` tag that is probed with `-C` before every insert
  or delete. A revert names its rule by that tag, so two blocks of the same target are reverted independently and in any
  order (each removes exactly its own tagged rule). A revert of a block applied by an older agent uses the stored
  revert plan as the fallback record. If
  `handled.json` in the state directory is lost, the agent cannot revert its blocks: remove them by hand.
  `quarantine_file` needs a real, symlink-free path (`/usr/bin/x`, not `/bin/x` on a merged-usr host).

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
It is safe to run while the service is up: it changes the key under the state-directory lock and signals the
running daemon (SIGHUP), which reloads the new key at once; a daemon that was not signalled reloads it anyway
when its next request is refused with 401, and retries before counting a failure. `paddock enroll --force`
needs the service stopped (`systemctl stop paddock-agent`): it refuses while a daemon holds the state directory.

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
families only for patches; a firewall using ipset, marks, DNAT or Docker publishing stays `UNKNOWN`, and so does
one held in legacy iptables tables (the shipped unit has no `CAP_NET_RAW`, section 3); a host
without root or without `sshd -T` is `UNKNOWN`; AWS instance identity is matched by address overlap, not verified
cryptographically; RHEL 8's default Python 3.6 is unsupported (install the `python39` module); the rate limits are
per process; and the installer, the unit and a real release have not been run on a live host or a real GitHub
release yet.
