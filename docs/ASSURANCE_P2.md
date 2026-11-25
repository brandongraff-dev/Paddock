# Provable Containment, P2: agent v2 for servers

> Status: design contract for P2, built and then hardened after an adversarial review (13.7); sections 0 to 12 were
> corrected after that review where the build now does something else, and section 13 says what shipped, where it
> differs and what is still open. Companion to [ASSURANCE_P1.md](ASSURANCE_P1.md) (the reach graph,
> builders, runner and findings P2 plugs into) and [PROVABLE_CONTAINMENT_MVP.md](PROVABLE_CONTAINMENT_MVP.md)
> section 6. Where documents disagree, **this file wins for P2**. Background research (long, may
> contradict the decisions below) is in the scouting reports: see section 12.

## 0. Decisions

Owner decisions (asked and answered on 2026-11-24):

| # | Decision |
|---|---|
| O1 | **Stdlib-only agent core, Python >= 3.8.** No `httpx`, no `psutil`. Ed25519 signing uses `cryptography` if importable, else a **vendored pure-Python RFC 8032 signer**; both produce byte-identical signatures. |
| O2 | **One root process, hardened.** Read-only collectors run in a single root service under systemd sandboxing. The unprivileged-agent-plus-root-helper split is deferred to P4. Documented risk: a network-facing process holds root. |
| O3 | **Hard cut.** `FLEET_ENROLL_TOKEN` and hostname-upsert re-enrollment are removed. Per-tenant one-time tokens only. Existing v1 agents (no key) are marked `legacy` and get `403 re_enroll_required` on every agent route. Their rows and history are kept. |
| O4 | **`std:kev-patched-within-N` is deferred to P2.1.** P2 collects patch state (so P2.1 has data) but ships no KEV matching and no KEV invariant. |

Engineering decisions (mine; revisit if you disagree):

| # | Decision | Why |
|---|---|---|
| E1 | Host invariants use the **typed field registry + small expression grammar** (MVP doc 3.2/3.3), three-valued (Kleene) logic, **not** a closed `check:` enum. | The predicate is readable in the invariant text and covered by its content digest, which the open verifier (P3) needs. |
| E2 | Agent-signed facts have tier **`configured`**, never `observed`. P2 never lifts a tier. | Signed does not mean true. Corroboration (external scan agrees) is a conflict check, not a promotion. |
| E3 | A managed host is a node `agent:<agent_uuid>` (new ref prefix, kind `host`). The contract allowed it to be replaced by `asset:<cloud uuid>` when **corroborated** (claimed addresses a subset of exactly one AWS instance's private IPs, the server-observed peer one of them, no other agent in the way). **As shipped and hardened, no agent is merged in P2** (`_ipmap.PRIVATE_PEER_IS_PROOF` is `False`): a private source address cannot be told from a header-less NAT or VPN instance that rewrites another machine's address, so the weak proof was switched off (a decision taken in the hardening, not one of O1 to O4 and still open to the owner: 11 item 2; 13.7, area hostfw). The rules stay in the code for the day a trust root exists (a server-verified signed instance identity, or an operator pairing of agent and asset: P2.1). **No new `assets.kind`.** | A new asset kind touches the DB CHECK, `AssetKind`, both SDKs and the dashboard. |
| E4 | Enrollment tokens `fet_<prefix>_<secret>`: single-use by default; optional `max_uses <= 50` with `ttl <= 24h` for cloud-init fleets. Atomic redeem, generic 401, per-IP rate limit and fail lockout (copy `sensors.py`). Prefix is 12 hex. | |
| E5 | Std host invariants: `coverage.require: 1.0`, selector `tag: [agent, server]` (a declared `server` with no agent is `UNKNOWN: no_agent`, never silently out of scope). | A silent server may be the compromised one. |
| E6 | The cloud metadata (IMDS) request is **off by default**, opt-in per agent config. | "No egress beyond the Paddock API." |
| E7 | Install path: signed single-file **zipapp** + `scripts/install-agent.sh` (pins a release tag, verifies sha256, cosign bundle when `cosign` is present). deb/rpm are P2.1. | Needs no repo hosting or key custody. |
| E8 | Posture history is stored **only when the content digest changes or at most hourly**; retention defaults `agent_posture` 90 d, `agent_inventory` 30 d. A changed posture within 300 s of the last insert **overwrites** the newest row instead of adding one (`FLEET_POSTURE_MIN_STORE_S`), and stored bytes are capped per agent (128 MiB, `FLEET_POSTURE_AGENT_MAX_MB`) and per tenant (2 GiB, `FLEET_POSTURE_TENANT_MAX_MB`; v1 inventory 512 MiB, `FLEET_INVENTORY_TENANT_MAX_MB`), oldest first, never an agent's newest row. The per-agent caps are exact; the tenant-wide byte check runs at most once per tenant per `FLEET_TENANT_EVICT_EVERY_S` (60 s) per process, so the tenant caps are soft by one interval. | Bounded growth, also against a valid key that changes one signed field on every post. |

Out of scope for P2: KEV matching (O4), accounts/FIM/egress/containers/persistence/platform collectors
(P2.1), Windows/macOS, enforcement changes beyond the safety fix in 7.4 (P4), the privilege split (P4),
attestation (P3), dashboard pages, AWS instance-identity-document verification, Alpine/SUSE patch state.

## 1. Evidence model (what a signature does and does not prove)

A valid envelope proves: enrolled agent key `K` (tenant `T`) sent exactly these bytes, once, in order,
at about `issued_at`. It does **not** prove the host is honest. Compromised hosts can sign lies, so:

* facts are `configured`, never `observed` (E2);
* a host whose agent says "port closed" while the external scan connected is a **conflict**: the node gets
  no coverage and the evaluation is `UNKNOWN` (never a pass);
* silence (`now - last_seen > silent_after_s`) drops coverage and facts: `UNKNOWN`;
* unsigned, unusable, stale, partial, or `approximate` data is never `HOLDS`.

## 2. Wire protocol

New routes (all agent routes require the **agent principal**, section 6):

| Route | Auth | Body |
|---|---|---|
| `POST /v1/fleet/enroll` | public; handler authenticates the `fet_` token | `{token, hostname, public_key_b64, proof_b64, agent_version, capabilities?}` -> `{agent_id, agent_token, key_id, server_time}` |
| `POST /v1/fleet/{agent_id}/heartbeat` | agent principal | signed envelope, `kind=heartbeat`, tiny payload |
| `POST /v1/fleet/{agent_id}/posture` | agent principal | signed envelope, `kind=posture` |
| `POST /v1/fleet/{agent_id}/keys/rotate` | agent principal | envelope signed by the current key carrying the new key + proof |
| `POST /v1/fleet/actions/{id}/result` | agent principal | unchanged contract, now principal-bound |
| `POST/GET/DELETE /v1/fleet/enroll-tokens[/{id}]` | admin (explicit GET rule) | mint (token shown once), list (prefix only), revoke |
| `POST /v1/fleet/agents/{id}/revoke`, `POST /v1/fleet/agents/{id}/keys/{key_id}/revoke` | admin | `{reason}`; the agent revoke is THE incident action and also revokes the multi-use enrollment token the agent came from unless `revoke_enroll_token=false`; revoking a ROTATED key whose successor is still active needs `successors="revoke"` (the whole chain) or `"keep"`, otherwise 409 and nothing changes |
| `GET /v1/fleet/agents/{id}/posture` | `triage` | full latest posture (the summary `GET /agents/{id}` stays viewer-safe) |

The v1 `POST /v1/fleet/{id}/inventory` route and `InventoryIn` (`extra="forbid"`) stay for the
Fleet page but are only accepted from non-legacy, non-revoked agents that still hold an ACTIVE signing key (a revoked
key cuts the bearer's unsigned routes too, and so the action-result route) and are marked `unsigned`: never evidence.
**The route itself stays unsigned: the shipped agent sends it bearer-only, and requiring a signature or dropping it is
an owner and contract decision that is still open (13.7).** It is bounded instead: a body of at most 2 MiB, an
inventory identical to the newest one only refreshes it, the newest 5 per agent are kept, a per-tenant byte cap
(`FLEET_INVENTORY_TENANT_MAX_MB`, 512 MiB) applies, and a body holding U+0000 or a lone surrogate (Postgres `jsonb`
cannot store them) is a 422. The same 422 applies to action-result bodies.

**Envelope v1** (JSON body, optional gzip; `Content-Type: application/json`):

```
{ "v":1, "alg":"ed25519", "kid":"<hex(sha256(pub32))[:32]>", "agent_id":"<uuid>", "tenant_id":"<uuid>",
  "kind":"posture|heartbeat", "seq":<uint 1..2^53-1>, "issued_at":"YYYY-MM-DDTHH:MM:SSZ", "nonce":"<b64url 16B>",
  "payload_type":"paddock.host.posture/v2", "payload_sha256":"<hex>", "payload_len":<int>,
  "collectors":{"agent":"0.2.0","sshd":"1","listeners":"1","firewall":"1","patch":"1","self":"1"},
  "payload_b64":"<b64url of the exact payload bytes>", "sig":"<b64url 64B>" }
```

* **Signing input** = `b"paddock-agent-envelope/v1\n" + canon(header)` where `header` is every field **except**
  `payload_b64` and `sig`; `canon(x) = json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=False,
  allow_nan=False).encode("utf-8")`. **No floats anywhere in the header or payload** (ints, strings, bools,
  lists, objects only). The stdlib form equals RFC 8785 (JCS) **only for the restricted inputs the protocol allows**,
  and both sides now enforce those restrictions: `seq` and every header integer stay within 2^53-1 (`MAX_SEQ`
  in `fleet_posture.py`; the agent never emits more), `collectors` keys match `[a-z0-9_.-]{1,64}` (so key order is
  never an astral-plane code-point-versus-UTF-16 question), and strings carry no control character or lone surrogate
  (a 400, never an unaudited 500). A P3 verifier may therefore use any RFC 8785 implementation on a header the
  server accepted; the claim is not true for arbitrary JSON. The payload is bound by
  `payload_sha256` over the decoded bytes; the server never re-serialises it.
* **Server checks, in this order, each failing closed with its own code and (see the audit rule below) an audit row
  `fleet.evidence.rejected` (reason, key_id, seq) inside the agent's tenant context:** 1 body size
  (gzip <= 1 MiB, inflated <= 4 MiB, payload <= 2 MiB, header <= 2 KiB, JSON depth <= 16) -> 413; 2 strict
  JSON parse (no duplicate keys), required fields/types, `v == 1` -> 400; 3 agent lookup by path id, active,
  not `legacy`, header `tenant_id` equals the row's -> 403/404; 4 `kid` is an `active` key of this agent with
  `alg == "ed25519"` -> 401; 5 payload b64 decode, `len` and `sha256` match -> 400; 6 signature verify -> 401;
  7 clock `|now - issued_at| <= 600 s` -> 422 with `server_now`; 8 **atomic seq claim**
  `UPDATE fleet_agent_keys SET last_seq=$s WHERE key_id=$k AND status='active' AND last_seq < $s RETURNING`
  (0 rows: identical `(kid, seq, sha)` is an idempotent 200, otherwise 409 with `expected_min`; equal seq with a
  different digest is an equivocation event); 9 payload schema (Pydantic `extra=forbid`, per-collector caps) -> 422;
  10 persist, in one transaction with step 8. **The signature is verified before any DB write and `seq`
  never advances on a failed signature.** A rejected envelope leaves the previous accepted posture in place, so
  tampering becomes silence, hence `UNKNOWN`.
* **Rate limits (as built; all in-process, so N replicas allow N times each limit).** (a) Pre-auth: a slot per
  (agent, strict peer address) is taken atomically when the request arrives and given back once the signature
  verified, so what stays in the bucket is the unverified requests: 30 per minute (`FLEET_PREAUTH_FAILS_PER_MIN`),
  then a 429 before any body is read. A holder of the bearer without the key burns only its own (agent, address)
  bucket. (b) The per-agent budget (heartbeat 60/min, posture 20/min, rotate 10/h) is charged only for an ACCEPTED
  envelope (signature verified, `issued_at` inside the window, fresh seq); a 429 there rolls the seq claim back.
  (c) Validly signed envelopes that make no progress (replay, superseded seq, idempotent resend, stale `issued_at`)
  are charged to a separate per-agent replay bucket (`FLEET_REPLAY_PER_MIN`, default 60) and over it get a 429, so a
  captured envelope can never use up the real agent's budget. The "strict peer" is `auth.client_ip_strict`:
  the socket peer, or, only when that peer is in `TRUSTED_PROXY_CIDRS`, the Nth `X-Forwarded-For` entry from the right
  (`TRUSTED_PROXY_HOPS`, all header lines joined); never the forgeable leftmost entry.
* **Audit rule.** Rejections of envelopes whose signature did **not** verify are sampled: per agent and reason at most
  3 rows per minute and per agent 10 (`FLEET_REJECT_AUDIT_PER_REASON_PER_MIN`, `FLEET_REJECT_AUDIT_PER_AGENT_PER_MIN`);
  the next written row carries `suppressed_before`, and `fleet_agents.rejected_total` stays exact. Rejections of
  signature-verified envelopes (equivocation, replayed seq, clock skew, payload errors) are never sampled out:
  their rate is bounded by (b) and (c). A 429 is not an evidence rejection: it is folded into one
  `fleet.evidence.throttled` aggregate row per agent per minute. A heartbeat or posture request whose rejection the
  handler folded into a counter or aggregate gets no extra per-request middleware row (`request.state.audit_aggregated`
  in `auth.py`, data-plane paths only); a rejection with its own `fleet.evidence.rejected` row still also gets the
  middleware row. Measured: 300 garbage requests add at most about 40 audit rows in total.
* Agent seq is persisted **write-ahead** (fsync before sending N). A wiped state dir means re-enrollment with a
  new token and key on the same agent row (old key revoked with a reason, history kept).
* Rotation: agent generates `K2`, posts `rotate` signed by `K1` with `K2` + proof-of-possession; `K1` becomes
  `rotated`. Admin revoke sets `revoked` immediately; nothing is cached. Revoking a `rotated` key does not revoke its
  successor unless the call says `successors=revoke` (13.7, wire-7). Revoking an agent (or its active key) also stops
  the bearer's unsigned routes: every agent route needs an active key (13.7, enroll-4).
* Enrollment `proof_b64` = signature by the new key over `b"paddock-enroll/v1\n" + token_prefix + "\n" + hostname`.
  A hostname matches `[A-Za-z0-9._:-]{1,253}` as a whole (a trailing newline is not a distinct name). The enrollment
  limiters (20 per client per minute, lockout after 5 failures in 10 minutes) key on the strict peer address, not the
  leftmost `X-Forwarded-For`; sensor enrollment (`routers/sensors.py`) still has the old pattern. Caps:
  `FLEET_MAX_AGENTS_PER_TENANT` (10000) bounds ACTIVE agents; `FLEET_MAX_AGENT_ROWS_PER_TENANT` (default 10 times
  that) bounds all rows including revoked ones, which nothing deletes (see tombstones, 7.1); both refusals are a 403
  that does not spend the token, and re-keying an existing agent is exempt. A long-lived autoscaling tenant therefore
  needs the knob raised eventually; there is no owner-approved purge of revoked rows. Revoking an agent also revokes its
  pending re-key tokens, and by default the multi-use fleet token it enrolled with.

## 3. Schema (`schema/041_agent_v2.sql`)

Declare `tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'` and put it in every UNIQUE
(099 then fixes default/FK/RLS). Sweep-generator traps: no NOT NULL column without a default that carries a
length/regex/format CHECK; extra `FOR SELECT` lookup policies named in `EXTRA_POLICIES`; the token prefix's global
UNIQUE named in `GLOBAL_UNIQUE_OK`.

* `fleet_enroll_tokens(id, tenant_id, token_prefix UNIQUE, token_hash, label, labels JSONB, max_uses INT DEFAULT 1
  CHECK (max_uses BETWEEN 1 AND 50), uses INT DEFAULT 0, for_agent UUID, created_by, created_at, expires_at,
  revoked_at, revoked_by)` + policy `fleet_token_auth_lookup`.
* `fleet_agent_keys(id, tenant_id, agent_id UUID, key_id TEXT, public_key BYTEA DEFAULT '', alg TEXT DEFAULT 'ed25519'
  CHECK (alg IN ('ed25519')), status TEXT DEFAULT 'active' CHECK (status IN ('active','rotated','revoked')),
  last_seq BIGINT DEFAULT 0, created_at, retired_at, revoked_at, revoke_reason, UNIQUE (tenant_id, key_id))`.
* `ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS`: `silent_after_s INT DEFAULT 300 CHECK (silent_after_s BETWEEN
  30 AND 86400)`, `online BOOL DEFAULT TRUE`, `offline_since`, `identity JSONB DEFAULT '{}'` (hostname, ips,
  `machine_id_hash`, `basis` claimed|corroborated), `node_ref TEXT`, `legacy BOOL DEFAULT FALSE`, `revoked_at`,
  `revoked_by`, `rejected_total BIGINT DEFAULT 0`, `last_posture_at`, `last_posture_seq BIGINT DEFAULT 0`;
  then `UPDATE fleet_agents SET legacy = TRUE WHERE NOT EXISTS (SELECT 1 FROM fleet_agent_keys ...)` (O3);
  policy `fleet_agent_auth_lookup` (FOR SELECT, `app.auth_lookup = 'on'`) so the agent principal resolves by token
  prefix across tenants.
* `agent_posture(id, tenant_id, agent_id, key_id, seq BIGINT, schema_version INT, collected_at, received_at,
  header JSONB, payload_raw BYTEA DEFAULT '', payload_sha256, signature, signed BOOL DEFAULT TRUE, size_bytes INT,
  UNIQUE (tenant_id, agent_id, key_id, seq))` (raw bytes kept so the signature stays re-verifiable by P3).
* `reach_node_facts(id, tenant_id, node_ref, source, tier CHECK (...), observed_at, digest, facts JSONB,
  UNIQUE (tenant_id, node_ref, source))`: compact (about 1 KB) values the invariants read.
* Retention defaults for `agent_inventory` (30 d) and `agent_posture` (90 d) in `retention.py`.

## 4. Collectors (agent side, `agent/paddock_agent/collectors/`)

Every collector is `collect(ctx) -> Section`; every parser is a **pure function over text** so fixtures drive it
with no OS. A `Section` is one of `{"s":"ok","v":{...},"conf":"exact|approximate","partial":false}`,
`{"s":"unavailable","reason":"tool_missing|permission_denied|not_applicable|unsupported_platform|daemon_not_running|unmanaged_kernel|containerised_agent|no_data"}`,
`{"s":"error","reason":"timeout|exit_nonzero|parse_error|truncated|exception","detail":"<=120 chars"}`.
Evaluator mapping: `ok` => evaluate; `unavailable(not_applicable)` => N/A; anything else => `UNKNOWN`. Never emit an
empty `ok` on failure. The probe runner returns `{rc, out, err_tail, timed_out, missing, truncated}` (fixed PATH,
`LC_ALL=C`, `shell=False`, stdin devnull, output cap, process-group kill on timeout); `_safe_run` stays only for v1.
Deterministic output (sorted keys/lists, no floats). Python 3.8 syntax only (no `X | Y` at runtime, no `list[str]` in
runtime positions, no `removeprefix`, `fromisoformat` of `Z`).

P2 collectors (spec detail: `collectors` scouting report, section "Collector specs"):

1. **runner/base/ctx** (tri-state results, budgets, caps).
2. **sshd**: locate sshd; `sshd -T` plus a probe matrix `-C user=U,host=probe.invalid,addr=A` (U in {root, up to 20
   login users, a nonexistent user}; A in {203.0.113.7, 10.255.255.1}) recorded as **deltas**; allowlisted keys
   only (`passwordauthentication`, `kbdinteractiveauthentication`, `permitrootlogin` normalising `without-password`,
   `pubkeyauthentication`, `permitemptypasswords`, `authenticationmethods`, `usepam`, `port`, `listenaddress`,
   `allowusers/groups`, `maxauthtries`, ...); config file digests; Match-block criteria seen (`match_unprobed`
   => `conf: approximate`); non-root or failure falls back to a text parse of `sshd_config` + `Include`s with
   `conf: approximate, source: text`, **which never yields HOLDS**. As hardened, `sshd -T` describes the files on
   disk, and an always-present `daemon` block (`found, masters, pid, start_epoch, reexec_epoch, config_path,
   config_default, options_override, binary_matches, config_mtime, reload_pending`) is the only evidence about the
   running daemon; a config value cut by the collector is listed in an optional `truncated` (that key is Unknown);
   the probe matrix adds one probe user per distinct selection class for `Match User/Group` (13.7, coll-1).
   `unavailable(tool_missing)` is **not** a claim that there is no SSH server: it is returned only when no trusted
   OpenSSH `sshd` exists, no ssh/dropbear evidence is present and every non-loopback TCP listener belongs to a short
   allow-list of known non-SSH programs; any other public listener gives `no_data`. Full field list:
   `agent/PAYLOAD.md`.
3. **listeners**: stdlib `/proc/net/{tcp,tcp6,udp,udp6}` (hex addresses decoded by `sys.byteorder`; TCP LISTEN `0A`; UDP bound
   `07`), inode -> pid via `/proc/*/fd`, per listener `proto, ip, port, bind_class, uid, pid, comm, exe (+deleted
   flag), exe_sha256 (cache by dev/inode/mtime, cap 128 MiB), unit or container id (cgroup)`. Never record argv.
   Cap 2000 distinct listeners: past it the section is `ok`, `partial`, a prioritised sample (wildcard and
   privileged first, loopback last) with `dropped` saying how many were cut, not `error(truncated)`; the pid
   attribution scan stops near the collector budget and also ends `partial`. Containerised agent =>
   `unavailable(containerised_agent)` for host-binary facts.
4. **firewall + `fwmodel.py`**: source of truth `nft -j list ruleset` (also covers iptables-nft) plus legacy
   `iptables-save`/`ip6tables-save`; ufw/firewalld recorded as `frontends` only. Normalise to the canonical model
   `{v, backend, frontends[], ipv6_enabled, families:{ip4,ip6}:{chains[{name,hook,prio,policy,base,rules[{m:{iif,oif,
   src[],dst[],proto,sport,dport,ct}, v:"accept|drop|reject|jump:|goto:|return|opaque", opaque_reason}]}],
   effective_default}, flat_view:{default_input_policy, rules[], confidence}}`. `effective_default` walks every
   input-hook base chain treating every conditional rule as no-match (drop/reject if **any** base chain yields it,
   else `unknown`). **`confidence` is `exact` only if every traversed rule uses supported matchers** (iif/oif, CIDRs,
   proto, port set/range, ct state, jump/goto depth <= 8, accept/drop/reject/return); ipset, mark, ct helper,
   owner, recent, limit, geoip, physdev, tcp flags, dynamic/map sets, DNAT/REDIRECT, NFQUEUE, TPROXY make a rule
   `opaque` => `approximate`; unreadable/unparseable or K8s/eBPF dataplane => `unknown`. Non-root =>
   `unavailable(permission_denied)`. Cap 2000 rules (over => `error(truncated)`). As hardened: `reject with
   icmp`/`icmpv6` and `meta nfproto` apply to one family only; a chain with any `return` (or a `goto` into one that
   may return) never counts as always terminating, so a policy-accept base chain with a conditional `return` gives
   `effective_default: unknown`, not `drop`; `ipv6_enabled` comes from `/proc/net/if_inet6` (unreadable or garbled
   means unknown, not "IPv6 off"); the model walk is bounded (400000 rule visits, over it `error(truncated)`).
   **Known limit:** `nft -j` prints `ip6 nexthdr tcp tcp dport 22 drop` exactly like `meta l4proto tcp tcp dport 22
   drop`, but the kernel checks only the immediate next header, so IPv6 packets with extension headers bypass it; the
   model reports a definite IPv6 tcp/22 deny. Legacy `iptables-save` is only readable with `CAP_NET_RAW`, which the
   shipped unit does not grant (section 8).
5. **patch (lite, O4)**: `/etc/os-release` identity; package manifest (dpkg `${binary:Package}\t${Version}\t${Architecture}
   \t${db:Status-Abbrev}\t${source:Package}\t${source:Version}`, rpm with epoch/release/arch/sourcerpm; truncation =>
   `error(truncated)`, never a silent cut); manifest **digest sent every time, full list only when it changes**;
   pending security updates (apt `-s dist-upgrade` parsing the `-security` suite, `dnf -C updateinfo list
   --security`); auto-update state; running kernel and reboot-required (`/var/run/reboot-required`,
   `needs-restarting -r`). No matching, no verdicts.
6. **self-health**: agent/python version, per-collector `{status, ms, reason}`, CapEff, `boot_id`, salted
   `machine_id_hash` (never the raw id), uptime, `seq`, `key_id`, payload bytes, `clock_skew_ms` (server `Date`
   header minus local time, RTT-corrected). Sent even when collectors fail so the server can tell a collector
   error (field-level `UNKNOWN`) from agent silence (everything `UNKNOWN`).

Redaction: fingerprints, counts, exe path + sha256, unit names only; never argv, env, key material, file
contents. Server side re-validates with `extra=forbid` per-collector Pydantic models and caps.

## 5. Library: host-config invariants (`assurance/`)

`assert:` may be a literal (as today) or a mapping `{all|any|not|<predicate>}` (HOSTCONFIG). `subjects.to` selects
hosts (reuses `Selector`); `from`, `ports`, `allow`, `via` are forbidden. The predicate language: hand-written
tokenizer (no `eval`, no regex backtracking), <= 200 chars/predicate, depth <= 6, <= 64 leaves;
`pred := path OP literal | path 'in' list | path 'subset_of' list | 'count(' path ')' CMP INT`; types
str(case-insensitive), int, bool, set<str>, set<cidr>; operators `== != < <= > >= in subset_of`. A typed **registry**
(name, params, type, collector, max_tier, absent semantics) type-checks fields, params (ports 1-65535) and rejects
`min_tier` above a field's reachable tier. Canonical form is structured (sorted children, collapsed singletons) so
the digest ignores whitespace/order and changes with any field, param, operator, literal or `not`.

Facts live in the graph document at `nodes[].facts.<collector> = {status, tier, observed_at, signed, source, key_id,
seq, evidence_ref, conflict?, data}`; `Node.host: HostFacts` (frozen); caps (<= 16 collectors/node, rows <= 5000).

* **Three-valued logic (Kleene strong).** `all`: F dominates, else U, else T. `any`: T dominates, else U, else F.
  `not` swaps T/F, U stays. A leaf is `U` unless its collector fact is **usable**: `status == ok` AND `signed` AND
  `tier >= min_tier` AND fresh AND no `conflict` AND `conf == exact` where the field needs it AND the accessor
  produced a value. **An unusable fact never becomes F** (a stale violating value is `U`; the open finding stays open).
* Per host T/F/U, then: `VIOLATED` if any host F; else `UNKNOWN` (`hosts_unknown:<n>`) if any U (a std invariant
  has `coverage.require = 1.0`; a lower custom floor may let `HOLDS` stand when passing/selected >= require, unknown
  hosts listed as blind spots); else `HOLDS`. Empty selector = `UNKNOWN: empty_selector:to`. A host-config result
  also carries `passing_targets` (the hosts it found definitely passing, capped at 5000, `passing_truncated` says
  when the cap bit) and `unproven_targets` (the UNKNOWN ones); findings sync closes a host's finding only if the
  host is in `passing_targets` (7.2).
* Witness: hop-less, fixed all-string `detail` keys `node, field, clause, predicate, op, expected, observed, tier,
  observed_at, source, signed, key_id, seq, evidence_ref`; <= 3 per host, <= 50 total. `BlindSpot.direction` gains
  `host` plus an optional `collector`.
* `HOLDS` tier = min over facts relied on; `valid_until` = min(observed_at) + max_age.
* Derived registry fields (computed by the library, so the std predicates stay short and auditable):
  `host.sshd.password_login_possible` (true if `passwordauthentication yes`, or `kbdinteractiveauthentication yes`
  with `usepam yes` and no public-key-only `authenticationmethods`; any Match probe delta counts),
  `host.sshd.root_login_possible`, `host.fw.default_inbound_all_families` (`deny` only if every enabled family's
  `effective_default` is drop/reject **and** `confidence == exact`; ip6 with policy accept while IPv6 is enabled
  => `allow`).

As hardened (each is in `hostfields.py` / `hostconfig.py`, except the `Match User/Group` matcher and the NSS rules, which are in the agent's `collectors/sshd.py`; the wording is what the code decides, not a plan):

* **The running daemon needs positive evidence.** `sshd -T` describes the files on disk; `v.daemon` is the only
  evidence about what runs. A config claim (every `host.sshd.*` config field) is usable only if, for a running master:
  `found` true, `masters == 1`, `config_default` true, `options_override` false, `binary_matches` true and
  `reload_pending` false. A null flag is not evidence (it reads Unknown `approximate`: the agent emits null when
  `/proc/<pid>/cmdline` or `/exe` is unreadable); an explicit difference reads `daemon_differs`; `reload_pending`
  true reads `reload_pending`. With no master daemon only socket activation is accepted (`found` false, `masters` 0,
  `reload_pending` false). So an agent that cannot read `/proc/<pid>/exe` or `cmdline` (not root, `hidepid`), a
  stopped sshd, or one whose `reload_pending` is null reads UNKNOWN for every sshd config invariant. `reload_pending`
  also accounts for the change time (mtime and ctime) of `sshd_config`, every `Include`d file and directory and every
  symlink on those paths, and for `-f`/`-o`/`-p`/`-g`/`-h`/`-c`/`-4`/`-6` on the daemon's command line. A reload that
  does not rewrite the pid file keeps it true until restart (over-conservative, never a false HOLDS).
* **Per-variant scalars.** A leaf over a key a `Match` block changes is a universal claim over the base config and
  every probed variant: True if every variant satisfies it, False (a *witnessed* False, only a False in that variant)
  if some variant does not. `all` is False on any False child; an `any` with two witnessed-False children is UNKNOWN
  (`match_override`), because they may fail in different variants; an `any` with one witnessed child and children
  that are False in every variant (`installed == false`) is False. Never under `not`. Not decided (UNKNOWN, safe): an
  `any` whose variant-dependent branches pass in different variants (would be HOLDS) or all fail in the same variant
  (would be VIOLATED).
* **Lists, cuts, keys.** An absent `allowusers`/`allowgroups` is Unknown (`unrestricted`), never the empty set (the
  `_set` booleans say whether it is configured); a list with `*`, `?` or `!` entries is a pattern list, not a set of
  names, and is Unknown too. A key named in `v.truncated` (matched case-insensitively), a list exactly as long as its
  cap and an `authenticationmethods` as long as its cap are Unknown. A `v.config` or probe-delta key that is not
  lower case, is the alias `challengeresponseauthentication` or is outside the library's `SSHD_KEYS` makes the whole
  sshd fact approximate (keep `SSHD_KEYS` in step with the agent's allow-list: a new agent key the library does not
  list degrades hosts to UNKNOWN, safe and visible). `Match User/Group` patterns are matched in linear time with
  bounds (list 1024 characters, name 256, 200000 steps); over a bound the section is approximate (`user_pattern`).
* **`host.sshd.installed == false`** needs `tool_missing` plus a usable (signed, fresh, no conflict), complete,
  fully attributed listener table in which every public TCP listener belongs to the allow-list of known non-SSH
  programs (`NON_SSH_COMMS`); a row on port 22, a row whose port is not an integer, or a name containing `ssh` or
  `dropbear` in any case vetoes it. Anything less is UNKNOWN.
* **Witness text.** The free text of a host (`authenticationmethods`, set elements, process names) is shown in
  `detail.observed` restricted to `[A-Za-z0-9._:/@,?-]`, `?` marking what was not shown, at most 120 characters.
* `ReachGraph.from_json` and `from_file` only ever raise `GraphError`: size, nesting depth (a linear pre-scan; an
  unterminated string is a `GraphError`), duplicate keys, non-finite numbers and over-long integers are refused.

Std invariants shipped in P2 (`stdlib/*.yaml`; baseline is digest-bound, so changing it is a new version). The
title and description of `std:server-ssh-hardened` were reworded after the review to say what it checks ("no root
login by password"; root key login is allowed); the predicate is unchanged:

```yaml
id: std:server-ssh-hardened     # severity high; selector tag [agent, server]; min_tier configured; max_age 6h; coverage 1.0
assert:
  any:
    - host.sshd.installed == false
    - all:
        - host.sshd.password_login_possible == false
        - host.sshd.root_login_possible == false
        - host.sshd.permitemptypasswords == "no"
        - host.sshd.pubkeyauthentication == "yes"
        - host.sshd.maxauthtries <= 4
```

```yaml
id: std:server-default-deny-inbound   # severity high; same selector/tier/age/coverage
assert: host.fw.default_inbound_all_families == "deny"
```

Tests: a brute-force oracle (independent predicate evaluator) over random fact tables, truth tables for Kleene
logic, order invariance, "a violating host always beats an unknown host", "stale/unsigned/approximate is never
HOLDS", digest sensitivity, and mutation checks (flip a Kleene rule; drop the `signed` requirement).

## 6. Server: ingest, principal, RBAC (`orchestrator/app/`)

* `auth.resolve_principal` gains a branch for `X-Agent-Token` (`fat_`): look up `fleet_agents` by `token_prefix`
  under `auth_lookup`, check sha256 (constant time), status, not `legacy`, tenant status; return
  `Principal(kind="agent", capabilities=frozenset({"agent"}), tenant_id=row.tenant_id, agent_id=row.id)`.
  `"agent"` is **not** a role and never appears in `ROLE_CAPABILITIES` or `_VALID_SCOPES`. Handlers assert the
  principal's `agent_id` equals the path id. Rules (appended **near the sensors block** to minimise merge friction,
  anchored UUID patterns so they cannot shadow `/v1/fleet/actions/...`): heartbeat/posture/rotate/result need
  `agent`; enroll public (None); enroll-tokens, revoke admin (explicit `GET /v1/fleet/enroll-tokens` rule);
  posture read `triage`. Extend the write-ahead-audit data-plane exemption (`_SENSOR_DATA_PLANE`) to heartbeat and
  posture; 4xx stay audited, except a rejection the handler folded into the counter or the per-minute aggregate (2,
  audit rule), which gets no second per-request row. Rotate, the wrong-agent 403 and a garbage bearer are outside that
  and still get one middleware row each (13.4 item 9). Every agent route also needs an ACTIVE signing key, not just a
  valid bearer. This also fixes the existing enforce-mode bug (fleet routes were admin-gated, so agents
  could not work outside dev mode or outside the default tenant).
* `app/fleet_enroll.py` (token mint/redeem/revoke, ported from `sensors.py`), `app/fleet_posture.py` (verify, seq
  claim, digest dedupe, store, audit rejections, `last_seen`, `reach_node_facts` write is the **builder's** job,
  not ingest's), changed digest => `assurance_state.last_build_at = NULL` so the runner rebuilds within a tick.
* `fleet_agents.node_ref` and identity: set at enroll/posture. `peer_ip` is the strict peer (2) and
  `peer_proxied` records that the address may be a forwarding hop (the request carried `x-forwarded-for`, `forwarded`,
  `x-real-ip`, `via` or `x-forwarded-proto/host/port` from a peer that is not a trusted proxy; or the peer is a trusted
  proxy with no usable chain; or the reported client lies inside the trusted range; a non-`ClientAddr` address counts
  as proxied). `node_ref` is `agent:<uuid>` for every agent in P2: `_ipmap.corroborate` decides, one function for the
  ingest and the builder, and with `PRIVATE_PEER_IS_PROOF` off a claim that would have passed stays `claimed` (note
  `peer_address_not_proof`). Two agents claiming one cloud node, or sharing one peer address, would merge neither (notes
  `ambiguous_cloud_node`, `shared_peer_address`); `peer_address_not_instance` and `peer_not_direct` are the other notes.
  The Helm chart ships `trustedProxyCidrs` empty, so a request that reaches the orchestrator through an ingress that adds
  `X-Forwarded-For` reads as proxied (`peer_not_direct`), and the audit log and the enrollment limiters see the ingress
  address; to trust one, list the ingress addresses ONLY (never a whole RFC1918 range) and keep `trustedProxyHops` equal to the
  number of appending proxies.
* Gating: enrollment, posture ingest and the `host_fw` build are free (Community); evaluation and std-invariant
  enablement stay under the existing `assurance` Team feature (no new FEATURES entry).
* Monitor: `fleet_agent_monitor_loop` (copy of `sensors.monitor_loop`) sets `online/offline_since` and emits
  `agent.offline/online` events; `silent_after_s` default 300 drives builder staleness.

## 7. Server: `host_fw` builder and the facts path (P1 extensions)

### 7.1 `orchestrator/app/assurance/builders/host_fw.py`

`SOURCE = "host_fw"`, mode `replace`, registered **after** `external_exposure` in `BUILDER_NAMES`.
`load(conn, now)`: latest verified posture per non-revoked, non-legacy agent (+ `last_seen`, `silent_after_s`), the
ip-map rows (`_ipmap`, extended with agent identities), existing `external_scan` edges/coverage, the full-port scans
that back that coverage, and the revoked or legacy agents that still have an open finding (tombstones, below). Every
stored posture is verified again here (digests, header, Ed25519 signature under the agent's active key). Pure
`build()`:

* Node identity (E3): `agent:<uuid>` for every agent in P2 (E3, 13.7: nothing is corroborated into an
  `asset:<uuid>`). `NodeOut.attrs.ips` stays **empty** for an agent node, which the loader reads as "address unknown":
  the node is inside every CIDR expansion (a host cannot take itself out of a CIDR rule by claiming another address).
  What the host claims about itself is `attrs.claimed_ips`; the direct, unique, private address the server observed is
  `attrs.observed_ips`. Never fall back to `ip:` for a managed host. **Consequence:** a cloud instance that runs an agent
  has two nodes, `asset:<uuid>` (inventory and exposure edges, no host facts) and `agent:<uuid>` (the host facts).
  Host-config invariants judge the agent node; reach and exposure invariants keep seeing the instance node as having no
  host facts, so inbound coverage that used to come from the agent's firewall and listener facts for the instance does
  not attach to it and reads UNKNOWN (never HOLDS).
* **Zone** (loader, `graph_loader._agent_zone`): a declared zone label (`PUT /v1/labels`, tag `zone`, Team feature)
  always wins. Otherwise a host is placed in a zone only when the address the server observed and the addresses the host
  claims resolve to the SAME single zone (two unverified hints that agree). If they do not agree (or only one exists),
  a zone label that a connector or asset metadata wrote (weaker than a declared one) still places it. With no such
  label, if they disagree, or a claim spans several zones, or there is no claim or it matches no zone, the node is
  `zone_unknown`: it never definitely
  matches a zone selector and possibly matches every one (as source, target, `stop_at` boundary and allow target), so a
  zone-selected invariant reads UNKNOWN (`possible_via_zone_unknown`, blind spot `zone_unknown`, witness
  `detail.zone_unknown`), never HOLDS, where the node could change the verdict. Disagreements are listed in
  `diag.zone_conflicts`, claim-only guesses in `zone_from_claim`, no claim in `zone_unplaced`. Honest hosts with only
  wildcard listeners, or a claim outside every zone, are therefore `zone_unknown` until a zone label is declared.
* **Edges** per non-loopback listener x source atom (a partition of the address space by every CIDR in the rules plus
  public/RFC1918 representatives; NEW state, unknown interface), walking each input-hook base chain with first-match
  semantics: allow only if all chains allow, deny if any denies, **maybe** if an opaque or unresolved rule could
  decide. Any-source => `internet -> node` when addressable (else `cidr:0.0.0.0/0`, `evidence.assumed_public`).
  basis `configured` (never `observed`); confidence 100 exact, 60 otherwise (widen to all listeners and sources).
  Docker-published ports and unresolved DNAT are always `maybe`. Edges from the last good posture are **kept** while
  the agent is silent for a bounded TTL (over-approximate); only coverage and facts are dropped.
* **Coverage** `in`, tier `configured`, source `host_fw`, `observed_at = LEAST(collected_at, received_at)`, **only
  when all hold**: signature verified, key not revoked, agent not revoked/legacy, `now - last_seen <= silent_after_s`,
  posture fresh, `firewall.confidence == exact`, listener table complete, no open conflict for the node.
* **Conflicts**: an `external_scan` observation inside the external max age (`assurance_external_max_age_h`, 168 h;
  `assurance_edge_window_h` is the separate 24 h flow window) on a `(proto, port)` that the agent models as closed,
  with an exact firewall model and a complete listener table, is a conflict **regardless of the posture's collection
  time** (sticky) => **no coverage**, `facts.conflicts[]` gets `{kind: "agent_closed_scan_open", proto, port,
  scan_seen_at}`, and every collector entry of the host is in conflict. It clears only on positive evidence: a later
  completed full-port external scan of the node (`external_scan` `in` coverage) that finished after
  `posture.collected_at` and started after the last observation of that port, so it did not see it open again. The
  scanner is TCP only, so UDP and `any` observations are never cleared by it, and a newer posture never clears it. A
  conflict check that cannot finish inside the walk budget is itself a conflict (`agent_scan_check_budget_exceeded`).
  A conflict never turns into a pass. There is no operator action to acknowledge or clear one in P2 (13.7).
* **Facts** (`BuildOutput.facts`): compact `host_agent` facts per node (sshd keys, firewall defaults/engine/confidence,
  pending-security count, reboot-required, conflicts, identity basis). The sshd fact carries `daemon` and `truncated`
  unchanged. The listeners fact keeps at most 200 rows (reachable first); `count` is never below the rows seen plus the
  agent's `dropped`, `reported_count`, `capped`, `omitted` and `dropped` say "N of M", and a table with `dropped` or a
  count above its rows is never complete, so no absence claim rests on it. Addresses are stored in compressed form and
  `exe` is the program basename. A fact row over 256 KiB is never dropped: the largest collector entries become `error`
  entries with reason `facts_too_large`, so the host stays tagged and UNKNOWN for them.
* **Rule tokens are validated.** `proto`: `tcp udp icmp icmpv6 sctp dccp udplite gre esp ah igmp ipip ipv6` or `pNNN`
  (0 to 255, not a named protocol's number); a lower-case `/etc/protocols` name the agent forwards (`vrrp`, `ospf`,
  ...) is folded onto its number, so `vrrp` and `p112` are one protocol; `ct`: the five states; `dtype`: the five
  types; `iif`/`oif`: 1 to 15 printable characters without space, `*` or `/`; icmp codes 0 to 255. Anything else
  (`all`, `TCP`, a typo) marks the rule unknown (widened to confidence 60) and is not applied as a filter, which is
  safe (more edges) but loud for an honest host that writes one.
* **Tombstones.** A revoked or legacy agent that still has an OPEN or TRIAGED host-config finding naming it stays in
  the graph as an UNKNOWN node (`host_agent` fact: status `unavailable`, reason `agent_revoked` or `agent_legacy`,
  `data.agent_status`; at most 5000, more adds a note and their findings still stay open). It is dropped when an operator
  closes the finding or a live agent decides the node. A revoked agent with no open finding is **not** kept (to keep
  every revoked row, drop the `EXISTS` clause of `TOMBSTONES_SQL`; an open owner decision, 11 item 8). A host an operator labels out
  of the selector (declared `agent=false` or `server=false`) is an opt-out, not a tombstone: it is not judged and its
  finding stays open until it is selected again and passes, or an operator sets the finding's status
  (`PATCH /findings/{id}`).

### 7.2 Interface deltas (small, additive; owned by one package)

`types.py`: `FactOut(node_ref, source, tier, observed_at, facts)` and `BuildOutput.facts` (default empty, so existing
builders are untouched). `refs.py`: new prefix `agent:<uuid>` (kind `host`). `store.persist_build`: replace this
source's `reach_node_facts`, `BuildReport.facts_changed` (digest of facts minus timestamps) sets `changed`
(graph_version bump); `_prune_nodes` also checks the facts table. The fact digest ignores the top-level
`observed_at`/`seq`/`evidence_ref`, every `*_at` inside a conflict record and, for the `host_agent` summary,
`data.seq`, `data.payload_sha256`, `data.collected_at` and `*_at` inside `data.conflicts` (`store.digest_view`, shared by
`fact_row_digest` and `graph_loader.doc_sha`), so a re-signed identical posture leaves `graph_version` unchanged.
`graph_loader`: emits `nodes[].facts` and auto-tags nodes with agent facts `agent` (metadata, declared labels still
override), and `nodes[].zone_unknown` (an optional boolean, written only when true) for a node whose zone is not
established (7.1). `findings_sync`: `target_of/describe_witness` handle hop-less host witnesses (`assertion ==
"host-config"`). **A host-config finding never closes by absence**: a host that left the graph (revoked, legacy, re-keyed,
re-labelled, an identity flip, an oversized row) is in none of the library's lists, so a finding closes only when its
target is in `passing_targets` (and `passing_truncated` is false), under HOLDS and under VIOLATED alike; the closing
reason reads "host evaluated as passing at graph version N". Under a VIOLATED verdict every zone-unknown node is
listed in `unproven_targets` (capped at 5000; past the cap `violating_truncated` is set and nothing closes), and when
the possible-membership run is not itself a VIOLATED verdict (`overlapping_selectors_too_large` past 64 nodes in both
selections, an empty selection, any other stop) the result carries `violating_truncated = true` and findings sync closes
nothing (`close_skipped = "truncated"`); the verdict stays VIOLATED. `finding_follow.migrate_targets` moves only host-config
findings (witness detail with a `clause` and `detail.node == target_ref`); the posture ingest is its only caller, so a
graph-only identity change (an asset appears after the agent enrolled, an asset's addresses change) closes and reopens
the host-config finding until the runner or findings sync calls it. Rebuild requests from content changes are spaced to
one per 10 s per agent (the periodic rebuild covers the rest). Runner: new opts `agent_posture_max_age`, nothing else.

## 8. Agent client and safety fixes (`agent/paddock_agent/`)

* `urllib.request` HTTP (Sentry's pattern); wrap **all** transport errors in `FleetClientError`; jittered exponential
  backoff capped at 300 s; on-disk gzip outbox with oldest-first eviction (port `sentry/paddock_sentry/buffer.py`);
  `Idempotency-Key = seq`; refuse `http://` for non-loopback servers (copy `normalize_server`). (Today
  `httpx.ConnectError` escapes `run()` and the first network blip kills the daemon.)
* Credentials and key via `mkstemp` + `fchmod 0600` + `fsync` + `os.replace`, refuse group/world-readable files on read
  (port `sentry/store.py`); state dir `/var/lib/paddock-agent` (0700, root). Seq state write-ahead.
* **Safety fix (7.4 of the audit):** `revert_action` and `LinuxEnforcer.revert` currently execute server-supplied argv
  verbatim (`rm -rf` demonstrated). Revert plans are **re-derived locally from the original typed action**; any
  server-supplied plan is validated against an allow-list or ignored. Add the missing IPv6 refusal for `block_ip`
  rather than silently failing. Tests prove `rm`-style plans are rejected.
* systemd unit (one root process, O2): `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `ReadWritePaths=/var/lib/paddock-agent`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
  `ProtectKernelTunables`, `SystemCallFilter=@system-service`, `CapabilityBoundingSet` limited to the capabilities the
  P2 collectors need (`CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN` read-only use), run as root. The existing
  dry-run default and approve-before-apply rails are untouched. **Caveat found in review (13.7, pkg-2): the contract
  text above is not the whole truth.** `CAP_NET_ADMIN` reaches nftables and `iptables-nft` over netlink, but legacy
  iptables (`iptables-legacy`) opens a raw socket and needs `CAP_NET_RAW`, which the unit deliberately does not grant,
  and it needs a writable `/run/xtables.lock`, which `ProtectSystem=strict` forbids. So on a host whose firewall is
  legacy iptables the firewall facts are partial and approximate, `std:server-default-deny-inbound` reads UNKNOWN,
  and `block_ip`/`firewall_rule` fail; "firewall actions use netlink" is true only for nft and `iptables-nft`. The
  contract records no decision about `CAP_NET_RAW`: leaving it out is the conservative default, **pending the owner's
  confirmation** (adding it widens what a compromised root agent can do; AGENT_V2.md section 3 has the operator drop-in,
  untested here). Do not read the capability set as "exactly what the collectors need" without this caveat.
* **Safety rails added by the hardening** (all agent-side, in `actions.py`, `agent.py`, `state.py`): a revert is bound to
  a local ledger record (`handled.json`) of what this agent applied, and its iptables rules carry a
  `paddock:<action id>` tag probed with `-C` before every insert or delete, so two blocks of one target revert
  independently and in any order; a revert of a block applied by an older agent falls back to the stored revert plan; if
  `handled.json` is lost the blocks must be removed by hand. `quarantine_file` needs a real, symlink-free path
  (`/usr/bin/x`, not `/bin/x` on a merged-usr host); `block_domain` never replaces a symlinked hosts file and refuses
  when the link does not point at a regular file in `/etc`. A self-lockout guard refuses `block_ip`, `block_domain` and
  `firewall_rule` that would cut the host off from its server (the addresses the server's name resolves to, the address
  the client actually connected to, the proxies named by `https_proxy`/`http_proxy`/`all_proxy` with `no_proxy` ignored on
  purpose, loopback, outbound to the server's or proxy's port, DNS when the server is a name; failure `self_lockout`,
  nothing applied). A dead-man timer (`PADDOCK_NETBLOCK_DEADMAN_MIN`, default 10, `0` off; `block_ip` and
  `firewall_rule` only) removes a block when no round trip to the server succeeds after it was applied. The removal is
  recorded in `handled.json` and reported on the next round trip as a failed result with `output.error =
  "deadman_reverted"` through the existing result route (never as `applied`). **That route accepts a report only while
  the server holds the action as `approved`.** If the server already processed the `applied` result and only the
  acknowledgement was lost, it answers 409; the agent logs ERROR and records `report_conflict` in `handled.json`, and the
  server keeps showing `applied` (with a revert plan for a rule that is gone) until an operator looks or the next
  posture shows the firewall without the rule. Fail-safe, but the server's action view can be wrong in that window; a
  server-side `applied` to `failed` correction needs a route or contract change and was not invented (13.7).
  `PADDOCK_DRY_RUN` and `PADDOCK_ENABLE_IMDS` parse fail-safe (only an explicit false word turns dry-run off; a typo keeps
  it on and logs an error). The state directory has two locks (`.instance.lock` one daemon, `.state.lock` every
  read-modify-write), so `paddock rotate-key` can run beside the daemon (it signals SIGHUP; a daemon also reloads the key
  when a request is refused with 401); `enroll --force` needs the service stopped.
* **Exit status 7** is now only an explicit structured server verdict (a JSON body whose `error` or `reason` is
  `agent_revoked` or `re_enroll_required`); `RestartPreventExitStatus=7` is correct as written. A bare 401/403/404
  (a proxy, WAF or gateway) is retried at the 300 s backoff forever and logged loudly after ten in a row. The other side:
  an agent whose row was deleted on the server, behind something that answers a bare 404, never exits by itself and
  logs an error every few minutes until an operator stops it.
* The client has a total per-request deadline (a name lookup that never answers is abandoned on a daemon thread that
  cannot be cancelled and ends when the resolver returns), turns a hostile deeply nested reply into a
  `FleetClientError`, refuses a `PADDOCK_SERVER` that differs from the server recorded at enrollment, and installs the
  CA file whatever the case of the URL scheme.
* Packaging (E7): `agent/packaging/build_zipapp.py` (stdlib `zipapp`), `scripts/install-agent.sh` (POSIX sh, pins tag,
  verifies sha256, cosign if present, creates unit, enrolls with the token from stdin/env never argv, `--dry-run`,
  `--uninstall`), a `release.yml` job producing `paddock-agent.pyz`, `SHA256SUMS` and a cosign bundle. As hardened, the
  installer reads the token first (a token piped without a trailing newline works), keeps every other line of
  `agent.env`, restarts the service and checks it is active, installs a `paddock` wrapper without ever overwriting a
  foreign `paddock`, checks ownership and permissions of the install directory and its parent and refuses symlinked
  archive, config and state directories (relocate state with a bind mount), and traps INT, TERM, QUIT and HUP so the
  terminal echo is restored. `release.yml` has a `gate` job (`environment: release`; the tag must be on the default
  branch), SHA-pinned actions, cosign pinned to v2.5.2, a constant `SOURCE_DATE_EPOCH=315532800` and a release body with
  the archive and installer digests. **The gate does not stop someone who can push tags:** the workflow that runs is
  the file in the tagged commit and can delete the gate. The real controls are GitHub repository settings (a tag
  ruleset for `v*.*.*`, the `release` environment with required reviewers and a deployment-tag rule, branch
  protection), which nothing in the repository can enforce, are **not yet applied** (open owner action; checklist in
  AGENT_V2.md section 1), and the workflow has never run. A cosign signature proves which workflow signed, not that the
  commit was reviewed; the release-notes digest is not independent of the release; the independent checks are cosign or
  rebuilding from the tag with the documented constant epoch on a clean checkout. `--require-cosign` is the documented
  default; the installer's own default (warn, then the sha256 of the same release only) is unchanged.
* CI: an AST/`vermin`-style check that new agent code is Python 3.8 compatible plus a `python:3.8` test job.

## 9. Work packages and file ownership

One owner per file. Frozen after P1 verification: P1 files change only through the package that owns them below.

| WP | Owns | Needs first |
|---|---|---|
| WP1 SCHEMA + TOKENS | `schema/041_agent_v2.sql`, `app/fleet_enroll.py`, `tests/test_fleet_enroll.py`, one-line edits to `tests/test_isolation_sweep.py` (`EXTRA_POLICIES`) and `tests/test_isolation_keys.py` (`GLOBAL_UNIQUE_OK`) | nothing |
| WP2a AGENT CORE | `agent/paddock_agent/{signing,ed25519_pure,state,client,agent,cli,config,envelope,actions,platform_block}.py`, `agent/pyproject.toml`, `agent/tests/` (non-collector) | wire contract (section 2) |
| WP2b COLLECTORS | `agent/paddock_agent/{collectors/*,runner.py}`, `agent/tests/collectors/`, `agent/tests/fixtures/` | none (pure) |
| WP3 SERVER INGEST | `app/routers/fleet.py`, `app/fleet_posture.py`, `app/auth.py` (agent principal + rules; **sole owner**), `app/retention.py`, monitor loop, `tests/test_fleet.py` (adapted), `tests/test_fleet_posture.py` | WP1 |
| WP4 LIBRARY | `assurance/**` (HOSTCONFIG, registry, expression, std yaml) | none |
| WP5 BUILDER | `app/assurance/builders/host_fw.py`, `builders/_ipmap.py`, `builders/__init__.py`, `tests/test_assurance_host_fw.py` (pure) | WP1, WP2b model, WP6 types |
| WP6 STORE/LOADER/FINDINGS | `app/assurance/{types,refs,store,graph_loader,findings_sync,runner}.py` and their tests | WP1 |
| WP7 PACKAGING + DOCS + E2E | `agent/packaging/*`, `scripts/install-agent.sh`, `release.yml` job, `docs/AGENT_V2.md`, `docs/FLEET_WIRING.md`, `docs/READINESS.md`, generated files (OpenAPI/SDKs), `tests/test_assurance_p2_e2e.py` | all |

Landing order: WP1 -> (WP2a, WP2b, WP3, WP4, WP6 in parallel pairs) -> WP5 -> WP7 -> independent verifier.

## 10. Verification gates (all green before P2 is done)

* `agent`: `pytest -q`, a Python 3.8 syntax/AST check, `ruff check .`; RFC 8032 test vectors for both signer
  backends and a test that they are byte-identical.
* `assurance`: `pytest -q`, `ruff check .`.
* Orchestrator, run **sequentially, one pytest session at a time** (the `pytest-postgresql` template database name is
  fixed): the P1 gate list plus `tests/test_fleet*.py`, `test_isolation_keys.py`, `test_public_surface_adversarial.py`,
  `test_assurance_host_fw.py`, `test_assurance_p2_e2e.py`, once normally and once with `ORCH_TEST_APP_ROLE=1`.
* Generated files regenerated and `--check` clean. `ruff check .` at repo root.
* **Definition of done (one end-to-end test):** a one-time token enrolls an agent with its key; signed posture is
  accepted; `std:server-ssh-hardened` and `std:server-default-deny-inbound` `HOLDS` (tier `configured`); flipping
  `PasswordAuthentication yes` => `VIOLATED` with a finding; a tampered payload is rejected with 401 and an audit row
  and the previous posture stays; a replayed envelope gets 409; silencing the agent => `UNKNOWN`; the external scan
  seeing a port the agent calls closed => conflict, no coverage, `UNKNOWN`; a legacy v1 credential gets
  `403 re_enroll_required`; tenant B sees nothing of tenant A; 20 concurrent redemptions of one token have exactly one
  winner.

## 11. Known gaps after P2 (stated, not hidden)

Rewritten after the adversarial review and its three hardening rounds (13.7, which says what was closed). Each item
says which way it fails: **safe** means the host reads UNKNOWN or a finding stays open; **not safe** means a false
HOLDS or a wrong closure is still possible. Only the items marked **owner** need a decision that is not the code's to make.

**What the evidence can and cannot say**

1. **Signed is not true** (not safe, by nature). Cross-validation covers only ports the external scan or cloud
   configuration can see. A root attacker on the host holds the key and signs any posture, including a clean one.
2. **No agent is corroborated into a cloud instance in P2** (safe). A private source address is not proof of identity:
   a header-less NAT or VPN instance that rewrites another machine's address to its own private address, with one
   enrolled agent behind it, cannot be told from the instance. So every agent is `agent:<uuid>`, basis `claimed`
   (note `peer_address_not_proof`); an instance that runs an agent has an instance node with no host facts and an agent
   node with them, and reach and exposure invariants read the instance node as UNKNOWN. An ingress that rewrites the
   source without adding any header cannot be recognised as a proxy. Turning merging back on needs a trust root: a
   server-verified signed instance-identity document (not built; out of scope in section 0) or an operator pairing of
   agent and asset (no route or UI exists). **Owner decision, P2.1.**
3. **Zone placement rests on two unverified hints** (not safe, narrow). A host without a declared zone label is placed
   from the address the server observed only when its own claimed addresses resolve to the same single zone. A forged
   peer alone now gives zone-unknown (UNKNOWN), but a compromised host that tunnels its agent traffic through a machine
   in another zone **and** writes an address of that zone into its own listener claim is placed in that zone, so
   "guest cannot reach pos" can read HOLDS for it. Same trust root as item 2. A declared zone label always wins and is
   the operator's remedy. **Owner decision, P2.1.**
4. **Zone-unknown nodes: findings stop closing at 65 or more** (safe). The shipped Helm default
   (`trustedProxyCidrs` empty) makes every undeclared agent that connects through an ingress adding `X-Forwarded-For`
   zone-unknown. When more than 64 zone-unknown nodes sit in both
   selections, the possible-membership run gives up (`overlapping_selectors_too_large`), the VIOLATED zone invariant
   carries `violating_truncated`, and findings sync closes **nothing** (`close_skipped = truncated`) until the
   zone-unknown count drops by declaring zone labels. Also honest hosts with only wildcard listeners, or a claim outside
   every zone, are zone-unknown until labelled, so zone-selected invariants read UNKNOWN for them (never HOLDS).
5. **sshd claims are about the files, plus positive evidence about the daemon** (safe). They need `v.daemon`
   evidence (section 5): an agent that cannot read `/proc/<pid>/exe` or `cmdline` (not root, `hidepid`), a stopped sshd or an
   unresolvable symlink reads UNKNOWN for every sshd config invariant. A pending reload reads UNKNOWN, never VIOLATED
   (a one-sided violation under a pending reload was not built: it needs polarity tracking through `not`/`any`, and
   calling an unreloaded file a violation is a policy call). A reload that does not rewrite the pid file keeps
   `reload_pending` true until restart. The collector cannot know the path the daemon resolved at start, so a repoint
   hidden before the daemon started is out of scope. Per-variant evaluation does not decide an `any` whose branches
   pass in different variants or fail in the same one (UNKNOWN). `Match User/Group` is complete only for files-only NSS
   (`files`, `compat`, `systemd`, no userdb/homed data, no NIS `+`/`-` rows): sssd, ldap, winbind, extrausers or an
   unreadable `nsswitch.conf`/`group` read `nss_users_unknown` (approximate), and a group is named by its first
   `/etc/group` entry as glibc does. A `Match` pattern list over 1024 characters reads approximate. `tool_missing` from
   the collector never means "no SSH server".
6. **The firewall model is approximate in places** (safe, except the last point). ipset, marks, DNAT, Docker, K8s or
   eBPF dataplanes, a missing `nft` binary and a non-root agent give UNKNOWN. A chain name over 120 characters
   (`<family>.<table>.<chain>`, or `jump:` plus that) is refused 422, so such a host reads UNKNOWN (the pinned test
   fixes 121 as refused; kube, docker and ufw names are short). Big-endian decoding is verified only by faking
   `sys.byteorder`. **Not safe:** `nft -j` cannot distinguish `ip6 nexthdr tcp tcp dport 22 drop` from `meta l4proto tcp
   tcp dport 22 drop`; the kernel checks only the immediate next header, so IPv6 packets with extension headers bypass
   the former, and the model reports a definite IPv6 tcp/22 deny.
7. **Legacy iptables hosts read UNKNOWN under the shipped unit** (safe). `CAP_NET_RAW` is not in the bounding set, so
   `iptables-legacy` cannot be read (`std:server-default-deny-inbound` is UNKNOWN), `block_ip` and `firewall_rule`
   fail there and `/run/xtables.lock` is unwritable under `ProtectSystem=strict`. The contract records no decision
   either way; leaving it out is the conservative default, **pending the owner's confirmation** (alternative: an
   operator drop-in at the operator's own risk, untested). **Owner decision.**

**Lifecycle, findings and operators**

8. **Tombstone scope** (safe). A revoked or legacy agent stays in the graph, reading UNKNOWN, only while an OPEN or
   TRIAGED host-config finding names it; a host revoked while passing leaves the coverage universe. Keeping every revoked row would add a node and a fact per
   decommissioned autoscaling instance (one-line switch: drop the `EXISTS` clause of `TOMBSTONES_SQL`; more than 5000
   tombstones adds a note and their findings still stay open). Revoked rows are never deleted: `FLEET_MAX_AGENT_ROWS_PER_TENANT`
   (10 times the active cap) is the only bound, so a long-lived autoscaling tenant needs the knob raised, and there is no
   purge. **Owner decision.**
9. **A scan conflict has no operator action** (safe). `agent_closed_scan_open` clears only by a later completed
   full-port TCP scan that did not see the port, or when the observation leaves the 168 h external window; an honest,
   remediated host stays in conflict (no coverage, UNKNOWN) until then. There is no route to acknowledge it, and none to
   pair an agent with an asset (item 2); both need a route, an RBAC decision and a migration (P2.1). UDP
   observations are never cleared by a scan. **Owner decision.**
10. **A label-changed host is an opt-out** (safe). Declaring `agent=false` or `server=false` removes the host from the
    selector: it is not judged and its finding stays open (only `passing_targets` close), until it is selected again and
    passes or an operator sets the status through `PATCH /findings/{id}`.
11. **Disabled or deleted invariants keep their findings open** (safe; runner-4, carried from P1, ASSURANCE_P1.md
    section 12). Closing them would be a false verification; whether to close, annotate or keep is a product decision.
    **Owner decision.**
12. **Sensor scopes** (P1, ASSURANCE_P1.md section 12; not part of the review's 66 findings). A declared Sentry sensor
    scope is an accountability record, not a technical guard: a scope declared wider than the sensor really sees yields
    coverage. Unchanged by P2; whether to check it against observed flows is **an open owner decision**.

**Intake, limits and the agent**

13. **The v1 inventory route stays unsigned** (safe: never evidence, stored `signed: false`, tier `declared`). It is
    bounded (active key, 2 MiB, dedupe, newest 5 per agent, tenant byte cap, NUL and lone surrogates refused) but a
    bearer-only holder with an active key can still write it. Requiring a signature, or dropping the route, is a
    contract decision (section 2). **Owner decision.**
14. **Limiters are per process** (safe). N replicas allow N times each limit. The pre-auth slot is atomic, but the
    enrollment fail-lockout (`fleet_enroll.enroll_agent`) is still check-then-act: fixing it needs a design that excludes
    in-flight enrollments from the failure count (a multi-use token legitimately boots a fleet behind one NAT address),
    so a concurrent burst can overshoot within a minute; it is bounded by the atomic 20 per minute enrollment limiter and
    the 128-bit token secret. An attacker on the agent's own egress address, or a peerless socket, shares the agent's
    pre-auth bucket and, holding its bearer, can fill it, which silences that agent (UNKNOWN, never HOLDS). Replays are free for the agent's budget but cost CPU and a database round trip until the
    per-agent replay bucket (60 per minute) is spent, and a holder of the bearer plus one captured envelope can make the
    real agent's idempotent lost-answer resends 429 for up to a minute (it retries).
15. **Audit rows are still unbounded for three denied paths** (safe; noise, not evidence, the chain still verifies):
    `POST /v1/fleet/{id}/keys/rotate` rejections (outside the data-plane exemption), a wrong-agent bearer on another
    agent's route (403) and a garbage `fat_` bearer (401) each still get one per-request middleware row. Bounding them
    needs a limiter keyed on the caller. Sensor enrollment (`routers/sensors.py`) still keys its limiters on `client_ip()`.
16. **Older agents are refused, not degraded** (safe). A posture without `sections.sshd.v.daemon` (an agent built before
    the hardening) is a 422, so none of its sections, firewall and listeners included, becomes evidence and the host
    reads UNKNOWN until it is upgraded. A chain name or delta key outside the wire limits is the same.
17. **Dead-man report can be refused** (safe, but the server's action view can be wrong). The removal of a block by the
    dead-man timer is reported as a failed result only while the server holds the action as `approved`. If the server
    processed `applied` and only the acknowledgement was lost, it answers 409; the agent logs ERROR and records
    `report_conflict`; the server keeps showing `applied` until an operator looks or the next posture shows the firewall
    without the rule. A server-side `applied` to `failed` correction needs a route or contract change. A dead-man report
    is lost only if both the queued item and the server's re-offer never happen.
18. **Revoked or deleted agents behind a bare 404** (safe). Exit 7 follows only an explicit structured verdict, so an
    agent whose row was deleted behind something that answers a bare 404 keeps polling and logging an error every few
    minutes until an operator stops it (`systemctl disable --now paddock-agent`). A lost `handled.json` means the agent
    cannot revert its blocks; they must be removed by hand. An abandoned name lookup cannot be cancelled (a daemon thread
    that ends when the resolver returns). The server's 409 `detail` is written unsanitised to the ERROR log and to
    `handled.json` (a hostile server could forge a log line; low, the server is already a trusted channel).
19. **Release trust is not enforced by the repository** (not safe until applied). The GitHub settings (environment
    `release` with required reviewers and a `v*.*.*` deployment-tag rule, a tag ruleset, branch protection) are an
    **open owner action**; until then a release is trusted only as far as everyone who can push tags. `release.yml` has
    never run, and cosign was exercised only through a recording fake. **Owner action.**

**Scope and platform (unchanged from the contract)**

The Python-3.6 case (RHEL 8 default interpreter) needs the `python39` module or is unsupported. The vendored signer is
not constant-time. A root network-facing process (O2). No KEV matching (O4), no accounts/FIM/egress/containers
collectors, no Windows/macOS, no deb/rpm, no distro advisory data, no dashboard screens for tokens, rotation or verdicts.
The open P1 risks (std invariants only `HOLDS` with strong coverage, tenant-wide coverage floor, SG-referenced rules
over unmodelled ENIs) are tracked in ASSURANCE_P1.md and must be resolved before P2 evaluates real tenants.

## 12. Background

Scouting reports (six, about 175 KB, may contradict the decisions above): the session scratchpad
`.../scratchpad/p2/scouts.json`, keys `agent, fleet, signing, collectors, invariants, integration`; real captured
command output for fixtures: `.../scratchpad/p2/fixtures-collectors/` and `fixtures-signing/`.

## 13. Status: what shipped, what differs, what is open

Written after the build and rewritten after the adversarial review (2026-11-25). Sections 0 to 12 are the contract as
agreed; where the hardened build does something else they were corrected in place (and say so), and sections 11 and 13
are exact about what shipped, what differs and what is open. **How to read a verdict:** `HOLDS` means no counterexample
under this evidence (tier `configured`), not that the host is secure, and not that anything was run on a real host:
section 13.5 lists what no test has exercised. Operator documentation: [AGENT_V2.md](AGENT_V2.md).

### 13.1 Shipped

| WP | What exists |
|---|---|
| WP1 | `schema/041_agent_v2.sql`; `app/fleet_enroll.py` (one-time and multi-use tokens, strict Ed25519 key validation, proof of possession, re-key tokens) |
| WP2a | agent core: signing (OpenSSL or the vendored RFC 8032 signer, byte-identical), envelope, write-ahead state, urllib client with backoff and outbox, enrollment, rotation, the revert-plan safety fix |
| WP2b | collectors sshd, listeners, firewall (`fwmodel.py`), patch, self-health; the probe runner; `agent/PAYLOAD.md` |
| WP3 | `app/fleet_posture.py` (the ten ordered checks), `routers/fleet.py`, the agent principal and RBAC rules in `auth.py`, `fleet_monitor.py`, retention |
| WP4 | library: host-config predicates, field registry, Kleene evaluation, `std:server-ssh-hardened`, `std:server-default-deny-inbound`, `paddock-invariants fields` |
| WP5 | `builders/host_fw.py` and agent identities in `_ipmap.py` |
| WP6 | `FactOut`, `agent:` refs, `reach_node_facts` in the store, loader and findings sync, runner option and build stamp |
| WP7 | reproducible zipapp builder, installer, systemd unit, release job and CI jobs, `AGENT_V2.md`, `FLEET_WIRING.md`, `READINESS.md`, regenerated OpenAPI and SDKs, the end-to-end test and the cross-language wire vectors |

### 13.2 Differences from the contract text (each deliberate; none loosens a rule)

* **Schema and tokens.** `agent_posture.signed` defaults to `FALSE` (a row is evidence only if ingest set it after
  verifying); one active key per agent is enforced by a partial unique index (rotation retires the old key first);
  `uses <= max_uses` is also a CHECK; re-key tokens (`for_agent`) exist and cannot revive an agent revoked after
  they were minted; v1 revoked rows get `revoked_at` backfilled.
* **Wire.** `kind=rotate` (payload type `paddock.agent.key-rotate/v1`, proof message `paddock-rotate/v1\n<agent>\n<old
  kid>\n<new kid>`) and a heartbeat payload are defined; the enroll reply carries `tenant_id` and the body takes an
  optional `platform`; `kid` is 1 to 64 printable characters; heartbeat payloads are capped at 4 KiB; an identical
  resend of an older stored posture is an idempotent 200; the viewer-safe agent detail hides the machine id hash,
  boot id and peer address.
* **Library.** `Invariant.assert_` is the string `host-config` and the tree is in `Invariant.expr`; facts carry
  `conf`, `partial` and `reason` besides the listed keys (missing means the weakest value); `min_tier` above a
  field's reachable tier is a `CompileError`; `host.sshd.installed == false` needs `tool_missing` and a complete,
  attributed listener table whose public TCP listeners are all known non-SSH programs (section 5); `root_login_possible` is true only for `PermitRootLogin yes`; the document depth cap
  went from 12 to 14. A bare predicate string is a valid `assert:`, so a misspelt literal such as `nonsense` now
  fails as a predicate, not as an unknown assertion.
* **Builder and store.** Facts are `{collector: entry}` plus an informational `host_agent` entry the library never
  reads; edges also cover ICMP and other IP protocols, and a firewall that accepts everything emits the world CIDR
  as well as `internet`; the corroboration rules require the server-observed peer address to be one of the instance's
  private addresses and accept any VM-type cloud resource, but **they are switched off** (7.1, 13.7); a conflict
  flags every collector entry of the host; the digest ignores `seq`, `evidence_ref` and collection times (7.2); the
  runner stamps `last_build_at` at the start of a build, so a request made during the build is not overwritten.
* **Collectors.** A host with iptables-nft but no `nft` binary, or a failing `nft`, is `UNKNOWN`; the firewall's
  `effective_default` claims a drop only if some packet really reaches the policy.
* **Packaging.** The archive is written member by member (fixed timestamp and modes, stored, files only) and
  `zipapp` only prepends the interpreter line, because `zipapp`'s directory mode gives different bytes on Python
  3.12 than on 3.11; the entry point is a generated `__main__.py` with `sys.exit(main())` (`zipapp`'s `main=` drops
  the return value, which would turn exit status 7 into 0). The installer adds `--sha256`, `--require-cosign`,
  `--root` and `--base-url`, and each release carries an installer pinned to its own tag. CI gains `agent-py38`
  (the `python:3.8` image) and `agent-installer`.

### 13.3 Verification

Final gates, 2026-11-25, after the third hardening round (Postgres 16 on a private port, Python 3.13 unless stated):

* `agent` (`agent/tests`): 917 pass; on a real CPython 3.8.20 915 pass (two tests need Python 3.10);
  `agent/packaging/tests`: 127 pass on 3.13; `ruff check` clean.
* `assurance` (library): 8405 pass, 1 skipped; `ruff check` clean.
* Orchestrator, one pytest session at a time, normally and with `ORCH_TEST_APP_ROLE=1` (the RLS role): 3088 pass in each
  mode (the figure the hardening run recorded; the orchestrator gates were not re-run when these documents were edited).
* Generated files: `export_openapi.py`, the Python SDK codegen and the TypeScript SDK codegen all report up to date with
  `--check`; `ruff check .` at the repository root is clean (both re-run while editing these documents).
* The doc-pinned tests (`-k "doc or pkg9 or readiness"` in the orchestrator, the agent suite and `agent/packaging/tests`)
  read `AGENT_V2.md`, `FLEET_WIRING.md`, `agent/README.md`, `READINESS.md` and `release.yml`; a documentation edit that
  breaks one fails there.
* Definition of done: `tests/test_assurance_p2_e2e.py` (real agent, real server, two tenants) and
  `tests/test_fleet_wire_vectors.py` (the agent's vectors checked by the server, `cryptography` and the OpenSSL CLI).
  After the review, `tests/test_p2x_integration.py` drives the **real collectors and agent code** against the server's
  schema (the round-1 integration defect, 13.7 area wire, was a server model that refused the agent's `sshd.v.daemon`;
  nothing exercised the two together). Its `p2_support.FixtureHost` models a root sshd master (`/proc/700`, a boot time a
  day ahead so the config is older than the daemon); without positive daemon evidence the ssh invariant honestly reads
  UNKNOWN, and the e2e tests prove that too (no daemon, a cut value, a failed `sshd -T` all give UNKNOWN, never HOLDS).
  A later change to the agent's sshd or listeners payload that the server models do not follow fails there first.
* Mutation checks from the original build (a rule broken in a scratch copy, the tests must fail): WP1 20/20, WP2a 23/24
  (the survivor is an equivalent mutant), WP2b 30 killed and 1 equivalent mutant, WP3 44/44, WP4 15/15 plus 19 in-suite,
  WP5 40/40, WP6 30/30; WP7: 11/11 server rules through the end-to-end and vector tests, 14/14 installer and builder
  rules. Not repeated for the hardening; the verifiers instead re-ran each attack on the fixed tree and checked that the
  new tests fail on the base (13.7).
* Existing tests that encoded behaviour a finding proved wrong were rewritten, each with its reason in the docstring and
  none weakened, skipped or deleted: the host-config closing tests (closing now needs `passing_targets`), the
  sticky-conflict tests, the "observation overrides the claim" zone tests, the corroboration tests (they now set
  `_ipmap.PRIVATE_PEER_IS_PROOF = True` in an autouse fixture because they test rules 1 to 4, which still exist; the
  default-off behaviour is pinned in `test_p2z_builder.py`), the ten-consecutive-401 exit tests, the revert round-trip
  tests (they expect the `-C` probe), and the sshd collector tests (their fixtures now add a socket-activation marker or
  a master daemon, because a config with no daemon evidence is approximate).

### 13.4 Open issues (found while building; status after the hardening)

1. **Fixed by the verifier (13.6, item 3).** ~~Rotation leaves the host `UNKNOWN` for up to an hour.~~ The first posture
   under a new key is not stored when its digest is unchanged, so the newest stored posture is signed by a `rotated`
   key and `host_fw` rightly ignores it. Fixed in `fleet_posture._claim_and_persist` (store when the key id differs);
   `test_assurance_p2_e2e.py::test_a_healthy_host_keeps_holds_after_a_key_rotation` is a normal test now. No P2 test
   carries an `xfail` marker.
2. **Fixed by the verifier (13.6).** ~~P1 end-to-end test is stale.~~ `host_fw` is in the builder set the test expects.
3. **Fixed by the verifier (13.6).** ~~`tests/test_assurance_api.py` encodes superseded behaviour.~~ (6 std invariants
   ship; `assert: nonsense` is now a predicate error.)
4. **Fixed by the verifier (13.6, item 5).** ~~`agent.offline` and `agent.online` are not in `integrations.base.EVENT_TYPES`.~~
5. **Setting.** `config.py` has no `assurance_agent_posture_max_age_h`; the runner reads it with `getattr` and falls back to
   its 6 h default, so it is not yet a setting.
6. **Fixed (13.7, hostfw-4), with scope limits (11 items 8 and 10).** ~~A host that leaves the graph is silent.~~ A
   host-config finding closes only when its target is in the library's `passing_targets` (and `passing_truncated` is
   false), under HOLDS and under VIOLATED. A host that left the graph (revoked, legacy, re-keyed, re-labelled, identity
   flip, oversized row) is in no list and keeps its finding open. A revoked or legacy agent with an open or triaged
   host-config finding stays in the graph as an UNKNOWN tombstone; a revoked agent with no open finding is not kept.
7. **External observations persist, and the conflict is sticky (13.7, hostfw-3).** After the external scan sees a port
   the agent calls closed, the conflict holds for as long as the observation is in the graph (the external max age,
   `assurance_external_max_age_h`, 168 h; **not** `assurance_edge_window_h`, which is 24 h and is the flow window). A newer
   posture never clears it. It clears when a later completed full-port TCP scan, started after the last observation of
   that port and finished after the posture was collected, did not see it open. No operator action exists (11 item 9).
8. **Environment.** `scripts/tests/test_ci_templates.py::test_shellcheck` fails where `shellcheck` 0.10 is
   installed (info-level SC2015 in `integrations/ci/paddock-ci.sh`); it skips where there is no `shellcheck`. Not
   re-run here. `shellcheck` was not available to check the installer after its last change (the signal traps).
9. **Limits (11 items 13 to 15).** In-process rate limiters (N replicas allow N times the limit); no dashboard screens for
   tokens, rotation or verdicts; rotate rejections, a wrong-agent bearer and a garbage bearer still write one audit row
   each; `POST /v1/fleet/actions/{id}/result` has no body-size cap of its own and is an existence oracle inside one
   tenant (403 versus 404).

### 13.5 Not verified

What the tests do exercise: the real agent code against the real server code and a real Postgres (RLS role, two tenants)
on **synthetic hosts** (command output and `/proc` content written from captures of Ubuntu 24.04 and from the manuals);
the installer staged into a directory (`--root`) against a local mirror, including pty tests with real signals under
`sh`, `dash` and `bash`; a byte-reproducible archive across Python 3.8 to 3.13, time zones and umasks; a unit file
identical to the installer's heredoc apart from the two install paths; and the structure of `release.yml` (SHA pins, cosign version, `needs: gate`),
read as text.

What nothing has exercised: the installer as root on a host, the unit under a real systemd (the sandbox directives, the
capability bounding set, `RestartPreventExitStatus`), a real GitHub release (`release.yml` has **never run**; cosign was
exercised only through a recording fake), real `nft` and `iptables` applied on a host (including the dead-man timer,
reverts and `self_lockout` against a live firewall), a real `sshd -T` and a real running sshd master (the sshd fixtures are
synthetic, and `v.daemon` is built from a modelled `/proc`), RHEL, SUSE and Alpine hosts, Docker and Kubernetes
dataplanes, a big-endian host (decoding is checked by faking `sys.byteorder`), several orchestrator replicas, a Postgres
major version other than 16, and the performance of `host_fw` on a large fleet (about 100 ms per host with a distinct large
ruleset, measured by WP5 on synthetic data; a hostile single posture can still cost up to the per-agent budget of about 4 s).

### 13.6 Independent verification (2026-11-25)

A verifier who trusted none of the work packages' reports re-ran every gate and probed the seams between packages.
Five defects were found and fixed, each with a test that failed before and passes after
(`orchestrator/tests/test_p2_verifier.py`, plus the un-xfailed rotation test and the three stale tests):

1. **`host_fw` could be made to compute for hours by one signed posture (DoS, high).** The walk budget counted walks,
   but a walk costs up to one rule evaluation per rule: 2000 distinct-CIDR rules and 2000 listeners (a 700 KB posture
   the ingest schema accepts) is billions of evaluations in a worker thread no timeout can stop (measured before the fix:
   1.3 s, 8.6 s and 56 s for 100, 200 and 400 rules and listeners; cubic). Now bounded in rule evaluations
   (`STEP_BUDGET` per agent, `BUILD_STEP_BUDGET` per build); a host over budget is widened (confidence 60, no coverage), and
   an external-scan check that cannot finish is a conflict, never a pass.
2. **A declared `server` that no builder drew a node for was silently out of scope (E5 violated).** `graph_loader` now adds
   every node carrying a `server` label, so the std host invariants see it as `UNKNOWN: no_agent`.
3. **After a key rotation the host read `UNKNOWN` for up to an hour** (13.4 item 1): the first posture under a new key is
   now always stored and the graph rebuilt.
4. **Cloud-instance corroboration was forgeable behind a proxy.** `peer_ip` was the leftmost `X-Forwarded-For` entry,
   which a proxy that appends leaves attacker-chosen: a compromised host could be merged into `asset:<victim>` and
   attach its facts and coverage to it. `auth.client_ip_strict` read the header from the right, skipping trusted proxies.
   **That fix was itself wrong** (the adversarial review, 13.7 wire-1): skipping every entry inside a trusted CIDR returned
   the attacker-written entry when the trusted range was RFC1918 (the Helm default then). It now takes the Nth entry from
   the right and fails closed; and since the review, no agent is corroborated at all (7.1).
5. **`agent.offline` / `agent.online` are registered integration events** (13.4 item 4), with OCSF activity and docs.

6. **The suite passed only in alphabetical order.** The assurance runner keeps its last build per tenant in a process-local
   dict and every test uses the default tenant, so a test that builds (the P2 end-to-end tests do) made a later
   `test_state_endpoint` fail (`pytest tests/test_assurance_p2_e2e.py tests/test_assurance_api.py`). `tests/conftest.py` now
   clears it before every test.

Limits chosen for item 1: 8 M rule evaluations per agent (about 4 s; a typical host needs 0.2 M) and 100 M per build. A fleet of
more than about 500 hosts that all have DIFFERENT large rulesets will see the later hosts widened (UNKNOWN) rather than
walked; hosts with identical rulesets share one walk.

Also corrected: three tests that encoded superseded behaviour (the P1 end-to-end builder set, the std count, the
`assert: nonsense` diagnostic; the library now reports the predicate error alone, not next to a severity error).

What this list said was "deliberately not changed" has since moved: a revoked or legacy agent with an open finding now
stays in the graph as an UNKNOWN tombstone (13.4 item 6, 13.7), and the fleet routes and enrollment limiters key on
`client_ip_strict`. Still true: the in-process limiters multiply with replicas and the pure signer is not constant-time.

### 13.7 Adversarial review and hardening

After 13.6 an adversarial review attacked the built P2 from seven angles (the wire and server, enrollment, the agent
core, the collectors, the library's host-config predicates, the `host_fw` builder and the packaging). It confirmed **66
findings**: 7 high (6 of them false-HOLDS paths), 22 medium and 37 low as filed, 13 false-HOLDS paths in all (the
review's own verifiers, who reproduced each finding before it was confirmed, rated the 66 lower: 3 high, 16 medium, 47 low). Three fix rounds
followed. Each round had one fixer per area and then an independent verifier, who re-ran the attack on the fixed tree,
checked that the new tests fail on the base and marked each finding fixed, partial or accepted-as-deferred; what
a verifier found new went into the next round. Round 1 left five findings partial (wire-3, hostcfg-6, hostfw-1, hostfw-2,
pkg-13) and a **cross-package integration defect**: the agent emitted `sections.sshd.v.daemon`, `sshd.v.truncated` and
`listeners.v.dropped`, which the server's `extra=forbid` models refused, so every honest posture was a 422 (the host read
UNKNOWN, never HOLDS, but nothing worked) until round 2 added the fields and an end-to-end test over the real collectors
(13.3). Rounds 2 and 3 closed the partials and what the verifiers found; round 3 changed docs, the zone rule and the
dead-man report.

Outcome words: **fixed** (the attack no longer works; a test fails on the base and passes now); **fixed, residual** (the
attack is closed but a stated limit remains, pointing at section 11); **deferred** (not fixed, and why). Totals: 45
fixed, 20 fixed with a residual, 1 deferred. No finding is left unexamined, but a "fixed" here means "no counterexample
found by the verifier", not that a real host or a real systemd was involved (13.5).

**Wire and server (7)**

| Finding | What it was | Outcome |
|---|---|---|
| wire-1 (high) | Corroboration address forgeable from inside the network under the Helm default `TRUSTED_PROXY_CIDRS`: a compromised host got HOLDS on an agentless victim instance | Fixed, residual. `client_ip_strict` takes the Nth `X-Forwarded-For` entry from the right (all lines joined, hops configured), marks an address `proxied`, and the Helm default is now empty. Then corroboration itself was switched off (hostfw-2). Residual: 11 items 2 and 3 |
| wire-2 (medium) | Posture and inventory storage bounded only for honest hosts | Fixed, residual. Per-agent and per-tenant byte caps, overwrite within 300 s, NUL and lone-surrogate refusal (E8, section 2). Residual: the v1 inventory route stays unsigned (**owner**, 11 item 13) |
| wire-3 (medium) | The rate limit was spent before authentication and 429/400 answers were audited without bound: a bearer-only holder could lock the real agent out and flood the audit chain | Fixed, residual (partial in round 1, closed in round 2). Atomic pre-auth slot refunded on a verified signature, per-agent budget charged only for an accepted envelope, replay bucket, sampled and aggregated audit rows, `audit_aggregated` (section 2). Residual: 11 items 14 and 15 |
| wire-4 (low) | A lone surrogate in an envelope or payload string was an unaudited 500 | Fixed (rejected as a control character; digest and canon errors are a 422) |
| wire-5 (medium) | Any enrolled host could demote a neighbour's corroborated identity by claiming its private addresses, flipping the neighbour's finding to fixed | Fixed. A claim never owns an address and never makes one ambiguous; only an agent that itself passed the corroboration rules can clash with another |
| wire-6 (low) | "Fleet agents reporting" counted agents that cannot or do not report | Fixed. `REPORTING_AGENT_SQL`: not revoked, not legacy, online, an active key that signed at least once, a posture or heartbeat inside the window |
| wire-7 (low) | Revoking a rotated key left its successor active | Fixed. `successors` (`revoke` or `keep`) is required when an active successor exists (409 otherwise) |

**Enrollment (6)**

| Finding | What it was | Outcome |
|---|---|---|
| enroll-1 (medium) | A stolen `fat_` bearer burned the agent's limits, silencing its evidence and blocking rotation | Fixed, residual (as wire-3: 11 item 14) |
| enroll-2 (low) | Lock-order inversion between re-key enrollment and revoke deadlocked | Fixed. One global lock order (token rows, agent count lock, agent row, keys); a deadlock victim is retried |
| enroll-3 (low) | A hostname with a trailing newline was a distinct, valid name | Fixed (`fullmatch`) |
| enroll-4 (low) | Revoking a key did not revoke the bearer's unsigned routes | Fixed. Inventory and action results need an active key |
| enroll-5 (low) | Enrollment limits keyed on the spoofable leftmost `X-Forwarded-For` | Fixed, residual: fleet enrollment keys on the strict peer; sensor enrollment (`routers/sensors.py`) keeps the old pattern (11 item 15) |
| enroll-6 (low) | Revoking an agent left the multi-use token it came from | Fixed. `revoke_enroll_token` defaults true |

**Agent core (14: agent-1 to agent-12, srv-env-1 and the canonical-form finding, which the review also numbered wire-1)**

| Finding | What it was | Outcome |
|---|---|---|
| agent-1 (medium) | A second process (`rotate-key`, `enroll --force`) left the daemon signing with a retired key | Fixed. Two state locks, SIGHUP on rotate, reload on a 401, `enroll --force` refuses while a daemon runs |
| agent-2 (medium) | Ten consecutive 401/403/404, from any intermediary, permanently stopped the agent | Fixed, residual. Exit 7 only on a structured verdict; 11 item 18 |
| agent-3 (medium) | One non-UUID action id wedged the outbox for good | Fixed (ids are validated; the head of the outbox cannot block the heartbeat) |
| srv-env-1 (low) | The server's envelope parser raised an unhandled `UnicodeEncodeError` | Fixed (same as wire-4) |
| agent-4 (medium) | A revert was bound to nothing the agent applied and could delete an admin's own DROP rule | Fixed, residual. Local ledger, tagged iptables rules probed with `-C`; if `handled.json` is lost the blocks are removed by hand |
| agent-5 (medium) | `quarantine_file` checked the path lexically; symlinks were followed | Fixed (needs a real, symlink-free path) |
| agent-6 (low) | `block_domain` corrupted the last hosts entry and could map the blocked name to a real address | Fixed (and a symlinked hosts file is not replaced) |
| agent-7 (low) | Apply was not crash-safe or atomic | Fixed (ledger record, idempotent apply) |
| agent-8 (low) | `PADDOCK_DRY_RUN` parsing was fail-open | Fixed (only an explicit false word turns dry-run off) |
| agent-9 (low) | No self-lockout guard | Fixed, residual. `self_lockout` refusals and the dead-man timer; its report can be refused with a 409 (11 item 17) |
| agent-10 (low) | No inter-process exclusion on the state directory | Fixed (`.instance.lock`, `.state.lock`) |
| agent-11 (low) | The 24 h forced full package manifest was dead code | Fixed |
| wire-1 (low, canonical form) | "Stdlib canon equals RFC 8785" was false for inputs the server accepted | Fixed. Both sides cap `seq` at 2^53-1 and restrict `collectors` keys; the claim in section 2 now says exactly that |
| agent-12 (low) | Client invariants overstated (recursion, no total deadline, server not pinned, scheme case) | Fixed, residual (an abandoned name lookup cannot be cancelled: 11 item 18) |

**Collectors (9)**

| Finding | What it was | Outcome |
|---|---|---|
| coll-1 (high) | The sshd probe matrix never asked about users that `Match` blocks select, so HOLDS stood while passwords worked | Fixed, residual. One probe per distinct selection class; complete only for files-only NSS, otherwise `nss_users_unknown` (11 item 5) |
| coll-2 (high) | `reject with icmp/icmpv6` lost its implicit family and was modelled as a reject for both | Fixed |
| coll-3 (medium) | A conditional `return` in a policy-accept chain hid an accept path | Fixed (the always-terminating test is return-aware) |
| coll-4 (medium) | `ipv6_enabled` trusted the sysctl over `/proc/net/if_inet6` | Fixed (if_inet6 decides; unreadable or garbled is unknown) |
| coll-5 (medium) | `find_sshd` preferred `/usr/local` binaries and ran them as root | Fixed (the running daemon's binary, then the system PATH; `/usr/local` only when every directory up to `/usr` is root-owned and not group or world writable) |
| coll-6 (low) | Exponential-time firewall walks hung the agent on a small ruleset | Fixed (bounded by `WALK_BUDGET`) |
| coll-7 (low) | Protocol-field matchers were modelled more strongly than the kernel evaluates them | Fixed, residual (`ip6 nexthdr` is indistinguishable in `nft -j`: 11 item 6) |
| coll-8 (low) | Listeners decoded `/proc/net` hex as little-endian unconditionally | Fixed, residual (agent listeners and the v1 inventory follow `sys.byteorder`; the server decodes no such address; verified by faking the byte order only) |
| coll-9 (low) | An unprivileged user could force the listeners section to `error(truncated)`, widening edges | Fixed (a prioritised partial sample with `dropped`) |

**Host-config library (8)**

| Finding | What it was | Outcome |
|---|---|---|
| hostcfg-1 (medium) | `subset_of`/`count()` on `AllowUsers` held on a host with no `AllowUsers` | Fixed. Absent is Unknown (`unrestricted`); wildcard and negation lists are patterns, not sets |
| hostcfg-2 (medium) | `installed == false` held while an SSH daemon listened on a non-22 port under another name | Fixed in both halves (agent `tool_missing` rule; library allow-list over the listener table) |
| hostcfg-3 (low) | The collector silently truncated lists and `AuthenticationMethods` and still said exact | Fixed (`v.truncated`, approximate, the key is Unknown) |
| hostcfg-4 (low) | A `Match` that weakens a setting turned a certain violation into UNKNOWN | Fixed, residual (per-variant evaluation; two cases stay UNKNOWN: 11 item 5) |
| hostcfg-5 (low) | `ReachGraph.from_json` leaked `RecursionError`/`ValueError` and accepted duplicate keys | Fixed |
| hostcfg-6 (low) | sshd facts described the files, not the running daemon | Fixed, residual (`v.daemon` positive evidence, symlink and Include change times, `-g/-h/-c` overrides; a pending reload reads UNKNOWN, not VIOLATED: 11 item 5) |
| hostcfg-7 (low) | Host-controlled free text flowed unescaped into witnesses and findings | Fixed (restricted charset, capped) |
| hostcfg-8 (low) | The std ssh text and CLI output disagreed with what the registry checks | Fixed (text says "no root login by password"; the plan lists the listener collector too) |

**Builder and graph (9)**

| Finding | What it was | Outcome |
|---|---|---|
| hostfw-1 (high) | Host-claimed addresses decided a node's zone and CIDR membership: a compromised host hid from segmentation invariants | Fixed, residual. CIDR half closed (agent nodes are address-unknown). Zone: declared label wins; a claim and an observed peer must agree, else `zone_unknown` (UNKNOWN, never HOLDS). Residuals: a consistent lie by claim and peer (11 item 3); more than 64 zone-unknown nodes close no finding (11 item 4) |
| hostfw-2 (high) | Corroboration merged an attacker into any instance whose address is a shared egress (NAT or proxy) | Fixed, residual, by turning the merge off (the hardening's decision that a weak proof means do not corroborate; not one of O1 to O4, open to the owner). Rules 1 to 4 stay for a future trust root (11 item 2) |
| hostfw-3 (high) | The `agent_closed_scan_open` conflict cleared itself on one later signed "closed" posture | Fixed, residual. Sticky until a later full scan did not see the port; no operator action (11 item 9) |
| hostfw-4 (high) | A host that left the graph had its open finding closed as fixed | Fixed, residual. Only `passing_targets` close; UNKNOWN tombstones; label-changed hosts are an opt-out (11 items 8 and 10) |
| hostfw-5 (medium) | Any enrolled host could demote another's identity and blind its observed coverage by claiming an address | Fixed (as wire-5) |
| hostfw-6 (medium) | A pure re-sign of an unchanged posture bumped `graph_version` every time | Fixed (`store.digest_view`) |
| hostfw-7 (medium) | An oversized fact row was skipped, so the host silently left the std invariants | Fixed (`facts_too_large` error entries; the host stays in scope and UNKNOWN) |
| hostfw-8 (low) | Unrecognised rule tokens were treated as "does not match" instead of unknown | Fixed (tokens are validated; unknown ones widen) |
| hostfw-9 (low) | Attacker-chosen multi-second walks, quadratic identity resolution, verification on the event loop | Fixed, residual. Walk results cached across builds by firewall digest, verification in a worker thread, rebuild requests spaced to one per 10 s per agent; one hostile posture can still cost up to the per-agent budget (about 4 s, 100 M evaluations per build) |

**Packaging and release (13)**

| Finding | What it was | Outcome |
|---|---|---|
| pkg-1 (medium) | The documented `printf %s "$TOKEN" \| sudo ./install-agent.sh` always failed | Fixed (a token without a trailing newline works; the token is read first) |
| pkg-2 (medium) | `CapabilityBoundingSet` lacks `CAP_NET_RAW`: legacy iptables is unreadable and unusable, contradicting "limited to what the collectors need" and "firewall actions use netlink" | **Deferred (owner).** Widening the root agent's surface is an owner and contract decision. Documented exactly instead (section 8, 11 item 7, AGENT_V2.md section 3); the unit says why in a comment |
| pkg-3 (medium) | `sudo paddock rotate-key` while the service ran left the daemon on the retired key | Fixed (as agent-1) |
| pkg-4 (medium) | Re-running the installer swapped the archive under a live process and never restarted it | Fixed (restart and `is-active` check) |
| pkg-5 (low) | Every installer run overwrote `agent.env` | Fixed (other lines are kept) |
| pkg-6 (medium) | The docs pointed no-cosign operators at release-note digests that did not exist | Fixed (the release body carries the digests, and the docs say they are not independent of the release) |
| pkg-7 (low) | `curl -O` gives a non-executable script, so `./install-agent.sh` failed | Fixed (documented as `sh ./install-agent.sh`; a test pins it) |
| pkg-8 (low) | The installer clobbered an existing `/usr/local/bin/paddock` | Fixed (a wrapper, never over a foreign `paddock`) |
| pkg-9 (low) | The "byte-identical" build recipe gave another digest | Fixed (constant `SOURCE_DATE_EPOCH=315532800`; a test pins the recipe to `release.yml`) |
| pkg-10 (low) | READINESS said the agent events are audit rows only | Fixed (they are registered integration events) |
| pkg-11 (low) | Exit 7 after ten bare 401/403/404 was permanent | Fixed (as agent-2) |
| pkg-12 (low) | `release.yml` trusted any commit at a `v*.*.*` tag | Fixed, residual. `gate` job, SHA-pinned actions, cosign v2.5.2; the gate cannot stop a tag pusher, and the repository settings are **not applied** (**owner action**, 11 item 19) |
| pkg-13 (low) | Token hygiene gaps in the installer (inherited env, signals, symlinked dirs) | Fixed (partial in round 1: Ctrl-C at the prompt left echo off; QUIT and HUP are trapped too; `shellcheck` was not available to run on the last change) |

**Found by the verifiers (not among the 66)**, with their outcome: the schema integration defect above (fixed, round 2);
the pre-auth limiter was check-then-act (fixed with an atomic take and refund); a replayed captured envelope burned the
agent's budget (fixed with the replay bucket); the heartbeat and posture audit-row flood (fixed with `audit_aggregated`);
a repointed `sshd_config` symlink, a regex-backtracking `Match` matcher, `sshd -g`, wildcard allow lists and a
non-lower-case delta key (all fixed, round 2); zone-selected invariants read a false HOLDS under the shipped default for
an unplaced host (round 2: `zone_unknown`; round 3 made the zone depend on two agreeing hints and made a certain
violation close nothing when the possible run is cut off); stored identities without `peer_proxied` read as direct (fixed:
only an explicit false is direct); LIFO-only reverts, setuid loss on a cross-device quarantine, a hosts symlink replaced,
an environment proxy not covered by the self-lockout guard, a dead-man timer that never told the server, a hung name
lookup, Ctrl-C and an exported `ENV_TOKEN` at the token prompt, an over-claiming "owner decision" in the docs (all fixed);
open and low: audit rows on rotate, wrong-agent and garbage-bearer rejections, the enrollment fail-lockout race, the dead-man
409, an unsanitised server `detail` in the agent's log, older agents refused 422 (11 items 14 to 18).

**Owner decisions still open** (none is the code's to make; each says what the code does meanwhile):

1. **The v1 inventory route stays unsigned** (contract section 2 keeps it for the Fleet page; the agent sends it
   bearer-only). Sign it, or drop it?
2. **An operator route to clear a scan conflict, and one to pair an agent with an asset.** Neither exists; each needs a
   route, an RBAC decision and a migration (P2.1). Until then the conflict ages out or a full scan clears it, and no
   agent is merged.
3. **A trust root for identity (P2.1):** header-less NAT or VPN corroboration and consistent-lie zone placement
   (a claim and a peer that agree) need a server-verified signed instance identity or an operator pairing. Until then
   nothing is corroborated and a declared zone label is the remedy.
4. **Legacy iptables and `CAP_NET_RAW`:** leave it out (those hosts read UNKNOWN, `block_ip`/`firewall_rule` fail), or
   widen the unit. Open, pending the owner's confirmation.
5. **Tombstone scope and revoked agents:** keep a tombstone only while a finding is open (shipped), or keep every revoked
   agent (drop the `EXISTS` clause of `TOMBSTONES_SQL`); and whether revoked rows may ever be purged (none is, the cap is
   10 times the active cap).
6. **Zone-unknown behaviour at 65 or more agents without zone labels:** today a VIOLATED zone invariant closes no finding;
   a library or runner rule that does better needs a decision, as does shipping a Helm default that places agents.
7. **Disabled or deleted invariants keep their findings open** (runner-4, from P1): close, annotate or keep.
8. **Sensor scopes** (P1): whether a declared Sentry scope needs a technical check against observed flows.
9. **Release settings:** apply the GitHub environment, tag ruleset and branch protection (AGENT_V2.md section 1), then run
   `release.yml` once for real.
