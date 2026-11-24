# Provable Containment, P2: agent v2 for servers

> Status: design contract for P2. Companion to [ASSURANCE_P1.md](ASSURANCE_P1.md) (the reach graph,
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
| E3 | A managed host is a node `agent:<agent_uuid>` (new ref prefix, kind `host`). It is replaced by `asset:<cloud uuid>` only when **corroborated** (the agent's IPs are a subset of exactly one AWS instance's private IPs and no other agent claims it). **No new `assets.kind`.** | A new asset kind touches the DB CHECK, `AssetKind`, both SDKs and the dashboard. |
| E4 | Enrollment tokens `fet_<prefix>_<secret>`: single-use by default; optional `max_uses <= 50` with `ttl <= 24h` for cloud-init fleets. Atomic redeem, generic 401, per-IP rate limit and fail lockout (copy `sensors.py`). Prefix is 12 hex. | |
| E5 | Std host invariants: `coverage.require: 1.0`, selector `tag: [agent, server]` (a declared `server` with no agent is `UNKNOWN: no_agent`, never silently out of scope). | A silent server may be the compromised one. |
| E6 | The cloud metadata (IMDS) request is **off by default**, opt-in per agent config. | "No egress beyond the Paddock API." |
| E7 | Install path: signed single-file **zipapp** + `scripts/install-agent.sh` (pins a release tag, verifies sha256, cosign bundle when `cosign` is present). deb/rpm are P2.1. | Needs no repo hosting or key custody. |
| E8 | Posture history is stored **only when the content digest changes or at most hourly**; retention defaults `agent_posture` 90 d, `agent_inventory` 30 d. | Bounded growth. |

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
| `POST /v1/fleet/agents/{id}/revoke`, `POST /v1/fleet/agents/{id}/keys/{key_id}/revoke` | admin | `{reason}` |
| `GET /v1/fleet/agents/{id}/posture` | `triage` | full latest posture (the summary `GET /agents/{id}` stays viewer-safe) |

The v1 `POST /v1/fleet/{id}/inventory` route and `InventoryIn` (`extra="forbid"`) stay for the
Fleet page but are only accepted from non-legacy agents and are marked `unsigned`: never evidence.

**Envelope v1** (JSON body, optional gzip; `Content-Type: application/json`):

```
{ "v":1, "alg":"ed25519", "kid":"<hex(sha256(pub32))[:32]>", "agent_id":"<uuid>", "tenant_id":"<uuid>",
  "kind":"posture|heartbeat", "seq":<uint>=1>, "issued_at":"YYYY-MM-DDTHH:MM:SSZ", "nonce":"<b64url 16B>",
  "payload_type":"paddock.host.posture/v2", "payload_sha256":"<hex>", "payload_len":<int>,
  "collectors":{"agent":"0.2.0","sshd":"1","listeners":"1","firewall":"1","patch":"1","self":"1"},
  "payload_b64":"<b64url of the exact payload bytes>", "sig":"<b64url 64B>" }
```

* **Signing input** = `b"paddock-agent-envelope/v1\n" + canon(header)` where `header` is every field **except**
  `payload_b64` and `sig`; `canon(x) = json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=False,
  allow_nan=False).encode("utf-8")`. **No floats anywhere in the header or payload** (ints, strings, bools,
  lists, objects only), so the stdlib form equals RFC 8785 for these inputs. The payload is bound by
  `payload_sha256` over the decoded bytes; the server never re-serialises it.
* **Server checks, in this order, each failing closed with its own code and an audit row
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
* Agent seq is persisted **write-ahead** (fsync before sending N). A wiped state dir means re-enrollment with a
  new token and key on the same agent row (old key revoked with a reason, history kept).
* Rotation: agent generates `K2`, posts `rotate` signed by `K1` with `K2` + proof-of-possession; `K1` becomes
  `rotated`. Admin revoke sets `revoked` immediately; nothing is cached.
* Enrollment `proof_b64` = signature by the new key over `b"paddock-enroll/v1\n" + token_prefix + "\n" + hostname`.

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
   `conf: approximate, source: text`, **which never yields HOLDS**; sshd absent => `unavailable(tool_missing)`.
3. **listeners**: stdlib `/proc/net/{tcp,tcp6,udp,udp6}` (little-endian hex addresses; TCP LISTEN `0A`; UDP bound
   `07`), inode -> pid via `/proc/*/fd`, per listener `proto, ip, port, bind_class, uid, pid, comm, exe (+deleted
   flag), exe_sha256 (cache by dev/inode/mtime, cap 128 MiB), unit or container id (cgroup)`. Never record argv.
   Cap 2000. Containerised agent => `unavailable(containerised_agent)` for host-binary facts.
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
   `unavailable(permission_denied)`. Cap 2000 rules (over => `error(truncated)`).
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
  hosts listed as blind spots); else `HOLDS`. Empty selector = `UNKNOWN: empty_selector:to`.
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

Std invariants shipped in P2 (`stdlib/*.yaml`; baseline is digest-bound, so changing it is a new version):

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
  posture; 4xx stay audited. This also fixes the existing enforce-mode bug (fleet routes were admin-gated, so agents
  could not work outside dev mode or outside the default tenant).
* `app/fleet_enroll.py` (token mint/redeem/revoke, ported from `sensors.py`), `app/fleet_posture.py` (verify, seq
  claim, digest dedupe, store, audit rejections, `last_seen`, `reach_node_facts` write is the **builder's** job,
  not ingest's), changed digest => `assurance_state.last_build_at = NULL` so the runner rebuilds within a tick.
* `fleet_agents.node_ref` and identity: set at enroll/posture. Two agents claiming one cloud node => neither merges
  (a note is emitted).
* Gating: enrollment, posture ingest and the `host_fw` build are free (Community); evaluation and std-invariant
  enablement stay under the existing `assurance` Team feature (no new FEATURES entry).
* Monitor: `fleet_agent_monitor_loop` (copy of `sensors.monitor_loop`) sets `online/offline_since` and emits
  `agent.offline/online` events; `silent_after_s` default 300 drives builder staleness.

## 7. Server: `host_fw` builder and the facts path (P1 extensions)

### 7.1 `orchestrator/app/assurance/builders/host_fw.py`

`SOURCE = "host_fw"`, mode `replace`, registered **after** `external_exposure` in `BUILDER_NAMES`.
`load(conn, now)`: latest verified posture per non-revoked, non-legacy agent (+ `last_seen`, `silent_after_s`), the
ip-map rows (`_ipmap`, extended with agent identities), and existing `external_scan` edges/coverage. Pure `build()`:

* Node identity (E3): corroborated cloud instance `asset:<uuid>`, else `agent:<uuid>`. All agent IPs go into
  `NodeOut.attrs.ips` (zone resolution). Never fall back to `ip:` for a managed host.
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
* **Conflicts**: if `external_scan` observed an internet-reachable `(proto, port)` on this node newer than
  `posture.collected_at - 5 min` that the agent models as closed => **no coverage**, `facts.conflicts[]` gets
  `{kind: "agent_closed_scan_open", proto, port, scan_seen_at}`. A conflict never turns into a pass.
* **Facts** (`BuildOutput.facts`): compact `host_agent` facts per node (sshd keys, firewall defaults/engine/confidence,
  pending-security count, reboot-required, conflicts, identity basis).

### 7.2 Interface deltas (small, additive; owned by one package)

`types.py`: `FactOut(node_ref, source, tier, observed_at, facts)` and `BuildOutput.facts` (default empty, so existing
builders are untouched). `refs.py`: new prefix `agent:<uuid>` (kind `host`). `store.persist_build`: replace this
source's `reach_node_facts`, `BuildReport.facts_changed` (digest of facts minus timestamps) sets `changed`
(graph_version bump); `_prune_nodes` also checks the facts table. `graph_loader`: emits `nodes[].facts` and
auto-tags nodes with agent facts `agent` (metadata, declared labels still override). `findings_sync`:
`target_of/describe_witness` handle hop-less host witnesses (`assertion == "host-config"`). Runner: new opts
`agent_posture_max_age`, nothing else.

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
  dry-run default and approve-before-apply rails are untouched.
* Packaging (E7): `agent/packaging/build_zipapp.py` (stdlib `zipapp`), `scripts/install-agent.sh` (POSIX sh, pins tag,
  verifies sha256, cosign if present, creates unit, enrolls with the token from stdin/env never argv, `--dry-run`,
  `--uninstall`), a `release.yml` job producing `paddock-agent.pyz`, `SHA256SUMS` and a cosign bundle.
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

Signed is not true (cross-validation covers only ports the external scan or cloud config can see). The firewall model
is `approximate` for ipset/mark/DNAT/Docker, so those hosts stay `UNKNOWN`, not `HOLDS`. A root network-facing process
(O2). The Python-3.6 case (RHEL 8 default interpreter) needs the `python39` module or is unsupported. The vendored
signer is not constant-time. AWS instance identity is not verified cryptographically (IP-overlap corroboration only).
No KEV matching (O4), no accounts/FIM/egress/containers collectors, no Windows/macOS, no deb/rpm, no distro advisory
data. Reports of 1 and 2 above and the open P1 risks (std invariants only `HOLDS` with strong coverage, tenant-wide
coverage floor) are tracked in ASSURANCE_P1.md and must be resolved before P2 evaluates real tenants.

## 12. Background

Scouting reports (six, about 175 KB, may contradict the decisions above): the session scratchpad
`.../scratchpad/p2/scouts.json`, keys `agent, fleet, signing, collectors, invariants, integration`; real captured
command output for fixtures: `.../scratchpad/p2/fixtures-collectors/` and `fixtures-signing/`.
