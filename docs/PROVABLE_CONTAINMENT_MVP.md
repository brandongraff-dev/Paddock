# Provable Containment: MVP scope against the codebase

> **Status:** proposal, not built. Written from a read of the repo on 2026-11-24
> (`docs/*`, `correlation/app/engine/*`, `orchestrator/app/{audit,audit_anchor,licensing,verification,growth/trust,routers/*}`,
> `agent/paddock_agent/*`, `otdiscovery/app/exposure.py`, `schema/*`). Nothing was run.
> **Not inspected:** the AWS/GCP/Azure connectors' depth, `graphsync`, `remediation/`, `brain/`,
> `changewatch/`. Anything below that depends on them is marked *(verify)*.

## 0. The idea in one paragraph

Today Paddock answers *"what is wrong?"* with a list of findings. Provable Containment answers
*"what must never be true, and can anyone prove it is still not true right now?"*

1. An operator declares a short list of **invariants** ("nothing on guest Wi-Fi reaches the POS
   segment", "no server accepts SSH passwords", "no internet path reaches a data store").
2. A **counterexample search** keeps trying to break each invariant against the live model of the
   estate, and confirms any hit with a safe, scope-proven test.
3. Violations become ordinary findings that flow through the existing fix → approve → re-verify loop.
4. Every verdict that holds becomes a **signed, short-lived attestation** anyone can check with an
   **open verifier**, without trusting Paddock's UI, database or vendor.

The product claim is deliberately narrow and honest: *"no counterexample was found, across these
evidence sources, at this coverage, at this time."* Never "secure."

---

## 1. What exists vs. what is missing

| Need | What the repo has today | Gap |
|---|---|---|
| Asset/edge graph | `assets` + `asset_edges` (`schema/002_assets.sql`); edge `kind` is free text (`resolves_to`, `hosts`, `runs`, `references`, `member_of`) | Edges describe *discovery relationships*, not *network reachability*. No direction/port/protocol semantics, no "intended vs observed" basis. |
| Attack paths | `correlation/app/engine/attackpath.py`: Dijkstra over the **undirected** edge set, ≤8 hops, top 50, crown jewels guessed from tech names (`DATA_STORE_TOKENS`) | Built to *rank* paths, not to *prove absence*. Undirected + top-N + heuristic targets means it cannot back a "no path exists" claim. Keep it for prioritisation; do not reuse it for proofs. |
| Policy-as-code | `correlation/app/engine/policy.py`: YAML `ChainRule` (declarative) and `PolicyRule` (hand-written `SELECT` validated with sqlglot, `on_hit.create_finding`) | `PolicyRule` is "SQL that returns asset ids": cannot express reachability, host config assertions, evidence tiers, freshness or coverage. It is the seed of the compiler, not the compiler. |
| Segments | `otdiscovery/app/exposure.py`: `network_segment` assets, `member_of` edges, `ot_it_exposure` from **observed flows** | OT/IT only; segments come only from passive sensors. No cloud security groups, no host firewalls, no declared zones. |
| Verification | `orchestrator/app/verification/*`: 11 checks, append-only `finding_verifications` ledger, pinned IPs, scope + proof-of-control, verdict never closes a finding by itself | Checks run from the **worker's vantage point** (outside). "Guest → POS" needs a vantage point *inside* a segment. Checks are finding-centric, not invariant-centric. |
| Host agent | `agent/`: enroll, heartbeat, inventory (`os_info`, `packages` via dpkg/rpm, `listeners` via psutil, firewall `posture`), 5 host-local actions (`block_ip`, `block_domain`, `quarantine_file`, `firewall_rule`, `revert`) behind propose → four-eyes approve → apply, dry-run default, revert plans | Posture is thin (no sshd config, users/sudoers, patch state, integrity, egress, containers). Apply is Linux-only (Windows/macOS dry-run). Enrollment uses one shared `FLEET_ENROLL_TOKEN`. Inventory is unsigned, so the server cannot tell a lying agent from an honest one. No blast-radius preview, no auto-rollback timer, no post-apply invariant re-check. |
| Tamper-evidence | `audit.py` hash chain (keyed), `audit_anchor.py` anchors to file / S3 Object Lock / webhook | Anchors are **HMAC-signed** (`audit.sign_anchor`): only the key holder can verify, so a third party cannot. Needs an asymmetric signature for anything external. |
| Signatures | `licensing.py`: Ed25519 sign/verify (`PDK1.<payload>.<sig>`), vendor-key ceremony script | Reusable crypto pattern, but nothing for attestations, key discovery or revocation. |
| Public sharing | `growth/trust.py`: signed expiring trust links, aggregates only, every view audited | Token is a bearer secret (HMAC tag, or *unkeyed* if `PADDOCK_SECRET_KEY` unset). It is not a verifiable statement. |
| Domain-bound proof | `scope_proof.py`: DNS TXT / HTTPS file / attestation proof of control | Reusable to bind a signing key to a domain (§7.4). |
| Remediation | PR / config / dependency fixes behind approval; re-check after merge | Needs an invariant-aware trigger and verify step. |
| Quality gate | `docs/EVALS.md` detection gate: 207 seeded cases, precision/recall thresholds | Needs a new "invariant range" suite (§11). |

**Conclusion:** roughly 40% of the plumbing exists (graph storage, scope/proof, verification ledger,
audit chain, Ed25519, fleet gate, integrations, reports). The genuinely new work is the
**reachability model**, the **invariant compiler + evaluator**, **host posture v2**, and the
**attestation + verifier** stack.

---

## 2. Architecture

```
 SENSE (evidence, each edge/fact tagged with a tier)           MODEL                 REASON                    PROVE
 ─────────────────────────────────────────────────           ─────                 ──────                    ─────
 cloud connectors  (SG/NACL/route/IAM)  ── configured ─┐
 host agent v2     (listeners+fw+sshd…) ── configured ─┤                     ┌ invariant compiler
 Sentry flows      (otdiscovery)        ── observed ───┼─►  reach graph  ──► │ counterexample search ──► verdicts ──► attestation
 external scan     (worker-active)      ── observed ───┤    (directed,       │ confirmation probes        │            (DSSE, Ed25519)
 declared zones    (tenant config)      ── declared ───┘     versioned)      └ coverage + blind spots     ▼                │
 vantage probes    (agent/sentry, TCP)  ── tested ─────────────────────────────────────────────►  findings (rule_source          ▼
                                                                                                   'invariant') → existing   open verifier
                                                                                                   fix/approve/re-verify     + public bundle
```

**New deployables**

| Piece | Where | Notes |
|---|---|---|
| `assurance/` service | new top-level package, modelled on `ontology/` (own DB role in `schema/101_service_roles.sh`, `tenancy.py`, FORCE RLS, internal network only, no egress) | Hosts compiler, reach-graph builder, evaluator, scheduler. Takes the next free port (check `docker-compose.yml`). |
| Orchestrator routers | `routers/invariants.py`, `routers/attestations.py`, public `/v1/public/attest/*` | Orchestrator stays the only DB writer for tenant data, per `docs/ARCHITECTURE.md` "one idea". The assurance service calls its API like the other compute services. |
| `verifier/` package | new top-level, **zero imports from Paddock** | Standalone `paddock-verify`. Separately licensed (§8.5). |
| `docs/spec/` | the open spec, JSON Schemas, test vectors | Versioned independently of the app. |
| Agent v2 | `agent/paddock_agent/*` | New collectors, signed inventory, new guarded actions. |
| CLI | `cli/` | `paddock invariants lint|test|explain`. |
| Dashboard | `dashboard/src/pages/Assurance*.tsx` | Must live inside the owner's design (see `CLAUDE.md`): glass cards, `.class-pill`, pixel aurora behind the sheet. No restyling. |

Migrations: `schema/` currently ends at `038`, then `098`/`099` (audit keyed, tenancy re-apply).
New files take `039+`; `099_tenancy.sql` must still apply last so every new table gets `tenant_id` + FORCE RLS,
and `test_isolation_sweep.py` / `test_api_isolation_sweep.py` will fail until each new table and route is classified.

---

## 3. The invariant language and compiler

### 3.1 Design rules

- **Closed vocabulary, not SQL.** Authors pick from typed selectors, relations and host fields. No
  free-form queries (this is the main departure from `PolicyRule`).
- **Not Turing-complete.** Evaluation always terminates; cost is bounded by graph size.
- **Content-addressed.** `invariant_id` is human-readable (`std:no-internet-to-datastore`); `digest` is
  SHA-256 of the canonical form. Attestations bind to the digest, so an invariant cannot be weakened
  silently after the fact.
- **Standard library.** Namespaced `std:*` invariants have canonical definitions shipped and signed
  by the project. A consumer (insurer, procurement tool) can require specific `std:*` ids, so a
  customer cannot define a vacuous invariant and attest to it.
- **Defender-only.** Same reject-filter gates as `policy.py` for any free text; no field can name an
  exploit step.

### 3.2 Surface syntax (YAML, JSON-Schema validated)

```yaml
apiVersion: paddock.dev/invariant/v1
id: std:no-internet-to-datastore
title: No internet path reaches a data store
severity: critical
subjects:
  from: { zone: internet }
  to:   { tag: crown-jewel, class: data_store }
assert: unreachable
via:  { protocols: [tcp], max_hops: 6 }
allow:                                   # explicit, expiring, audited exceptions
  - to: { tag: public-replica }
    reason: "read-only marketing replica"
    expires: 2027-01-31
evidence:
  min_tier: observed                     # declared < configured < observed < tested
  max_age: 24h
  confirm: all                           # none | sample | all  (active confirmation of counterexamples)
coverage: { require: 0.95 }              # fraction of the subject universe with a live sensor
on_violation:
  finding: true
  propose: [restrict_port_to_cidr]       # only from the allow-listed fix catalogue
```

```yaml
apiVersion: paddock.dev/invariant/v1
id: std:server-ssh-hardened
title: Servers do not accept password or root SSH from the network
severity: high
scope: { select: { kind: host, tag: server } }
assert:
  all:
    - host.sshd.passwordauthentication == "no"
    - host.sshd.permitrootlogin in ["no", "prohibit-password"]
    - any:
        - host.listener(22).bind != "0.0.0.0"
        - host.effective_inbound(22).sources subset_of zone("admin")
evidence: { min_tier: configured, max_age: 6h }
coverage: { require: 1.0 }
```

### 3.3 Grammar (sketch)

```
invariant   := header subjects? scope? assertion evidence coverage actions
assertion   := "unreachable" | "reachable-only-via" selector | "exposes-only" portset
             | "count" cmp INT | expr
expr        := "all:" [expr] | "any:" [expr] | "not:" expr | predicate
predicate   := path cmp literal | path "in" list | path "subset_of" setexpr
path        := ("host"|"asset"|"edge"|"zone") ("." IDENT ("(" arg ")")? )+
selector    := "{" ("zone"|"tag"|"kind"|"class"|"cidr") ":" value ("," …)* "}"
```

Types come from a registry (`host.sshd.*`, `host.listener(port).bind`, `host.fw.default_inbound`,
`host.patch.kev_open_days`, `host.fim.changed`, `asset.tags`, …). Each registry entry declares the
evidence source it needs and the minimum tier it can reach, which is how the compiler knows what to
collect and how to compute coverage.

### 3.4 Compiler pipeline

1. **Parse + schema-validate** (pydantic models, same approach as `policy.py`). Reject unknown keys.
2. **Resolve** selectors and registry paths; reject references to evidence the tenant has no sensor for
   unless `coverage` explicitly tolerates it.
3. **Type-check** (comparators, set ops, units like `24h`).
4. **Canonicalise + digest.**
5. **Lower to a plan** (the IR the evaluator runs):

```
Plan {
  digest, tenant, kind: REACH | HOSTCONFIG | EXPOSURE_SET | AGE | META
  universe:  selector            # what coverage is measured against
  query:     ReachQuery | HostPredicate | SetAssertion
  evidence:  { sources[], min_tier, max_age }
  confirm:   { mode, probe_kinds[] }
  outputs:   { verdict_ttl, finding_template, fix_catalogue[] }
  deps:      [graph regions / host ids] # for incremental re-evaluation
}
```

6. **Dry-run explain**: `paddock invariants explain <file>` prints the plan, required sensors, current
   coverage and the first witness if one exists. This is also the sales demo.

### 3.5 MVP standard library (8 invariants)

| id | Kind | Evidence needed | Exists today? |
|---|---|---|---|
| `std:no-internet-to-datastore` | REACH | external scan + cloud SG + host fw | partial (external scan, ports) |
| `std:segment-isolation` (guest ↛ POS, IoT ↛ corp) | REACH | Sentry flows, switch/AP config | partial (`otdiscovery/exposure.py`) |
| `std:public-ports-allowlist` | EXPOSURE_SET | external scan ∧ agent listeners | partial |
| `std:server-ssh-hardened` | HOSTCONFIG | agent v2 | no |
| `std:server-default-deny-inbound` | HOSTCONFIG | agent v2 | partial (`posture`) |
| `std:kev-patched-within-N` | AGE | agent packages + intel KEV | partial (`intel`, `sca`) |
| `std:no-live-secrets` | HOSTCONFIG/META | secret scan + verify | partial |
| `std:coverage-complete` (meta) | META | every in-scope asset has a live sensor | no |

The meta-invariant matters most for honesty: it turns "we cannot see this" into a first-class,
attestable fact instead of a silent gap.

---

## 4. The reachability model (the biggest missing piece)

### 4.1 New data

```sql
-- schema/039_assurance.sql (illustrative; FORCE RLS added by 099)
reach_edges(
  id, tenant_id,
  src_ref, dst_ref,            -- asset id | zone id | cidr | 'internet'
  direction  TEXT,             -- 'allows' (src may open conns to dst)
  proto      TEXT, port_lo INT, port_hi INT,
  basis      TEXT CHECK (basis IN ('declared','configured','observed','tested')),
  source     TEXT,             -- aws_sg | host_fw | sentry_flow | external_scan | probe | tenant
  confidence SMALLINT,
  first_seen, last_seen, valid_until,
  evidence_ref UUID            -- → provenance row (existing provenance.py)
)
zones(id, tenant_id, name, kind, cidrs[], labels JSONB, source)   -- internet, guest, pos, admin, iot, prod…
asset_labels(asset_id, tag, value, source)                        -- crown-jewel, server, prod, owner, zone
```

Edges are **directed and typed**, and each carries its **basis tier**. `observed` beats `configured`
beats `declared` when they disagree; disagreement itself is a finding ("firewall says closed, flows
show traffic").

### 4.2 Edge builders (each a small, separately testable module in `assurance/builders/`)

| Builder | Input | Output edges | Basis |
|---|---|---|---|
| Cloud security groups / NACLs / route tables | existing cloud connectors *(verify what they pull today)*; extend to read SG rules, NACLs, route tables, peering, public IPs | cidr/SG → instance:port | `configured` |
| Host firewall + listeners | agent v2 | `src-cidr → host:port` where listener ∧ firewall permits | `configured` |
| External exposure | `worker-active` naabu / httpx results | `internet → host:port` | `observed` |
| Passive flows | `otdiscovery` / Sentry flow records | `device → device:port` | `observed` |
| Declared zones | tenant config (UI/YAML) | zone memberships + intended policy | `declared` |
| Vantage probes | §5.3 | confirms or refutes an edge | `tested` |

Optional shortcut for firewall rule-set reasoning: **Batfish** (open source) already models multi-vendor
configs; evaluating whether to import its reachability answers instead of writing a rule-set analyser
is a build-vs-buy decision to make in week 1.

### 4.3 Labels and crown jewels

Today crown jewels are guessed from technology names. Provable invariants need **explicit,
owner-assigned labels** (`crown-jewel`, `server`, `prod`, zone). Build a label editor and
import (tags from cloud, CMDB connectors already in `docs/INTEGRATIONS-CONTEXT.md`). An unlabelled
asset in an invariant's universe lowers coverage rather than being silently ignored.

---

## 5. The counterexample search

### 5.1 Static phase

- **Algorithm:** directed BFS/DFS over `reach_edges` filtered by the invariant's `via` (proto/port/hops),
  from source set to target set. Existence, not cost: stop at the first witness, then enumerate up to
  *k* distinct witnesses for the report. For `exposes-only` / `count` predicates, a set diff.
- **Soundness rule:** *prefer false positives to false negatives.* Unknown edges are treated as
  *possible* for `unreachable` assertions, so uncertainty lands in `UNKNOWN`, never in `HOLDS`.
- **Incremental:** each plan lists its `deps`. Subscribe to graph change events (`changewatch`
  *(verify event shape)*, agent inventory deltas, sensor batches) and re-evaluate only affected plans.
  Full sweep on a schedule as a backstop.
- **Property tests:** evaluator results must equal a brute-force reachability oracle on random graphs
  (hypothesis-style), and must be invariant under edge-order permutation.

### 5.2 Verdicts (fixed vocabulary)

| Verdict | Meaning |
|---|---|
| `HOLDS` | No counterexample in the evidence, coverage ≥ required, evidence fresh, min tier met. |
| `VIOLATED` | A witness path/host exists. Carries witness, per-hop basis and whether confirmed. |
| `UNKNOWN` | Coverage below requirement, evidence stale, or a required sensor silent. Lists blind spots. |
| `EXPIRED` | Previously `HOLDS`, now past `max_age`. Attestation lapses automatically. |

**Coverage** = observed-and-fresh members of the invariant's universe ÷ universe size. The blind-spot
list (which assets/segments, why) is stored and committed to in the attestation.

### 5.3 Confirmation phase (active, optional, strictly bounded)

For each static counterexample, confirm hops that are not already `observed`/`tested`:

- **New check kinds** in the verification service's pattern (`reach_tcp_connect`): TCP connect +
  immediate close, **no payload, no banner write**, one attempt per hop, per-target politeness
  limiter, 8 s timeout, result written to an append-only ledger like `finding_verifications`.
- **Vantage points are the new hard part.** Proving "guest ↛ POS" requires running the connect *from
  inside guest*. Candidates: a Sentry on that VLAN, or an agent on a host in that zone. This is a **new
  job type, separate from `agent_actions`**: the agent's rail #1 ("no field names a remote host to
  act on") is about *enforcement*, so a read-only connect test does not violate it, but it is a new
  capability. The owner has approved building it (decision 3), strictly under the gating below.
- **Every probe is gated exactly like today's verify:** `/v1/scope/check` allow ∧ proof-of-control
  `verified|attested` ∧ pinned `resolved_ips` ∧ per-request outbound audit. No scope, no packet.
- **Outcome mapping:** connect succeeded → edge becomes `tested` (witness *confirmed*); refused/timeout
  → edge demoted, invariant may flip to `HOLDS` at tier `tested`; error/rate-limited → `UNKNOWN`
  (never "fixed", same discipline as `VERIFICATION.md`).

### 5.4 From verdict to action

- `VIOLATED` → upsert a `findings` row with a new `rule_source = 'invariant'` (must be added to the
  `findings_rule_source_check` constraint **and** kept in lockstep in `test_rule_source_sync.py`),
  witness path in `evidence`, severity from the invariant. SLA clocks, tickets, SIEM/OCSF events,
  suppressions with reason + expiry, and reports then work unchanged.
- Fix proposals come only from a **catalogue** per invariant (`restrict_port_to_cidr`,
  `disable_ssh_password_auth`, `isolate_host`, cloud SG change PR). Each proposal includes a **blast-radius preview** computed from the graph: "closing 5432 from 0.0.0.0/0 affects 0 observed flows in 30 days".
- After apply/merge, re-run the invariant. Closing a finding is **never** automatic from a verdict
  alone (existing rule), but `HOLDS` at tier ≥ `observed` is what marks "verified fixed".
- Suppression/exception handling reuses the lifecycle model (`019_finding_lifecycle.sql`); an `allow:`
  entry in an invariant is the *declarative* equivalent and appears in the attestation as an exception count.

---

## 6. Server protection: what the agent must become

> **Honest scope note.** The MVP agent is **posture, exposure and containment**, not an EDR. It will
> prove "this server is hardened, only exposes what you allowed, and can be isolated", and detect
> drift. It will **not** detect malware or live intrusions. State that plainly in the product, and plan
> runtime detection as a later phase (§10).

### 6.1 Today (`agent/paddock_agent/*`)

Enroll with a shared `FLEET_ENROLL_TOKEN`; heartbeat; inventory = OS info, ≤2000 packages
(dpkg/rpm), listening sockets (psutil), firewall presence (ufw/nft/iptables). Five host-local actions,
Linux-only apply, dry-run default, four-eyes approval, revert plans. Needs `NET_ADMIN` + host
networking to apply.

### 6.2 Collectors to add (all read-only, no network egress beyond the Paddock API)

| Collector | What it reads | Feeds |
|---|---|---|
| **SSH** | `sshd -T` effective config (not file text) | `host.sshd.*` |
| **Accounts** | UID-0 accounts, sudoers (`sudo -l` structure), interactive users, `authorized_keys` **counts and key fingerprints**, never key material | `host.accounts.*` |
| **Listeners (rich)** | socket, bind address, owning process, executable path, **binary SHA-256**, user, systemd unit | `host.listener(port)` |
| **Effective inbound** | firewall ruleset **normalised** (iptables/nft/ufw → one canonical allow-list + default policy), combined with listeners → "what can actually be reached from which source CIDR" | reach edges, `host.effective_inbound` |
| **Patch state** | pending security updates (apt/dnf), kernel vs running kernel, reboot-required, unattended-upgrades enabled, package GPG verification on | `host.patch.*`, KEV age |
| **Integrity (FIM)** | hashes of a fixed critical set (`/etc/ssh`, `sudoers*`, `passwd`/`shadow` metadata, `authorized_keys`, systemd units, listener binaries); baseline + diff; never uploads content | `host.fim.changed` |
| **Egress baseline** | established outbound connections (process → dst:port), learned per host role | egress invariants, drift |
| **Containers** | docker/podman socket exposure, privileged containers, published ports, host-network mode, image digests | exposure set, SBOM link |
| **Services & persistence** | enabled systemd units, cron/timers, new SUID/SGID binaries vs baseline | drift |
| **Platform context** | cloud IMDS version required (IMDSv2), instance identity doc, disk encryption status, time sync, auditd/journald status | CIS-style subset *mapped to invariants, not a score* |
| **Self-health** | agent version, collector errors, clock skew, time since last successful full inventory | coverage + `UNKNOWN` logic |

Delivery: **delta reporting** with a periodic full snapshot, size caps and redaction (reuse the
verification service's redaction rules) so inventory stays small at fleet scale.

### 6.3 Making agent evidence trustworthy

The server currently has to believe whatever an agent posts. Required:

1. **Per-agent Ed25519 identity key** generated at enrollment; the agent signs every inventory/health
   post with a monotonic sequence number. Server verifies and stores the signature with the snapshot
   (so the attestation can say "evidence signed by agent key K").
2. **Per-tenant one-time enrollment tokens** instead of one shared bootstrap secret. Port the
   `sensor_enroll_tokens` pattern from `schema/034_sensors.sql` (hashed, expiring, single-use, revocable).
3. **Cross-validation against outside observation:** if the agent says port 5432 is closed but the
   external scan connects, the verdict is `UNKNOWN`/`VIOLATED` and an "evidence conflict" finding is
   raised. A compromised host cannot silently self-certify.
4. **Silence is signal:** missed heartbeats move dependent invariants to `UNKNOWN` after the sensor's
   `silent_after_s`, never leave them `HOLDS`.
5. **Agent integrity:** signed releases + SBOM (release pipeline exists per READINESS), signed update
   manifest, version floor enforced by the server.
6. **Privilege separation:** run collectors as an unprivileged user with only the needed ambient
   capabilities; split a tiny **applier helper** that executes allow-listed operations with fixed argv
   (no shell, no string interpolation) and is the only component holding `CAP_NET_ADMIN`.

### 6.4 Enforcement upgrades (`agent/paddock_agent/actions.py`, `platform_block.py`)

Keep the existing rails (host-local only, propose → approve, dry-run default, reversible, allow-listed
action types). Add actions that map to invariants, each with the new safety mechanics below:

| New action | Purpose | Guard |
|---|---|---|
| `restrict_port_to_cidr` | narrow a listener's reachability | preview shows observed flows that would break |
| `firewall_default_deny_inbound` | establish default-deny with an explicit allow-list | **never** removes the management channel or the current admin session's source |
| `disable_ssh_password_auth` | set `PasswordAuthentication no` | pre-check ≥1 key-based admin exists; validate with `sshd -t`; reload not restart |
| `disable_unit` | stop/disable an unneeded service | revert plan stores prior state; denylist of critical units |
| `isolate_host` | containment: allow only the Paddock control channel (+ operator-defined mgmt CIDR) | requires reason; auto-release timer; four-eyes except when policy marks it autonomous |

New mechanics for **all** actions:

- **Blast-radius preview:** from the reach graph + 30-day observed flows, list what stops working.
- **Confirm-or-revert timer** (like Junos `commit confirmed`): changes that can lock you out are
  auto-reverted unless the agent receives a confirmation within N minutes.
- **Post-apply verification:** re-run the invariant; if it does not flip to `HOLDS`, or heartbeat is
  lost, revert.
- **Ledger:** extend `agent_actions` with `preview`, `confirm_deadline`, `verified_by_run`.
- **Platforms:** MVP = Linux servers only (apply). Windows/macOS stay inventory + dry-run, and are
  labelled "unverifiable" so invariants over them report `UNKNOWN`, not `HOLDS`.

### 6.5 Packaging and rollout

`.deb`/`.rpm` + systemd unit + container image; cloud-init / Terraform snippet (the
`terraform-provider-paddock` already exists); one-line install with a one-time token; Ansible role.
Fleet page gets coverage and version-drift views.

---

## 7. Attestation format and signing

### 7.1 Format: reuse DSSE + in-toto, don't invent

An attestation is a **DSSE envelope** whose payload is an **in-toto Statement v1** with a Paddock
predicate. That gives a standard container, existing tooling (`cosign verify-blob-attestation`,
sigstore ecosystems), and a spec others can implement.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "domain:example.com", "digest": { "sha256": "<scope-digest>" } }],
  "predicateType": "https://paddock.dev/attestation/containment/v1",
  "predicate": {
    "seq": 1842,
    "issued_at": "2026-12-01T09:00:00Z",
    "valid_until": "2026-12-02T09:00:00Z",
    "policy": { "commitment": "<merkle-root of ALL declared invariants>", "disclosed": 8, "total": 9 },
    "results": [{
      "invariant": "std:no-internet-to-datastore",
      "digest": "sha256:…",
      "verdict": "HOLDS",
      "evidence_tier": "tested",
      "evaluated_at": "2026-12-01T08:57:12Z",
      "coverage": { "universe": 42, "covered": 41, "required": 0.95, "blind_spots_root": "<merkle>" },
      "exceptions": 1,
      "graph_root": "<merkle root of the reach-edge set evaluated>"
    }],
    "engine": { "name": "paddock-assurance", "version": "0.1.0", "ruleset_digest": "sha256:…" },
    "audit_anchor": { "tenant": "…", "max_id": 99120, "head_hash": "…", "alg": "sha256" },
    "prev": "sha256:<previous attestation>"
  }
}
```

Design choices that make it hard to abuse:

- **Policy commitment.** The attestation commits to the *entire* declared invariant set. Publishing
  only the passes shows "8 of 9 disclosed", and the verifier displays that. Silent cherry-picking is
  visible; policy edits are chained in the audit log.
- **Privacy by default.** Hostnames/IPs are **not** in the public statement. Blind spots and graph
  edges are Merkle-committed; the owner can disclose inclusion proofs to an auditor selectively.
- **Fixed verdict vocabulary and fixed human wording** (generated by the verifier, not the issuer) so
  nobody can phrase "HOLDS" as "SECURE".
- **Freshness is built in:** `valid_until` is short (default 24 h, refreshed). A stale attestation
  is worthless by construction.
- **Chaining:** `seq` + `prev` detect rollback or withheld updates.
- **`VIOLATED` visibility:** private by default; the owner chooses whether to publish. Withholding is
  detectable through the policy commitment (above).

### 7.2 Signing and keys

- **Algorithm:** Ed25519 (already a dependency and a pattern in `licensing.py`); `alg` field for
  agility (ECDSA P-256 for KMS/HSM backends that lack Ed25519).
- **Key hierarchy:** vendor root (offline, ceremony script exists) → **per-tenant attestation key**
  (cert signed by root, validity window) → statements. Tenant key lives encrypted in the DB, with a KMS/HSM
  or **bring-your-own-key** option. A compromised orchestrator then cannot mint attestations under a
  hardware-held key, which is the "don't trust the vendor" property enterprise buyers ask for.
- **Rotation / revocation:** short key validity, overlapping windows, signed revocation list
  (`revoked.json`) served next to the keys.

### 7.3 Fix the audit anchor first

`audit.sign_anchor` uses HMAC, so no third party can verify an anchor. Add `sig_alg: ed25519`
(version field `v` already exists in `Anchor`), publish anchors with the tenant attestation key, and
keep the S3 Object Lock sink. Attestations then bind to a chain head an outsider can verify. This is a
small, high-leverage change and a prerequisite for the claim "tamper-evident."

### 7.4 Binding a key to a domain without trusting Paddock

Reuse `scope_proof.py`: the tenant proves control of `example.com` (DNS TXT today). Extend it so the
same mechanism publishes the attestation key:

```
_paddock-attest.example.com. TXT "v=1; kid=ab12…; fp=sha256:…; keys=https://example.com/.well-known/paddock/keys.json"
```

The verifier checks the DNS record against the key, so "who is this attestation about" does not rest
on Paddock's say-so.

### 7.5 Transparency (phase 2, designed now)

Append each attestation hash to an append-only log with signed tree heads. Options: Sigstore Rekor, or
a small tile-based log (Merkle tiles on object storage, as `sunlight` does). The existing audit-anchor
sinks make the storage side easy. Not required for the MVP demo; reserve the `log_inclusion` field in
the spec so adding it later is not a breaking change.

---

## 8. The open spec and verifier

### 8.1 Spec deliverables (`docs/spec/containment-attestation-v1/`)

1. Normative text (RFC 2119 language): statement, predicate fields, verdict semantics, tier
   definitions, coverage computation, freshness rules.
2. **JSON Schemas** for the predicate, the invariant DSL, `keys.json`, `revoked.json`, the bundle.
3. **Canonicalisation** rules (RFC 8785 JCS) and hashing/Merkle construction (RFC 6962-style domain
   separation).
4. **Test vectors**: valid, expired, tampered, wrong-key, revoked-key, policy-subset, rollback,
   coverage-below-threshold.
5. **Conformance suite** that any implementation runs.
6. Versioning policy and a security considerations section (gaming, privacy, replay).

### 8.2 Bundle layout (static-hostable on the customer's own domain)

```
/.well-known/paddock/
  keys.json                      # key set + validity windows
  revoked.json                   # signed revocations
  attestation/latest.json        # DSSE envelope
  attestation/<seq>.json         # history
  proofs/<invariant>.json        # optional Merkle inclusion proofs (disclosed to auditors)
```

Paddock can host it (`GET /v1/public/attest/{domain}`), **or** push it to the customer's static
host (S3/Cloudflare/GitHub Pages). Verification must keep working if Paddock is offline.

### 8.3 Verifier behaviour (`paddock-verify <domain|file>`)

Checks, in order: schema → DSSE signature → key found in `keys.json` and **matches DNS binding** →
key validity and revocation → `valid_until` and consumer max-age → `seq`/`prev` continuity (if history
available) → policy commitment (`disclosed` vs `total`) → coverage meets *consumer's* threshold →
required `std:*` invariants present with required tier → (optional) audit-anchor cross-check and
Merkle inclusion proofs.

Consumer-side **acceptance policy** is the product for insurers/procurement:

```yaml
require:
  - { invariant: std:no-internet-to-datastore, verdict: HOLDS, min_tier: observed }
  - { invariant: std:server-ssh-hardened,       verdict: HOLDS }
max_age: 48h
min_coverage: 0.95
```

Output is human text plus `--json`; exit code 0 = accepted, 1 = rejected, 2 = unverifiable.

### 8.4 Implementations

- **Python reference** (`cryptography` only) first. It is the quickest to keep in sync with the app.
- **TypeScript** (WebCrypto Ed25519) so a browser page can verify locally, "paste a domain, nothing is
  uploaded". Shares the test vectors.
- Go/Rust static binary later for CI and procurement tooling.

### 8.5 Licensing (decision needed)

The repo is **AGPL-3.0**. Procurement and insurer systems will not embed AGPL code. Publish the spec
under a permissive licence with a patent grant and the verifier under **Apache-2.0**. The existing
CLA should allow this; **have a lawyer confirm** (READINESS already lists the CLA review as open).

---

## 9. API, data and UI surface

### 9.1 Orchestrator API (all tenant-scoped, RBAC via `auth.py` rules; new routes need explicit rules because the middleware is deny-closed)

| Method | Path | Notes |
|---|---|---|
| `GET/POST` | `/v1/invariants` | list / create from YAML (lint server-side) |
| `GET/PUT/DELETE` | `/v1/invariants/{id}` | versions are immutable, new digest per edit |
| `POST` | `/v1/invariants/{id}/evaluate` | on-demand; returns run id |
| `GET` | `/v1/invariants/{id}/runs` | append-only ledger with witness + coverage |
| `GET` | `/v1/reach` / `/v1/zones` / `POST /v1/labels` | model editing + queries |
| `GET` | `/v1/assurance/coverage` | blind spots by sensor |
| `GET/POST` | `/v1/attestations` | list; issue now (admin) |
| `POST` | `/v1/attestations/publish` | push bundle to a configured target |
| `GET` | `/v1/public/attest/{domain}[/…]` | public bundle (rate-limited like growth endpoints) |
| `POST` | `/v1/fleet/{id}/posture` | signed agent posture v2 |
| `POST` | `/v1/fleet/probes` | vantage probe jobs (gated, see §5.3) |

After adding routes run the repo's generation chain (CI checks it):
`python scripts/export_openapi.py && python sdk/python/codegen.py && node sdk/typescript/scripts/codegen.mjs`.

### 9.2 Licensing

Add feature flags to `FEATURES` in `licensing.py` (unknown names raise at import): `assurance`
(evaluation), `attestations_public` (publishing), `attestation_byok`. Per `EDITIONS.md`, gate only
*new* capability; existing Community features stay free. Suggested: invariants + evaluation in Team,
public attestations + BYOK in Enterprise.

### 9.3 Dashboard (inside the owner's design system)

Pages: **Assurance** (invariant list with verdict pills and freshness), **Invariant detail** (plan,
coverage, witness path on the existing graph canvas, run history, "explain"), **Coverage** (blind
spots by sensor), **Attestations** (current, history, public preview, "verify it yourself" link),
Fleet additions (posture v2, signed-evidence status, action preview). Use the glass card/panel
pattern, `.class-pill` for classification, no new rim/shadow/hover glow, no change to the wordmark,
aurora, topbar or landing. A **public verify page** is the one new landing-adjacent surface: ask the
owner before building it.

---

## 10. Phased build plan

Effort is relative and rough. "S" ≈ days, "M" ≈ 1–2 weeks, "L" ≈ 3+ weeks for one strong engineer
(AI-assisted). Everything lands behind feature flags.

| Phase | Deliverable | Size | Done when |
|---|---|---|---|
| **P0: Prove the loop on today's data** | Invariant DSL v0 (3 REACH + 1 EXPOSURE_SET), compiler, evaluator over a *minimal* directed reach graph built from existing assets + external scan + `member_of`/flows; `paddock invariants test`; findings with `rule_source='invariant'`; migration 039 | M | CLI demo: seeded graph with a planted guest→POS path is flagged with a witness; removing it flips to `HOLDS`; property tests pass |
| **P1: Reach graph + coverage** | `reach_edges`/`zones`/`asset_labels`, builders for cloud SG (AWS first), host fw (via P2 data), Sentry flows; `std:coverage-complete`; coverage + blind spots; incremental evaluation | L | Coverage % and blind spots shown for a seeded tenant; `UNKNOWN` verdicts appear when a sensor is silenced |
| **P2: Agent v2 (servers)** | Collectors (§6.2), signed inventory, per-tenant enrollment tokens, cross-validation, 3 HOSTCONFIG invariants, `std:kev-patched-within-N` | L | Fresh Ubuntu/RHEL VM enrolls, reports signed posture, `std:server-ssh-hardened` evaluates; tampered inventory rejected |
| **P3: Attestation + verifier** | Anchor → Ed25519, DSSE/in-toto statement, tenant keys + cert, DNS key binding, bundle publisher, `paddock-verify` (Python), spec v1 + vectors + conformance | L | A third party with only the domain name verifies a live attestation offline of Paddock; every tamper vector rejected |
| **P4: Safe enforcement** | New actions (§6.4), blast-radius preview, confirm-or-revert timer, post-apply re-verify, `isolate_host` | M–L | Applying `disable_ssh_password_auth` on a test VM auto-reverts when the confirm is withheld; invariant flips to `HOLDS` when confirmed |
| **P5: Confirmation probes** | In-zone vantage probe job type, `reach_tcp_connect` check, ledger, scope/proof gating | M | A witness path is *confirmed* from a Sentry/agent vantage; out-of-scope target is refused with ledger row |
| **P6: UI + public page + evals** | Assurance pages, public verify page, invariant eval suite in CI | M | Demo script end to end; eval gate green |
| **Later** | Transparency log, TS verifier/WASM, Windows agent, runtime detection (auditd/eBPF exec + network baselines), identity invariants (Okta/Entra), Batfish-grade multi-vendor firewall reasoning, per-service keys (READINESS gap) | – | – |

**Thinnest sellable slice:** P0 + P1(cloud SG + external scan) + P3 + a slim P2 (SSH + listeners +
firewall). That is "attest that nothing from the internet reaches your databases and your servers are
SSH-hardened", verifiable by a customer's insurer.

---

## 10a. P0 status (implemented in `assurance/`)

P0 shipped as a **pure library + CLI** (`paddock-invariants lint|test|explain|std`), 803 tests, with
three standard invariants (`std:no-internet-to-datastore`, `std:guest-cannot-reach-pos`,
`std:public-ports-allowlist`). Deviations from the plan above, and why:

- **No database or findings wiring yet.** `rule_source = 'invariant'` touches the DB CHECK, `constants.py`,
  `test_rule_source_sync.py`, OpenAPI and both SDKs; it moves to P1 with the persistent graph.
- **Own console script, not `paddock invariants`.** The existing CLI is deliberately stdlib-only; this
  package needs `pydantic` and `PyYAML`.
- **Coverage semantics refined (supersedes §5.1/§5.2 wording).** Coverage is a property of *nodes*. A connection
  needs both ends to allow it, so one covered end rules an edge out and unknown edges exist only between
  two blind nodes. The evaluator re-searches with a clique among blind nodes; a target reachable only that
  way is `UNKNOWN`. `coverage.require` is a separate, consumer-visible floor on the share of known assets covered.
- **Application boundary (`via.stop_at`) added.** The first run flagged a *clean* three-tier estate, because
  internet -> LB -> web -> app -> database is a transitive path in every ordinary architecture. The search
  now reaches but does not pass through nodes the tenant labels as a boundary. Consequence for later phases:
  **labels are tenant-controlled, so a boundary can be abused to make an invariant vacuous.** The boundary is
  part of the digest and reported in every result; P3 must also commit to the boundary node set in the
  attestation, and label provenance (who set it, when) needs to be audited.
- **Witnesses are root causes.** A target reachable only through another violating target is counted but not
  repeated as its own witness.

## 11. Testing and quality gates

1. **Invariant ranges** (extend `docs/EVALS.md`): synthetic estates with planted paths and
   misconfigurations, scored on precision/recall, time-to-witness, **unsafe-probe attempts (must be 0)**.
2. **Evaluator soundness:** brute-force oracle comparison, permutation invariance, monotonicity (adding an
   `allows` edge never turns `VIOLATED` into `HOLDS`).
3. **DSL fuzzing:** hostile YAML (the repo already fuzzes ingest and scope): size/depth limits, no
   unbounded evaluation, reject filter.
4. **Attestation conformance:** the spec's test vectors run against Python and TS verifiers; mutation
   tests (flip a bit in every field → must reject).
5. **Agent:** extend `agent/tests` for each collector with captured fixtures from several distros;
   chaos tests for lock-out scenarios (the confirm-or-revert timer is the safety net).
6. **Tenancy:** new tables and routes pass the isolation sweeps; attestations never contain another
   tenant's data; public endpoints join `test_public_surface_adversarial.py`.
7. **Time-to-green:** the READINESS workflows that have never run (install, release, scale) should run
   before this ships, or attestations will rest on an unproven base.

---

## 12. Risks and decisions the owner must make

**Threats to the feature itself**

| Threat | Mitigation |
|---|---|
| A compromised or lying host self-certifies | Signed evidence + outside-in cross-validation + silence → `UNKNOWN` (§6.3) |
| Compromised Paddock mints false attestations | KMS/HSM or BYO key, transparency log, anchors an outsider can verify |
| Vacuous invariants ("1 == 1") | `std:*` library; consumers require named invariants |
| Cherry-picked publication | Policy commitment shows `disclosed` vs `total` |
| Attestation used as attacker recon | No hostnames/IPs in the public statement; Merkle commitments; `HOLDS` only by default |
| Over-claiming → liability | Fixed vocabulary, mandatory coverage/tier/time fields, terms of use, legal review |
| Wrong "HOLDS" from stale or partial data | Unknown edges treated as possible; freshness and coverage are inputs to the verdict |
| Lock-out from enforcement | Confirm-or-revert timer, management-channel protection, four-eyes, dry-run default |

**Decisions needed before P3/P5**

1. **Verifier and spec licence** (Apache-2.0 recommended) and CLA confirmation.
2. **Key custody:** hosted signing only for the MVP, or BYOK/KMS from day one? (Recommend: hosted key + published roadmap to BYOK; BYOK before the first enterprise/insurer deal.)
3. **In-zone vantage probes (§5.3):** *approved by the owner (built in P5)*: a new read-only TCP-connect capability for agents/Sentry, under existing scope/proof gating. Without it, REACH invariants top out at tier `observed`.
4. **Default visibility** of attestations: private-by-default with explicit publish (recommended) vs public by default.
5. **First buyer:** MSPs (multi-tenant console exists) vs cyber-insurance carriers vs vendors answering questionnaires. It decides which invariants and acceptance policy ship first.
6. **Naming/placement:** a product tier in `EDITIONS.md` and a new section in the owner-approved dashboard; the owner has given standing sign-off for UI work (`CLAUDE.md`), so no further approval is needed.

**Explicitly out of the MVP:** runtime/EDR detection, Windows/macOS enforcement, identity (IdP)
invariants, Wi-Fi/RF sensing, firmware, the Shield client, multi-vendor firewall equivalence proofs,
a public transparency log.
