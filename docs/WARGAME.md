# Wargame: reachability, choke-points, and the Proving Ground

> Strix tells you an app has holes. Paddock tells you whether anyone can reach
> what you care about, proves it on a copy, and proves the door stays shut.

Most attack-surface tools stop at a list of *possible* problems. Paddock's
Wargame line answers the inverse — and the only — question a CISO, board or
insurer actually pays for:

> **Can an attacker reach what we care about, what is the smallest set of fixes
> that cuts every route, and have we *proven* the door is shut?**

It is built in two parts, both of which ship in this repo.

---

## Part 1 — Reachability, choke-points and coverage (the `correlation` service)

The correlation service already computes **attack paths**: weighted routes
through the asset graph from an internet-facing source to a crown-jewel target
(`007_tier1` `attack_paths`, `correlation/app/engine/attackpath.py`). Part 1
turns that forward list into a defensive answer.

### Reachability & crown-jewel exposure
`correlation/app/engine/reachability.py` → `crown_jewel_exposure`

For every crown jewel it computes how many internet-facing sources can reach it,
over how many open paths, in how few hops, the worst exploitability, and whether
it is **proven closed** — no source can reach it in the model. A jewel that is
unreachable is evidence of *absence*, which a forward-only exploit search cannot
produce.

### Choke points — the minimum cut
`correlation/app/engine/chokepoint.py` → `choke_points`

Working **backward from the crown jewels**, a node-capacitated minimum cut
(max-flow / Dinic over the asset graph, every node split `v_in→v_out` with unit
removal cost, sources and jewels given infinite capacity) finds the **smallest
set of assets whose removal cuts every path**. Ranked greedily, it yields "cut
these 3 and 86% of paths to your crown jewels are gone" — a remediation plan,
not another backlog. This is the opposite of a 10,000-row findings list.

### Path coverage — the headline number
`correlation/app/engine/coverage.py` → `coverage_snapshots`

Every path is classified from the verification + lifecycle state of the findings
on it:

| Class | Meaning |
|---|---|
| `proven_closed` | every flagged hop re-checked and no longer reproducible |
| `risk_accepted` | every flagged hop consciously accepted / false-positive / won't-fix |
| `tripwired` | a decoy/canary watches the open route *(reserved; 0 until tripwires ship)* |
| `open` | anything else, including reachable-but-unproven |

`coverage_pct = (closed + tripwired + accepted) / total`. Each **hop** is also
labelled `proven` (a safe check confirmed or shut it) or `inferred` (known only
from graph structure) — the evidence-per-hop story that keeps the number honest.

---

## Part 2 — The Proving Ground (the `wargame` service)

A safe check says a finding is *probably* real. For the hops that matter,
defenders want certainty and auditors want proof. The Proving Ground runs the
**real** exploit — but in a sealed room.

### The one invariant (enforced in code, `wargame/app/sandbox/guard.py`)

> A scenario only ever runs against an **isolated replica the customer owns**,
> on an internal-only network with **no route out**. There is no
> "run against production" path anywhere in the service.

- **Replica, never a live target.** The component is rebuilt from its own
  image / SBOM / config as a throwaway replica (`SandboxSpec` can only describe
  an image to *build*, never an address to reach).
- **No egress.** Replicas run on a Docker `--internal` network, no published
  ports, `--cap-drop ALL`, `no-new-privileges`, resource caps, and a hard TTL.
- **Fail closed.** `IsolationGuard` verifies, before any scenario runs, that the
  replica's network is internal, its endpoint is a sandbox-internal alias (never
  a routable or metadata address), and the backend confirms isolation. Any doubt
  → `IsolationError`, the replica is destroyed, nothing runs.

### How a run works
`wargame/app/engine/prover.py` (orchestration) + `wargame/app/scenarios/`

1. Pick the scenario that matches the hop (CVE repro, default-credential,
   unauth endpoint, …).
2. Build the replica in its **current** (suspect) state; run the scenario's
   check → the **before** verdict (expected: vulnerable).
3. Apply the candidate fix (patched image / changed config); re-run → the
   **after** verdict (expected: not vulnerable).
4. Destroy the replica.

### The proof
`wargame/app/engine/signing.py` → `wargame_proofs` (append-only, hash-chained)

Each run emits a chained, signed sequence `setup → before → fix → after →
summary`:

```
payload_hash = sha256(canonical_json(payload))
entry_hash   = sha256(prev_hash || payload_hash || phase || seq)
signature    = HMAC-SHA256(key, entry_hash)
```

A verifier replays the chain and checks every link and signature, so the proof
an insurer or customer reads cannot be forged, reordered or silently truncated —
even though the tenant runs the service. In production the signing key is
hardware-/KMS-bound; an empty `WARGAME_SIGNING_SECRET` is unsigned dev mode (the
hash chain still protects integrity).

### Outcomes
`proven_exploitable` (before vulnerable, no fix proven) · `proven_fixed`
(before vulnerable, after not) · `not_exploitable` (before not vulnerable) ·
`inconclusive` · `refused` (isolation/ownership) · `error`.

### Scope
The Proving Ground is **off by default** (`WARGAME_ENABLED=false`) and needs an
explicit sandbox backend. The default `fake` backend builds nothing (for CI and
dry runs); real runs use the `docker` backend. It changes nothing about the
scope you may point Paddock at: it only ever builds and attacks replicas of
components you already own.

---

## Why this is defensible and fundable

- **Breadth through one model** — choke points and coverage read the same twin
  the rest of Paddock writes, so "guest-Wi-Fi → fridge → payment server" is one
  query, not four tools.
- **Precision through proof** — evidence-per-hop, a signed before/after on a
  replica, and a coverage number that only counts what's actually shut.
- **Safety as the product** — copy only, no egress, fail closed. This is what
  lets a hospital, a utility or a factory run real exploit validation at all.

## Status

Part 1 (reachability, choke-points, coverage) is implemented and tested in the
`correlation` service against the live schema. Part 2's engine — isolation
guard, sandbox backends, scenario library, prover and signed proofs — is
implemented and tested with the in-memory `fake` backend; the `docker` backend
is written to the same interface and runs real replicas where a Docker daemon is
available (it is not exercised in CI, which has no docker-in-docker). See
`docs/READINESS.md` for the gap list.
