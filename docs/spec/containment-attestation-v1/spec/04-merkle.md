<!-- SPDX-License-Identifier: Apache-2.0 -->
# 04. Commitments: blinded Merkle trees

Normative for the tree construction, the leaf records of the policy and blind-spot trees and the proof file.
The graph tree's record shapes are normative for what is *hashed* but a verifier treats the graph root as an opaque
commitment: it never rebuilds it.

A statement commits to three things with RFC 6962 trees, so an auditor who is later shown chosen leaves can check
them against the signed roots, while the public sees only roots and sizes:

* the **graph** (`snapshot.graph.root`): the single graph every result was evaluated on;
* the **policy** (`policy.commitment`): ALL declared invariants, enabled or not;
* the **blind spots** of each result (`results[].blind_spots.root`).

## 1. Construction

* **Leaf record**: a PCJ object that always contains `"tree": "graph" | "policy" | "blind"` (cross-tree domain
  separation) plus the record fields. `leaf_json = PCJ(record)`.
* **Nonce** (32 bytes): `HMAC-SHA256(commit_key, b"paddock/leaf-nonce/v1\x00" || SHA256(leaf_json))`. `commit_key`
  is a per-estate random 32-byte secret, not the signing key, so an HSM or KMS never has to compute HMACs.
  Deterministic nonces keep roots stable across refreshes when nothing changed.
* `leaf_hash = SHA256(0x00 || nonce || leaf_json)`; `node_hash = SHA256(0x01 || left || right)`.
* The tree shape is RFC 6962 `MTH`: split at the largest power of two strictly below `n`. The empty tree root is
  `SHA256("")` = `e3b0c442...b855`. There is no odd-node duplication. Roots are written `sha256:<hex>`.
* **Leaves are sorted by `leaf_hash`** (a set commitment, independent of input order). Identical leaves collapse to
  one; `size` is the number of distinct leaves.
* Blinding means that guessing a low-entropy leaf (an IP address, a port) from a root is infeasible without
  the nonce.

## 2. Inclusion proofs

A proof file (never served publicly, [06](06-bundle.md)) has exactly these keys:

```json
{"v":1,"tree":"policy","size":3,"index":0,"nonce":"<64 hex>","record":{"id":"std:server-ssh-hardened","digest":"sha256:...","enabled":true,"source":"std"},"path":["<64 hex>","<64 hex>"]}
```

The verifier rebuilds `leaf_json = PCJ({"tree": <tree>, ...record})` (the record MUST NOT contain `tree`),
computes `leaf_hash`, and walks `path` with RFC 9162 section 2.1.3.2, with **no per-hop direction flags**:

```
verify(leaf_hash, index, size, path, root):
    if index >= size: fail
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0: fail
        if fn & 1 or fn == sn:
            r = H(0x01 || p || r)
            if not fn & 1:
                while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else:
            r = H(0x01 || r || p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root
```

Any failure is `merkle.proof_invalid`. The proof's `size` is authenticated only through the root: a leaf in the
left part of a tree verifies for several sizes, so a consumer that knows the expected size (for example
`blind_spots.size`) MUST compare it. Because the tree label is inside the hashed leaf, a graph leaf offered as a
policy leaf fails. Requested but unsupplied proofs are `merkle.proof_missing`.

Vectors (`vectors/primitives/merkle.json`): leaf and node hashes, trees of 0 to 17 leaves, a proof for every index
of sizes 1, 2, 3, 5, 7, 8, 9 and 17, bad proofs (wrong index, wrong size, truncated or extended path, flipped bits,
swapped order) and proof files including cross-tree confusion.

## 3. The three trees

### 3.1 Policy tree

One leaf for **every** declared invariant, enabled or not (rows are archived, never deleted):

```
{"tree":"policy","id":INV,"digest":H,"enabled":bool,"source":"std"|"custom"}
```

`policy.total` is the number of leaves. A verifier cannot recompute the root (it does not know the nonces); the
counts are the public check: `disclosed <= enabled_std + enabled_custom <= total`. Policy edits change the
commitment:

| Event | Effect on the next statement |
|---|---|
| create a custom invariant | a new leaf; `total` and `enabled_custom` rise; not disclosed unless `disclosure.custom` |
| enable a std invariant | a copy of the shipped definition; its digest must equal the registry's |
| edit a custom invariant | a new digest and `versions + 1`; a verifier holding the previous statement reports `digest.changed` |
| disable or archive | the row stays, `enabled` flips, the result disappears, the enabled counts fall, `total` stays |
| a row is physically deleted | `total` or `versions` decreases: `policy.shrank` against the previous statement |

### 3.2 Blind-spot tree (one per result)

```
{"tree":"blind","inv":INV,"node":<node ref>,"direction":"in"|"out"|"both"|"host","reason":<string>,"relevant":bool,"collector"?:<string>}
```

for each blind spot of the **full** in-memory result, before the engine's storage cap. Node references are private
data and appear only inside blinded leaves.

### 3.3 Graph tree

One tree built from the same document the engine evaluated. Leaves, all with `"tree":"graph"`:

* `{"t":"node", ...}`: each node of the document without its `coverage` and `facts` keys (so identity, kind, zone
  and every label the loader emits are committed);
* `{"t":"edge", ...}`: each edge after address-range expansion;
* `{"t":"cov","node":<id>, ...}`: each coverage record of each node without `observed_at`;
* `{"t":"fact","node":<id>,"name":<collector>,"d":H}`: each host fact, where `d` is a digest of the engine's own
  meaning view of the entry (a verifier treats `d` as opaque);
* `{"t":"meta","k":<key>,"v":<value>}`: any other top-level key except `now`.

Exclusions keep roots stable across pure refreshes: the document's `now`, coverage `observed_at` and provenance
keys. Encoding of values: a key with value null is **omitted**; a string outside the PCJ charset is replaced by
`{"$h":"sha256:<hex of its UTF-8 bytes>"}`; anything else outside PCJ (a float, a negative integer) makes the issuer
**fail closed**: no statement is issued and the previous one lapses. A lossy encoding is never used.

`snapshot.graph.size` is the leaf count. What the root gives: it binds the issuer to one graph (non-repudiation),
lets the owner disclose chosen leaves to an auditor who can compare them with their own observation, and lets
consumers see "the graph changed" when roots differ. It does **not** prove the graph is true, and it leaks only
coarse size and change timing.
