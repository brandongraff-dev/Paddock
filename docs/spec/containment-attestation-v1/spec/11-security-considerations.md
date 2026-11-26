<!-- SPDX-License-Identifier: Apache-2.0 -->
# 11. Security considerations

## 1. What a hostile party must be unable to do

| Attack | What stops it |
|---|---|
| **Forge** a statement (wrong key, unlisted key, a key claiming another key's id) | Ed25519 over the PAE under a key in `keys.json` whose certificate chains to a pinned root and whose fingerprint is in the domain's own DNS. |
| **Re-sign** under another key of the same estate | `predicate.kid` is inside the signed bytes and must equal the envelope `keyid`. |
| **Replay** an old statement | `time.expired`; `valid_until` at most 7 days (default 24 hours); `seq` and `prev`; the state-file rollback check; `superseded[]` with `min_seq`; `require_latest`. Residual: an offline copy is accepted until its own `valid_until`. |
| **Cherry-pick** (publish only the passes) | The policy counts, the std id list from the registry, the `all`-mode self-check, `disclosure: complete`, one snapshot for every result. Residual: `holds_only` cannot distinguish violated from withheld. |
| **Cherry-pick across time** | One `snapshot.at` and one graph root for all results; no per-result time. |
| **Stale pass** | A result's `valid_until` is the stalest relied-on fact plus `max_age`; derived EXPIRED; consumer max-age on `issued_at` and `snapshot.at`. |
| **Downgrade** the algorithm, the spec or the engine | The algorithm comes from the certificate; an unknown `alg`, `predicateType` or ruleset is exit 2; advisories reject. |
| **Confuse** the verifier with non-canonical JSON | PCJ strict parse and the byte-equality round trip: duplicate keys, key order, number forms, escapes, Unicode, whitespace, BOM; even a validly signed non-canonical payload is rejected. |
| **Signature context confusion** (an anchor signature as a statement signature, a certificate as a statement) | Distinct contexts (`DSSEv1 <payloadType>` against `paddock-anchor/v2` and a line feed); the exact `payloadType` is inside the PAE; the certificate `usage` is checked. |
| **Domain confused deputy** (a statement naming `dns:victim.com`) | Accepted only if victim.com's own DNS names this key. |
| **Equivocation** (two payloads, one seq) | `chain.fork` when both are seen; the issuer enforces uniqueness per chain. |
| **Tier inflation** | The tier is copied from the engine; the issuer, its self-check and the verifier each re-assert it; `tested` is invalid in v1 and `declared` is never valid on a HOLDS. |
| **Vacuous or weakened rule** | The `std:` namespace is reserved; its digest is checked against the registry; custom ids are not public by default and carry a disclaimer; `selected` counts; `result.selected_empty`; `result.universe_empty`. |
| **Boundary-label abuse** | Node labels are in the graph tree; `selected.stop_at` is published; `result.boundary_dominant`; policy `max_stop_at_share`. |
| **Freeze the revocation list** | `next_update` plus 48 hours is unverifiable; the list's `seq` is monotone. |
| **Poison DNS** (one resolver lies) | All answering resolvers must agree, at least 2 by default; disagreement is exit 2; the certificate is the second anchor. |
| **Exhaust** the verifier (huge files, deep JSON, huge numbers) | Size, depth and result-count limits ([01](01-conventions.md) 3), linear-time strict reader, fetch caps. |
| **Mislead the terminal** with attacker text | There is no free text in a statement; `params` hold validated tokens only; custom ids appear in code style next to a disclaimer. |

## 2. What this specification does not stop

1. **Hosted custody.** A compromised issuer process, or a database dump plus the key-encryption key, can mint valid
   statements until the key is revoked. The Merkle roots bind the issuer to a graph but do not prove it true. The
   certificate's `custody` field and the verifier's output say which applies. Customer-held keys, an independently
   held anchor sink and a transparency log are the real mitigations and are later.
2. **The offline replay window.** A copy of a statement that said HOLDS stays acceptable until its `valid_until` even
   after the estate flips.
3. **`holds_only` is lossy by design.** A reader cannot tell violated from unknown from withheld.
4. **The anchor is not a public proof of the audit chain.** It is a keyed HMAC chain; outsiders verify the
   signature, the estate binding, monotonicity and, with an independent copy of the sink, byte equality ([B](B-anchor-v2.md)).
5. **DNS binding.** No local DNSSEC validation in a standard-library verifier; the AD bit is the resolver's claim; a
   registrar compromise defeats the domain anchor; the resolver sees which domain is verified; a missed TXT update
   before key activation, or removing the old record too early, makes verifiers reject.
6. **No transparency log in v1.** A compromised key can backdate `issued_at` within its certificate window, so a
   `key_compromise` revocation invalidates every statement of that key.
7. **Revocation latency** is bounded by the list's age; revocation of an issuer or root between verifier releases
   relies on the lists embedded in the release.
8. **Privacy residue.** Sizes, `covered/universe`, `estate_*`, the number of results, `seq` cadence, root-change
   timing, the engine version and the domain itself are visible. An estate's domains are linkable through the shared
   key fingerprint.
9. **Evidence is not truth.** Coverage counts assets with evidence, not the true estate. Agent facts are `configured`
   and a compromised host can report false data.
10. **Engine drift.** An engine upgrade changes std digests and the ruleset; an old verifier answers exit 2 until its
    registry is updated. A new engine reason maps to `other` until the enumeration grows.
11. **Time.** The verifier trusts its host clock.
12. **Residual cofactor ambiguity.** `R` is not pre-checked; a certified signer could craft a signature whose
    validity differs between implementations for small-order components of `R`. This needs a malicious certified
    signer.

## 3. Privacy

No host name, IP address, node reference, witness, label value or customer identifier appears in a signed statement
or in a public bundle file. Merkle leaves are blinded with a per-estate secret. The scope digest excludes private
ranges. Anchors carry the estate id and the hash family only. A verifier that resolves DNS reveals the domain being
checked to its resolver.
