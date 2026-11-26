<!-- SPDX-License-Identifier: Apache-2.0 -->
# 12. Conformance

## 1. Three implementations, one corpus

The vectors are the source of truth and are produced by a **third, independent implementation** written from this
text (`tools/gen_vectors.py` for primitives, `tools/gen_cases.py` for end-to-end cases), using only the standard
library and `cryptography` and importing nothing from the verifier or from any issuer. A defect in the reference
verifier or in the reference issuer therefore cannot be baked into the vectors.

* The reference verifier passes the corpus.
* The reference issuer passes it too: for each case marked `producer: true`, feeding the case's engine results, a
  fixed `now`, key seed, `seq`, `prev` and `commit_key` through its real builder and signer must give a
  **byte-identical** payload and envelope.
* The generators run in CI with `--check` (regenerate and diff). `vectors/MANIFEST.json` lists the SHA-256 of every
  file and the `spec_version`. Changing a vector's expectation needs a CHANGELOG line.

## 2. Determinism

No randomness and no clock. Keys are `Ed25519PrivateKey.from_private_bytes(sha256(b"paddock-conformance-seed/v1/" + name))`
for the names `root-1`, `root-2`, `issuer-1`, `revoker-1`, `tenant-a`, `tenant-b`, `anchor-a` and `attacker`. Ed25519
is deterministic, so signatures are byte reproducible. The reference clock is `2026-12-01T12:00:00Z`; `issued_at`
is `09:00:00Z` the same day, `valid_until` the next day `09:00:00Z`, the domain is `example.com` and the vector
`commit_key` is 32 bytes of `0x01`. Committed JSON uses sorted keys, a 2-space indent, ASCII and a trailing newline;
signed bytes are carried as base64.

**These seeds are public test keys.** A release pipeline test fails if a conformance key appears in the shipped trust
roots.

## 3. Primitive tables (`vectors/primitives/`)

| File | Pins |
|---|---|
| `pae.json` | the DSSE encoding for payload lengths 0, 9, 10, 99, 100, 127, 128, 255, 256, 1000, all three payload types and type lengths at digit boundaries |
| `b64.json` | canonical decode and encode, and every way to be non-canonical |
| `pcj.json` | accept and reject pairs for every rule and every row of the [01](01-conventions.md) 2.1 edge table, with the reason code and whether the reader or the round trip rejects |
| `time.json` | strict timestamps, calendar edges, durations and the end-exclusive window |
| `merkle.json` | leaf and node hashes, trees of 0 to 17 leaves, a proof for every index of sizes 1, 2, 3, 5, 7, 8, 9 and 17, bad proofs and proof files |
| `ed25519.json` | RFC 8032 tests 1 to 3, `S + L`, the identity key, small-order and non-canonical keys, wrong lengths |
| `kid.json` | the conformance seeds, public keys, key ids and fingerprints |
| `coverage.json` | integer cross-multiplication boundaries, flooring of the percentage and of `required_bp`, threshold parsing |
| `reason-map.json` | engine reason to public code |
| `dns-txt-parse.json` | the TXT parser table of [05](05-keys-certs-revocation-dns.md) 6.2 |
| `policy-parse.json` | the YAML subset accept and reject table with line numbers |
| `scope-digest.json` | scope document normalisation and private-range exclusion (for issuers) |
| `commit-nonce.json` | nonces, leaf hashes, trees and the graph leaf encoding with a fixed `commit_key` |
| `worked-example.json` | the complete statement of [C](C-worked-example.md) |

## 4. Case corpus (`vectors/cases/<id>/case.json`)

```json
{"id":"...","description":"...","spec_refs":["07 step 2"],"tags":["authenticity"],"producer":false,
 "now":"2026-12-01T12:00:00Z","target":{"kind":"dir","path":".well-known/paddock"},"args":[],
 "policy":null,"dns":{},"state":null,"anchor":null,"roots":"test","registry":"default",
 "recipes":[{"op":"pad_file","file":"..","bytes":600000}],
 "expect":{"exit":0,"decision":"accepted","codes":[],"warnings":[],"primary":null,"profile":"baseline","forbidden_terms":true}}
```

`bundle/` holds the files as they would be served. `schema/vector-case.schema.json` is the machine form. `exit`,
`decision`, `codes`, `warnings` and `primary` are all required: a case that leaves one out fails in the runner rather
than skipping the comparison, and so does a report that is not a JSON object. `codes` is
the **exact ordered list** of reject and unverifiable codes; `warnings` the set of warning codes. A corpus of about
110 end-to-end cases covers every code of [A](A-reason-codes.md) at least once: valid bundles, time, authenticity,
trust, key lifecycle, DNS, disclosure and commitments, chain, coverage and tier, versioning and strictness,
encoding, wording.

Recipes let the runner build huge inputs so the repository stays small: `pad_file` extends a file with a fill
character to an exact size, `write_file` creates a file of an exact size from a head, a fill and a tail.

## 5. The runner (`conformance/run.py`, standard library only)

```
run.py --impl "paddock-verify" [--filter tag] [--case id] [--primitives-adapter module]
```

For each case it materialises the recipes into a temporary directory and runs
`<impl> --json --offline --now <T> --roots <test roots> --dns-resolver file:<dns.json> [--state-file F | --no-state]
[--policy F] [--anchor-file F] [--std-registry F] <args> <target>`, then compares the exit code, the decision, the
exact ordered code list, the warnings, the primary reason and the profile, and finally scans every byte printed for
the forbidden vocabulary ([09](09-human-wording.md) section 5).

* **Level A** (a command line; mandatory) covers every case.
* **Level B** (a primitives adapter; optional) feeds the primitive vectors to functions `pae`, `b64_decode`,
  `pcj_parse`, `pcj_dumps`, `time_parse`, `merkle_root`, `merkle_verify` and `ed25519_verify`. Every primitive pin
  also has a Level A case that fails if the primitive disagrees (a wrong PAE can only break a valid vector, a wrong
  base64 only the variants), so an implementation without an adapter cannot diverge silently.

The runner prints a conformance matrix and exits non-zero on any mismatch. **An implementation may claim conformance
only against a named `spec_version` plus the MANIFEST hash**, for example "conforms to containment-attestation 1.0,
MANIFEST sha256 `...`".

## 6. Further tests a verifier ships

A mutation property (flip every bit of a compact valid bundle, truncate at every few bytes, delete each key of the
predicate: the exit code must never be 0); strict-reader fuzzing with linear time and no recursion error;
exit-code precedence; a fake resolver for DNS cases; fetch safety against a mocked transport; the codes table
against [A](A-reason-codes.md); the JSON schemas against the code validators; and an import lint proving the
verifier depends on the standard library and `cryptography` only.
