<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

A security-relevant change to a normative rule needs vectors and an entry here in the same commit. Changing the
expectation of an existing vector needs an entry here as well.

## 1.0 (unreleased)

First version of the specification: the statement and predicate, the signed-JSON profile (PCJ), strict base64, the
DSSE encoding with exactly one Ed25519 signature and the specification's own pre-checks, blinded Merkle commitments
(graph, policy, blind spots) with inclusion proofs, the key hierarchy and certificates, revocation and supersession,
DNS key binding, the bundle layout, the eleven-step verification procedure with stable reason codes, the acceptance
policy (JSON and a strict YAML subset), the verifier-owned wording and forbidden vocabulary, the signed audit anchor,
the registries, the primitive vectors and the conformance runner.

Decisions recorded while writing the text and the vectors (each is pinned by a vector):

* DNS TXT parser: a record that says `v=<plain token other than 1>` once is ignored without further parsing; a
  record with a duplicate tag, a missing required tag, an uppercase tag, a `kid` that is not the first 32 hex of
  `fp`, or a non-https `keys` is malformed; at most one trailing `;` and at most one space after a `;`.
* Strict reader error assignment: `input.number_invalid` covers every malformed or out-of-range numeric token
  (including `01`, `+1`, `1.0`, `NaN`); `null` is `input.not_json`; a string, key or whitespace that is valid JSON but not
  canonical is `schema.payload_not_canonical`.
* Ed25519 check order: signature length, public key (length, canonical encoding, not small order), `S < L`, then the
  library.
* A left-half Merkle leaf verifies for several tree sizes: the proof's `size` is authenticated only through the root.
* Wording: a word is a maximal run of letters, digits and underscores; hyphenated compounds are checked by part.
* Wording: the `W-KEY` phrase for a vendor-certified key is "vouched for by the vendor root" because the plain word
  from the forbidden vocabulary may not appear in verifier output; fixed message phrases may contain backticks (the
  code messages quote file names), issuer-supplied names and ids may not.
* A consumer that knows the expected size of a committed tree passes it to the proof check; the proof's own `size`
  is otherwise bound only through the root.
* Schemas carry an SPDX `$comment`. The conformance runner treats a case whose `expect` omits `exit`, `decision`,
  `codes`, `warnings` or `primary`, and a report that is not a JSON object, as a failure.
