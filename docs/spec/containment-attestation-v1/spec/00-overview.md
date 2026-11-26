<!-- SPDX-License-Identifier: Apache-2.0 -->
# 00. Overview

**Containment attestation, version 1.** A format and a verification procedure that let an organisation publish
signed statements of the form "an engine searched the evidence available to it and found no counterexample to
this declared rule", and let anyone check such a statement offline, without trusting the publisher's servers.

## 1. What an attestation says, and what it does not

An attestation says: *a named issuer's engine, running invariants whose definitions are identified by digests,
searched the evidence available to it at one moment and found no counterexample; this much of the relevant estate
had live evidence; the weakest evidence relied on was of this tier; the result is current until this time; and the
key that signed it is certified by a pinned root and named by the domain's own DNS.*

It does **not** say that the organisation, its network or any system is secure, compliant, certified, insured or
free of vulnerabilities. It is not a penetration test, an audit or a prediction. It says nothing about rules that
are not listed in it, it cannot detect a compromised host that reports false data, and the engine and its rules
can have defects. Those statements travel with every attestation as the pinned limits text
([09-human-wording.md](09-human-wording.md), `registry/limits-v1.txt`), whose digest is inside every signed
statement.

Three product rules govern the whole specification:

1. **HOLDS means "no counterexample under this evidence, this coverage and this freshness".** No field, template or
   output may phrase it as safety.
2. **UNKNOWN never becomes HOLDS.** A result that cannot be produced, proven or published is absent or UNKNOWN. A
   verifier never turns UNKNOWN into a pass and never aggregates verdicts into a score.
3. **Violations win and failures fail safe.** A disclosed VIOLATED rejects by default, and any failure while
   verifying means "not accepted" (exit 1 or 2), never exit 0.

## 2. Parties

| Party | Role |
|---|---|
| **Issuer** | Evaluates the declared invariants on one snapshot, commits to the inputs, builds and signs a statement. Normative here only through what it must produce. |
| **Publisher** | Makes the bundle available: on the issuer's hosted service, or pushed to the subject's own static host. Never trusted: everything fetched is authenticated by signature, certificate and DNS, never by transport. |
| **Subject** | The domain (or estate) the statement is about. Binds its attestation key in its own DNS. |
| **Root** | The offline key pinned into verifier releases. Certifies issuers and revokers. |
| **Verifier** | Anyone: an insurer, a procurement team, a customer. Runs the [verification procedure](07-verification-procedure.md) with its own clock, resolvers and acceptance policy. |

## 3. Document set

| File | Content |
|---|---|
| [01-conventions.md](01-conventions.md) | Notation, the signed-JSON profile (PCJ), base64, time, DSSE encoding, Ed25519 rules, size limits |
| [02-statement-predicate.md](02-statement-predicate.md) | Envelope, statement, predicate, results, reason codes |
| [03-verdicts-tiers-coverage-freshness.md](03-verdicts-tiers-coverage-freshness.md) | What each verdict, tier and coverage figure means; freshness; derived EXPIRED |
| [04-merkle.md](04-merkle.md) | The three blinded commitments and inclusion proofs |
| [05-keys-certs-revocation-dns.md](05-keys-certs-revocation-dns.md) | Key hierarchy, certificates, `keys.json`, revocation, DNS key binding |
| [06-bundle.md](06-bundle.md) | The static bundle layout and publishing rules |
| [07-verification-procedure.md](07-verification-procedure.md) | The eleven normative steps, exit codes, report, fetch rules |
| [08-acceptance-policy.md](08-acceptance-policy.md) | The consumer's acceptance policy (JSON and a strict YAML subset) |
| [09-human-wording.md](09-human-wording.md) | Verifier-owned sentences and the forbidden vocabulary |
| [10-versioning.md](10-versioning.md) | Version rules and registries |
| [11-security-considerations.md](11-security-considerations.md) | Attacks, mitigations and honest limits |
| [12-conformance.md](12-conformance.md) | Vectors, the conformance runner, how to claim conformance |
| [A-reason-codes.md](A-reason-codes.md) | Every stable reason code |
| [B-anchor-v2.md](B-anchor-v2.md) | The signed audit anchor |
| [C-worked-example.md](C-worked-example.md) | One complete statement with every byte |

Machine-readable companions: `schema/*.schema.json` (JSON Schema 2020-12), `registry/` (std registry,
advisories, wording, limits text), `vectors/` (test vectors), `conformance/run.py`.

## 4. Design in one page

```
 issuer evaluates all declared invariants on ONE snapshot (one graph, one time)
   -> commits to the graph, to ALL declared invariants and to each result's blind spots (blinded Merkle roots)
   -> builds a statement: enums, ids, hashes, integers, timestamps and no free text
   -> signs it (DSSE, Ed25519) with an estate key that a pinned root certified
 subject publishes the key fingerprint in its own DNS:   _paddock-attest.<domain> TXT
 publisher serves a static bundle:  statement, keys.json, revoked.json, anchors
 verifier: strict parse -> signature -> certificate chain and DNS -> revocation -> time -> chain
           -> engine and disclosure -> per-result rules -> consumer policy -> optional anchor and proofs
```

Because the statement carries no free text, every human sentence is generated by the verifier from a table the
specification owns. Nobody, including an issuer or a custom invariant id, can phrase HOLDS as "secure".

## 5. Terms

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** are used as in RFC 2119. "Reject" means exit code 1,
"unverifiable" means exit 2 (see [07](07-verification-procedure.md)). A *snapshot* is the single graph and instant
from which every result of a statement is evaluated. An *estate* is the issuer's per-customer chain identity. An
*invariant* is a declared rule that a result judges, identified by a content digest.
