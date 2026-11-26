<!-- SPDX-License-Identifier: Apache-2.0 -->
# Containment attestation, specification version 1.0

An open specification, licensed under the **Apache License 2.0** (see `LICENSE` and `NOTICE`; a patent grant is
included so anyone can implement it), for signed statements of the form *"an engine searched the evidence available
to it and found no counterexample to this declared rule"*, and for verifying them **offline, without trusting the
publisher**.

> A passing result means: no counterexample was found under this evidence, at this coverage, at this time. It is not
> a statement that the organisation is secure.

## Read in this order

| | |
|---|---|
| [spec/00-overview.md](spec/00-overview.md) | what it is, what it does not say, the parties |
| [spec/01-conventions.md](spec/01-conventions.md) | the byte-level rules every implementation must reproduce (strict JSON, base64, time, Ed25519) |
| [spec/02-statement-predicate.md](spec/02-statement-predicate.md) | the signed statement |
| [spec/03-verdicts-tiers-coverage-freshness.md](spec/03-verdicts-tiers-coverage-freshness.md) | what each field means |
| [spec/04-merkle.md](spec/04-merkle.md) | the blinded commitments |
| [spec/05-keys-certs-revocation-dns.md](spec/05-keys-certs-revocation-dns.md) | keys, certificates, revocation, DNS binding |
| [spec/06-bundle.md](spec/06-bundle.md) | the static bundle |
| [spec/07-verification-procedure.md](spec/07-verification-procedure.md) | the eleven steps, exit codes |
| [spec/08-acceptance-policy.md](spec/08-acceptance-policy.md) | the consumer's policy |
| [spec/09-human-wording.md](spec/09-human-wording.md) | the verifier's sentences and forbidden words |
| [spec/10-versioning.md](spec/10-versioning.md), [11](spec/11-security-considerations.md), [12](spec/12-conformance.md) | versioning, security, conformance |
| [spec/A-reason-codes.md](spec/A-reason-codes.md), [B](spec/B-anchor-v2.md), [C](spec/C-worked-example.md) | appendices |

## Machine readable parts

| Directory | Content |
|---|---|
| `schema/` | JSON Schema 2020-12 for the statement, predicate, envelope, `keys.json`, certificate, revocation list, anchor, inclusion proof, bundle conveniences, acceptance policy, verifier report and conformance case |
| `registry/` | `std-registry.json` (the only place a `std:` digest becomes trusted), `advisories.json`, `wording-v1.json`, `limits-v1.txt` |
| `vectors/primitives/` | test vectors for every primitive (PAE, base64, PCJ, time, Merkle, Ed25519, ...) and the worked example |
| `vectors/cases/` and `MANIFEST.json` | the end-to-end corpus (about 110 cases) |
| `tools/` | `gen_vectors.py` and `gen_cases.py`: independent generators (standard library and `cryptography` only) |
| `conformance/run.py` | a language-neutral runner (standard library only) |

## Implementing

1. Implement the primitives of [01](spec/01-conventions.md) and [04](spec/04-merkle.md) and run them against
   `vectors/primitives/` (Level B of the runner, or your own test harness).
2. Implement the [procedure](spec/07-verification-procedure.md) and a command line with the normative options, and
   run `conformance/run.py --impl "<your command>"` (Level A).
3. Claim conformance only against a named spec version plus the `MANIFEST.json` hash.

A reference verifier in Python (`paddock-verify`, Apache-2.0, dependency: `cryptography`) lives in `verifier/` of
the same repository.

## Status

Version 1.0 (draft until the legal review of the licensing grant is complete: nothing is published to a package
index or announced before it). See [CHANGELOG.md](CHANGELOG.md).
