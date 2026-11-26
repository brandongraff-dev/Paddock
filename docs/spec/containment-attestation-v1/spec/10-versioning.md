<!-- SPDX-License-Identifier: Apache-2.0 -->
# 10. Versioning

* `predicateType` carries the major version: `https://paddock.dev/attestation/containment/v1`. A change to PCJ, the
  Merkle rules, the check order, a closed enumeration (a new tier, verdict or direction) or the meaning of a field
  is a **new major**. A verifier that meets a higher major reports `predicate.unsupported_version` and exits 2.
* Verifiers support the current and the previous major for at least 24 months. Publishers MAY dual-publish
  `attestation/latest.json` (v1) next to a later `latest-v2.json`.
* The statement is strict ([02](02-statement-predicate.md) section 3): new fields mean a new predicate type, never a
  silently ignored key.
* Minor versions of this specification add reason codes, registry entries and vectors without changing any rule
  that an existing statement relies on. Reason codes are never renumbered or reused ([A](A-reason-codes.md)).
* `std-registry.json`, `advisories.json` and the trust roots are versioned independently of the specification
  (`registry_version`, `advisories_version`, and the release of the verifier that embeds them). The verifier prints
  the spec version it implements (`1.0`) and warns when its registry is older than a statement's ruleset.
* A security-relevant change to a normative rule needs vectors and a CHANGELOG entry **in the same commit**. Changing
  an existing vector's expectation needs a CHANGELOG line.
* `log_inclusion` is **reserved**: no signed field in v1. A v2 predicate or an unsigned bundle file
  `attestation/<seq>.inclusion.json` may carry a transparency-log entry later, because log entries are created after
  signing.
* Reserved: ECDSA P-256 for custody backends that cannot sign raw Ed25519 messages, per-publication keys and a
  probe-evidence profile for the `tested` tier. Each needs its own vectors and a minor or major version.
