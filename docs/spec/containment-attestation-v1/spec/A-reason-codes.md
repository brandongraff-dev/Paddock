<!-- SPDX-License-Identifier: Apache-2.0 -->
# Appendix A. Reason codes

Normative. Codes are **never renumbered or reused**; a new code is a minor-version addition (see
[10-versioning.md](10-versioning.md)). The reference verifier's `codes.py` is kept equal to this table by a test,
and every code is exercised by at least one conformance vector.

**Class**: `R` reject (exit 1), `U` unverifiable (exit 2), `W` warning (never changes the exit code on its own),
`X` usage or configuration error (exit 64). **Alt** is the class a code takes when the acceptance policy marks the
check optional or `warn` (the `Note` column says when); `-` means none. **Step** is the step of the
[verification procedure](07-verification-procedure.md) that raises the code; `any` means it can arise anywhere.

Exit precedence: any `R` gives 1, otherwise any `U` gives 2, otherwise 0. An unexpected internal failure is
`internal.error` (exit 2), never 0. An implementation may reword the message column for its own users but MUST
keep the code, the class and the order in which it reports codes (the conformance cases compare the exact ordered
list). Every message is fixed text: it never contains text taken from the attestation.

| Step | Code | Class | Alt | Message | Note |
|---|---|---|---|---|---|
| 0 | `input.unreadable` | U | - | Could not read the input. |  |
| 0 | `input.not_found` | U | - | No attestation bundle at this location. |  |
| 0 | `input.fetch_failed` | U | - | Could not download the bundle (network or server error). |  |
| 0 | `input.insecure_transport` | U | - | Refused a non-HTTPS or unsafe address. |  |
| 0 | `input.too_large` | R | - | A file exceeds the size limit. |  |
| 0 | `input.not_ascii` | R | - | A file is not valid ASCII where ASCII is required. |  |
| 0 | `input.not_json` | R | - | Not valid JSON under the strict profile. |  |
| 0 | `input.duplicate_key` | R | - | A JSON object repeats a key. |  |
| 0 | `input.depth_exceeded` | R | - | JSON nesting is too deep. |  |
| 0 | `input.number_invalid` | R | - | A number is not a plain in-range non-negative integer. |  |
| 1 | `schema.envelope_invalid` | R | - | Not a valid DSSE envelope. |  |
| 1 | `schema.payload_type` | R | - | Unexpected payload type. |  |
| 1 | `schema.base64_invalid` | R | - | A value is not canonical standard base64. |  |
| 1 | `schema.payload_not_canonical` | R | - | Payload bytes are not in canonical form. |  |
| 1 | `schema.statement_invalid` | R | - | Not a valid in-toto statement. |  |
| 1 | `schema.subject_invalid` | R | - | Subject is missing, malformed or its digest is wrong. |  |
| 1 | `schema.field_unknown` | R | - | A field that this version does not define is present. |  |
| 1 | `schema.field_invalid` | R | - | A field has the wrong type or format. | params: JSON path |
| 1 | `schema.time_format` | R | - | A timestamp is not YYYY-MM-DDTHH:MM:SSZ. |  |
| 1 | `schema.digest_format` | R | - | A digest or id is malformed. |  |
| 1 | `schema.enum_unknown` | R | - | A closed value is not recognised. |  |
| 1 | `schema.limit_exceeded` | R | - | A list or size exceeds the allowed maximum. |  |
| 1 | `schema.result_duplicate` | R | - | An invariant appears twice. |  |
| 1 | `schema.result_unsorted` | R | - | Results are not sorted by invariant id. |  |
| 1 | `schema.result_inconsistent` | R | - | A result's fields contradict its verdict. |  |
| 1 | `schema.seq_prev_invalid` | R | - | `seq` and `prev` are inconsistent. |  |
| 1 | `schema.counts_inconsistent` | R | - | Disclosed, enabled and total counts do not add up. |  |
| 1 | `predicate.unsupported_version` | U | - | This verifier does not support that predicate version. |  |
| 2 | `sig.count_invalid` | R | - | Version 1 requires exactly one signature. |  |
| 2 | `sig.malformed` | R | - | Signature is not 64 canonical bytes. |  |
| 2 | `sig.alg_unsupported` | U | - | Signature algorithm not supported. |  |
| 2 | `keys.missing` | U | - | `keys.json` not available. |  |
| 2 | `keys.invalid` | R | - | `keys.json` fails validation. |  |
| 2 | `key.unknown` | R | - | Signing key is not in `keys.json`. |  |
| 2 | `key.kid_mismatch` | R | - | The signed key id differs from the envelope key id. |  |
| 2 | `sig.weak_key` | R | - | The public key is a small-order or non-canonical point. |  |
| 2 | `sig.noncanonical_s` | R | - | The signature scalar is not reduced. |  |
| 2 | `sig.invalid` | R | - | The signature does not match the statement. |  |
| 3 | `config.no_trust_roots` | U | - | No trust roots are configured. |  |
| 3 | `key.fingerprint_mismatch` | R | - | Key id does not match the public key. |  |
| 3 | `key.cert_missing` | R | W | The key has no vendor certificate. | W when policy `vendor_cert: optional` |
| 3 | `key.cert_invalid` | R | - | Certificate is malformed or its signature fails. |  |
| 3 | `key.cert_subject_mismatch` | R | - | Certificate does not match the listed key, usage or estate. |  |
| 3 | `key.root_unknown` | R | - | Certificate does not chain to a trusted root. |  |
| 3 | `key.outside_validity` | R | - | The key was not valid when the statement was issued or for its whole lifetime. |  |
| 3 | `issuer.outside_validity` | R | - | An issuing certificate was not valid at issue time. |  |
| 3 | `dns.domain_mismatch` | R | - | Statement subject differs from the domain checked. |  |
| 3 | `dns.no_binding` | R | - | The domain publishes no binding for this key. |  |
| 3 | `dns.mismatch` | R | - | The domain's published key fingerprint differs. |  |
| 3 | `dns.record_conflict` | R | - | The domain publishes two fingerprints for one key id. |  |
| 3 | `dns.too_many_records` | R | - | The domain publishes too many binding records. |  |
| 3 | `dns.record_ignored` | W | - | A malformed DNS record was ignored. |  |
| 3 | `dns.not_applicable` | W | R | The subject has no domain to bind. | R when the policy requires DNS |
| 3 | `dns.lookup_failed` | U | - | DNS lookup failed. |  |
| 3 | `dns.insufficient_resolvers` | U | - | Too few resolvers answered. |  |
| 3 | `dns.resolvers_disagree` | U | - | Resolvers returned different answers. |  |
| 3 | `dns.skipped_offline` | U | W | DNS binding not checked (offline). | W when the policy marks it optional |
| 3 | `dns.dnssec_unproven` | U | - | DNSSEC validation required but not shown. |  |
| 4 | `key.revoked` | R | - | The signing key was revoked. |  |
| 4 | `key.revoked_superseded` | W | - | Key later retired; the statement predates that. |  |
| 4 | `issuer.revoked` | R | - | An issuing key was revoked. |  |
| 4 | `chain.superseded` | R | - | A newer statement or a supersession notice exists for this subject. |  |
| 4 | `revocation.missing` | U | - | No revocation list available. |  |
| 4 | `revocation.unverifiable` | U | - | Revocation list failed verification. |  |
| 4 | `revocation.stale` | U | - | Revocation list is too old to rely on. |  |
| 5 | `time.expired` | R | - | The attestation has expired. |  |
| 5 | `time.not_yet_valid` | R | - | Issued in the future beyond the allowed skew. |  |
| 5 | `time.window_invalid` | R | - | The validity window is inconsistent (`valid_until` not after `issued_at`, snapshot or anchor out of order). |  |
| 5 | `time.ttl_excessive` | R | - | Validity period exceeds the 7-day maximum. |  |
| 5 | `time.too_old` | R | - | Older than your maximum age. |  |
| 6 | `chain.seq_rollback` | R | - | Sequence number is lower than one seen before. |  |
| 6 | `chain.fork` | R | - | Two different statements share a sequence number. |  |
| 6 | `chain.prev_mismatch` | R | - | Does not link to the previous statement. |  |
| 6 | `chain.seq_gap` | R | - | Sequence skips a number (a withheld update). |  |
| 6 | `chain.latest_mismatch` | R | - | `latest.json` differs from the numbered statement. |  |
| 6 | `chain.history_missing` | U | W | Previous statement unavailable. | W if optional |
| 6 | `chain.state_unreadable` | U | - | Local state file unreadable. |  |
| 6 | `policy.shrank` | R | - | The declared policy shrank since the previous statement. |  |
| 6 | `anchor.max_id_regressed` | R | - | The anchored audit position went backwards. |  |
| 6 | `digest.changed` | W | - | An invariant's definition changed since the previous statement. |  |
| 7 | `limits.unknown` | R | - | The limits statement id is not known to this verifier. |  |
| 7 | `limits.digest_mismatch` | R | - | The limits statement text differs from the pinned one. |  |
| 7 | `engine.ruleset_unknown` | U | - | This verifier does not know the engine's ruleset. |  |
| 7 | `engine.advisory` | R | W | The engine version has a known defect advisory. | W when policy `warn` |
| 7 | `std.digest_mismatch` | R | - | A standard invariant's definition differs from the registry. |  |
| 7 | `std.id_unknown` | R | - | A `std:` id is not in the registry for this ruleset. |  |
| 7 | `disclosure.inconsistent` | R | - | The disclosure counts contradict the disclosure mode. |  |
| 8 | `result.tier_invalid` | R | - | The evidence tier is not allowed here. |  |
| 8 | `result.tier_below_min` | R | - | Evidence tier is below the invariant's own minimum. |  |
| 8 | `result.tier_above_cap` | R | - | Evidence tier exceeds what this kind of check can show. |  |
| 8 | `result.coverage_inconsistent` | R | - | Coverage numbers contradict the claimed verdict. |  |
| 8 | `result.universe_empty` | R | - | Nothing is in scope; the result is vacuous. |  |
| 8 | `result.selected_empty` | R | - | The invariant selects nothing; the result is vacuous. |  |
| 8 | `result.valid_until_invalid` | R | - | A result's validity is not after the issue time. |  |
| 8 | `result.boundary_dominant` | W | - | Boundary labels cover most of the estate. |  |
| 9 | `coverage.below_threshold` | R | - | Coverage is below your threshold. |  |
| 9 | `invariant.missing` | R | - | A required invariant is not in the attestation. |  |
| 9 | `invariant.verdict_violated` | R | - | A required invariant is violated. |  |
| 9 | `invariant.verdict_unknown` | R | - | A required invariant cannot be determined. |  |
| 9 | `invariant.expired` | R | - | A required invariant's evidence has expired. |  |
| 9 | `invariant.tier_below_required` | R | - | Evidence tier is below what you require. |  |
| 9 | `invariant.digest_mismatch` | R | - | Definition differs from the one your policy pins. |  |
| 9 | `invariant.exceptions_over_limit` | R | - | More exceptions than allowed. |  |
| 9 | `invariant.unrequired_violation` | R | W | A violated invariant is disclosed. | W if the policy says warn |
| 9 | `invariant.age_exceeded` | R | - | A required invariant's evidence is older than your limit for it. |  |
| 9 | `policy.disclosure_incomplete` | R | - | The issuer did not disclose every enabled invariant. |  |
| 9 | `chain.not_latest` | R | - | A newer statement exists and the policy requires the latest. |  |
| 10 | `anchor.unavailable` | U | W | Audit anchor not available. | W if optional; R when policy `anchor: required` and the field is absent |
| 10 | `anchor.not_ed25519` | R | - | Anchor is not an Ed25519 v2 anchor. |  |
| 10 | `anchor.invalid` | R | - | Anchor signature or format invalid. |  |
| 10 | `anchor.mismatch` | R | - | Anchor differs from the statement's. |  |
| 10 | `anchor.too_old` | R | - | The anchor is older than the allowed gap before the statement. |  |
| 10 | `merkle.proof_missing` | U | - | A requested proof was not supplied. |  |
| 10 | `merkle.proof_invalid` | R | - | A Merkle proof does not verify. |  |
| any | `internal.error` | U | - | The verifier failed internally; no decision. |  |
| exit 64 | `config.policy_invalid` | X | - | The acceptance policy is invalid. | the line number is reported; exit 64 |
| exit 64 | `config.usage` | X | - | The command line is invalid. | exit 64 |

`--explain CODE` prints the message, the class, the step and a pointer to the section of this specification that
defines the check.
