<!-- SPDX-License-Identifier: Apache-2.0 -->
# 02. Statement and predicate

Normative. Grammars (T, H, KID, ESTATE, INV, UINT, SUBJECT) are defined in [01](01-conventions.md). The machine
readable form is `schema/statement.schema.json` and `schema/predicate.schema.json`; where a rule cannot be written
as a schema (sortedness, counts, windows) this file and [07](07-verification-procedure.md) are authoritative.

## 1. Envelope

A DSSE envelope, plain JSON (not required to be canonical), at most 512 KiB:

```json
{"payloadType":"application/vnd.in-toto+json","payload":"<base64 of PAYLOAD BYTES>","signatures":[{"keyid":"<KID>","sig":"<base64 of 64 bytes>"}]}
```

* Exactly the three top-level keys. `signatures` has **exactly one** entry with exactly the keys `keyid` and `sig`.
  Zero, or two or more, is `sig.count_invalid`. (Multi-signature statements would need a new predicate type.)
* **PAYLOAD BYTES** are the PCJ encoding of the Statement ([01](01-conventions.md) 2.1). A verifier base64-decodes
  strictly, parses strictly, re-encodes and requires byte equality (`schema.payload_not_canonical` otherwise).
* The signature input is the DSSE PAE over `payloadType` and the **decoded** payload bytes; Ed25519, pure.
* `keyid` is the KID of the signing key. A verifier never trusts a key carried in the envelope.

## 2. Statement

```json
{"_type":"https://in-toto.io/Statement/v1",
 "subject":[{"name":"dns:example.com","digest":{"sha256":"<sha256 hex of the UTF-8 bytes of the name>"}}],
 "predicateType":"https://paddock.dev/attestation/containment/v1",
 "predicate":{ }}
```

* `_type` and `predicateType` MUST equal these strings. An unknown `predicateType` is `predicate.unsupported_version`
  (unverifiable) and nothing else of the statement is interpreted beyond steps 0 to 3 of the
  [procedure](07-verification-procedure.md).
* `subject` has **exactly one** entry. `name` is a SUBJECT. `digest` has exactly the key `sha256`, the SHA-256 of
  the name's UTF-8 bytes, so a verifier can recompute it from the name alone. The set of authorised assets is not
  in the subject: it is committed by `predicate.scope`.

## 3. Predicate

The predicate is **strict**: an unknown key anywhere is invalid (`schema.field_unknown`). New fields or semantics
mean a new `predicateType`. There is no extension map and no `critical` list: an extension map is a free-text
channel, and silently ignoring an unknown field is how meaning gets weakened.

| Field | Type and rule |
|---|---|
| `estate` | ESTATE. Equals the certificate's `estate`, and the `paddock-estate` subject when that is the subject. |
| `seq` | UINT, at least 1, strictly +1 per publication chain. |
| `prev` | H: SHA-256 of the exact payload bytes of `seq - 1`. Present **iff** `seq > 1`. |
| `issued_at` | T, whole seconds. |
| `valid_until` | T. `issued_at < valid_until <= issued_at + 7 days`. |
| `kid` | KID. Equals the envelope `keyid` (so a statement cannot be re-signed under another key of the same estate). |
| `snapshot` | `{"at": T, "graph": {"root": H, "size": UINT}}`. `snapshot.at <= issued_at <= snapshot.at + 900 s`. All results share this one time and this one graph. |
| `scope` | `{"digest": H, "entries": UINT, "unproven": UINT, "private": UINT}`: the digest of the declared, proven authorisation set and counts, never the entries (section 6). |
| `policy` | `{"commitment": H, "total": UINT, "enabled_std": UINT, "enabled_custom": UINT, "disclosed": UINT, "versions": UINT}` ([04](04-merkle.md)). |
| `disclosure` | `{"verdicts": "holds_only"\|"all", "custom": bool}`. |
| `results` | Array of result (section 4), sorted by `invariant` in byte order, unique, at most 256. |
| `engine` | `{"name": "paddock-assurance", "version": <[0-9A-Za-z.+-]{1,32}>, "ruleset": H}`. |
| `audit_anchor` | Optional `{"max_id": UINT, "head": 64 hex, "hash_alg": "sha256"\|"hmac-sha256", "at": T, "kid": KID, "digest": H}`; present only when a signed anchor exists ([B](B-anchor-v2.md)). |
| `limits` | `{"id": "paddock-limits/1", "digest": H}`. **Mandatory.** `digest` is the SHA-256 of the exact bytes of the pinned limits text for that id. |

Counting rules, checked by every verifier: `disclosed == len(results)`; and
`disclosed <= enabled_std + enabled_custom <= total`.

## 4. Results

All variants:

| Field | Type and rule |
|---|---|
| `invariant` | INV. A `std:` id MUST come from the registry of the statement's ruleset. |
| `digest` | H. The engine's invariant digest: an **opaque id** to the verifier. For a `std:` id it MUST equal the registry digest of the statement's ruleset. |
| `assertion` | `"unreachable"`, `"exposes-only"`, `"covered"` or `"host-config"` (closed set). |
| `verdict` | `"HOLDS"`, `"VIOLATED"` or `"UNKNOWN"` (closed set). `EXPIRED` is never issued: it is derived by the verifier ([03](03-verdicts-tiers-coverage-freshness.md)). Any other value is `schema.enum_unknown`. |
| `min_tier` | `"declared"`, `"configured"`, `"observed"` or `"tested"`: the invariant's own minimum evidence tier. |
| `max_age_s` | UINT: the invariant's maximum evidence age in seconds. |
| `coverage` | `{"universe": UINT, "covered": UINT, "required_bp": UINT <= 10000, "estate_universe": UINT, "estate_covered": UINT}`. `covered <= universe` and `estate_covered <= estate_universe`. The pair `universe`/`covered` is the figure relevant to this verdict; `estate_*` is the tenant-wide pair; `required_bp` is the floor that was applied, in basis points, rounded **down**. |
| `blind_spots` | `{"root": H, "size": UINT, "truncated": bool}`: the commitment over every blind spot of this result ([04](04-merkle.md)); `truncated` is true iff the engine's own cap was hit. An empty list has the empty-tree root `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. |
| `selected` | `{"from"?: UINT, "to": UINT, "stop_at"?: UINT}`: how many nodes the invariant's selectors chose. For `host-config` only `to`. |
| `exceptions` | UINT: the number of declared allow-entries the verdict relied on. Reasons and targets stay private. |

Verdict-specific fields, **exactly** these and no others:

* `HOLDS`: `tier` (`"configured"`, `"observed"` or `"tested"`; **never `declared`**) and `valid_until` (T, the
  engine's validity floored to the second, strictly after `issued_at`). Both required.
* `VIOLATED`: `violations` (UINT, at least 1). No witness, no node reference, ever.
* `UNKNOWN`: `reason_codes`: a non-empty, sorted, unique array of the enumeration below.

### 4.1 Reason codes of an UNKNOWN

| Public code | Engine reasons it covers (the part before the first `:`; parameters are dropped) |
|---|---|
| `coverage_below_required` | `coverage_below_required` |
| `possible_via_unknown_edges` | `possible_via_unknown_edges` |
| `zone_unknown` | `possible_via_zone_unknown`, `zone_unknown` |
| `selection_too_large` | `overlapping_selectors_too_large` |
| `host_evidence_unusable` | `hosts_unknown`, `no_agent`, `agent_revoked`, `no_value` and the other host fact reasons |
| `stale_or_missing_evidence` | `stale`, `future_timestamp`, `tier_below_min`, `no_sensor` |
| `empty_selector` | `empty_selector` |
| `graph_incomplete` | `graph_incomplete`, `graph_unavailable` |
| `invalid_definition` | `invalid_definition` |
| `evaluation_error` | `evaluation_error` |
| `other` | anything else |

A verifier prints a phrase for each code from its own table ([09](09-human-wording.md)); a reason code it does not
know is `schema.enum_unknown`. The mapping is pinned by `vectors/primitives/reason-map.json`. A new engine reason
maps to `other` until this enumeration grows (a version bump).

## 5. Deliberately absent

Ratios and percentages, titles, descriptions, reasons text, severity, node references, IP addresses, host names,
witnesses, `graph_version` (it leaks activity), per-result evaluation times, any customer identifier, and any
"overall", "score", "secure" or "pass" field, and any statement-level tier. A statement-level tier is a verifier
output: the minimum over the disclosed HOLDS tiers.

## 6. The scope document

The statement binds itself to an authorisation set through `scope.digest`. The set itself is never in the
statement. The owner MAY publish it as `scope.json` in the bundle ([06](06-bundle.md)) so anyone can check the
digest:

```json
{"entries":[{"kind":"domain","value":"example.com"}],"v":1}
```

PCJ; entries sorted by (`kind`, `value`); `kind` is `domain`, `subdomain_wildcard`, `ipv4_cidr`, `ipv6_cidr` or
`asn`; domains are lowercase A-labels (a wildcard keeps `*.`), CIDRs are canonical text with host bits cleared,
ASNs are `AS<n>`. `scope.digest` is `sha256:` plus the SHA-256 of those bytes. Only entries that are active,
unexpired and proven (or, for CIDRs and ASNs, attested) are included; entries without a proof are counted in
`scope.unproven`; non-global (private) CIDRs are excluded from the digest, because an unsalted digest of internal
ranges would be guessable, and counted in `scope.private`; `scope.entries` is the number included. The scope
digest is **not** the coverage universe: coverage comes from assets, connectors and agents. `vectors/primitives/
scope-digest.json` pins the normalisation for issuers; a verifier only checks a published `scope.json` against the
digest.

## 7. Limits of this document

A statement of this version is at most 256 KiB, has at most 256 results, nests at most 8 deep and has strings of
at most 512 bytes. An issuer whose signer cannot sign a message of the required size refuses to issue; it never
truncates.
