<!-- SPDX-License-Identifier: Apache-2.0 -->
# 07. Verification procedure

Normative. A conforming verifier performs these steps **in this order** and reports reason codes
([A](A-reason-codes.md)) in this order. The conformance corpus compares the exact ordered list.

Notation: **R** reject (exit 1), **U** unverifiable (exit 2), **W** warning.

## 1. Exit codes

| Exit | Meaning |
|---|---|
| `0` | accepted |
| `1` | rejected |
| `2` | unverifiable |
| `64` | usage or configuration error (the command line or policy file is invalid) |

**Precedence: any reject gives 1, else any unverifiable gives 2, else 0.** Any unexpected exception exits 2 with
`internal.error`, never 0. A verifier never prints an accepted headline on partial evaluation. (A command line parser
that exits 2 for usage errors must be patched so that 2 means only "unverifiable".)

## 2. Abort rules

* A reject in step 0 or 1 aborts everything.
* An unsupported `predicateType` (U) continues with steps 2 and 3 only, so an authentic but too-new statement
  reports U and a forged one reports R.
* A reject in steps 2 to 4 marks steps 5 to 10 `not_evaluated`: policy is never judged on unauthentic data.
* Steps 5 to 10 run to completion and collect **all** reasons in step order; the first reason is `primary`.

## 3. The steps

| Step | Checks |
|---|---|
| **0 INPUT** | acquire files; size limits; strict JSON parse ([01](01-conventions.md) 2.1: duplicate keys, BOM, trailing bytes, `NaN`, number rules, depth) |
| **1 SCHEMA** | envelope shape (three keys, one signature of two keys); exact `payloadType`; strict base64; ASCII; PCJ round trip; Statement shape (`_type`); exactly one subject with a valid name and the digest `sha256(name)`; `predicateType` known; **strict** predicate keys; every grammar of [01](01-conventions.md) 1; `seq`/`prev` coupling (`prev` iff `seq > 1`); `issued_at < valid_until <= issued_at + 7 d`; `snapshot.at <= issued_at <= snapshot.at + 900 s`; results sorted, unique, at most 256; verdict-specific fields exactly as [02](02-statement-predicate.md) section 4; a HOLDS has `tier` and `valid_until`; counts `disclosed == len(results)` and `disclosed <= enabled_std + enabled_custom <= total` |
| **2 SIGNATURE** | exactly one signature; `keyid` in `keys.json`; `predicate.kid == keyid`; the Ed25519 pre-checks ([01](01-conventions.md) 2.5); verify over the PAE of the decoded payload |
| **3 TRUST** | `kid` equals the derivation from the certificate's public key; the certificate chain (the estate certificate signed by an issuer listed in `issuers`, whose certificate is signed by a pinned root; the payload equals the listed entry; `usage == attest`; every window contains `issued_at`; the key window also contains `valid_until`); `estate` in the certificate equals `predicate.estate` equals the `paddock-estate` subject when applicable; **DNS binding** when the subject is `dns:` ([05](05-keys-certs-revocation-dns.md) 6.3); the subject domain equals the domain being checked |
| **4 REVOCATION** | `revoked.json` present, signed by a chained revoker or issuer, fresh; the key not revoked (`key_compromise` rejects regardless of `issued_at`; `superseded` rejects `issued_at >= revoked_at`); no issuer revoked (the root-signed list shipped with the release); `seq >= min_seq` of the subject |
| **5 TIME** | `now < valid_until` (end exclusive) else `time.expired`; `issued_at - 300 s <= now`; consumer `max_age` on **both** `issued_at` and `snapshot.at`; `anchor.at <= issued_at` |
| **6 CHAIN** | when history is available: `latest.json` byte-equal to `<seq>.json`; `prev` equals the SHA-256 of the payload bytes of `<seq-1>`; the previous statement's seq is `seq - 1`; the local state high-water mark per subject (a lower seq is `chain.seq_rollback`; the same seq with a different digest is `chain.fork`); against the previous statement `total` and `versions` never decrease (`policy.shrank`), `anchor.max_id` never decreases (`anchor.max_id_regressed`), `digest.changed` is reported. No history: a warning or unverifiable per policy `history`. State is updated only after steps 0 to 4 pass |
| **7 DISCLOSURE AND ENGINE** | `limits.id` known and `limits.digest` equal to the embedded text's SHA-256; `engine.name`; the `ruleset` known (else U) and every `std:` result digest equal to the registry's for that ruleset; advisories for `engine.version`; **disclosure self-check**: `verdicts = all` and `custom = true` requires `disclosed == enabled_std + enabled_custom`; `verdicts = all` and `custom = false` requires the number of std results `== enabled_std`; whenever `custom` is false no result may have a non-`std:` id; the counts and the missing std ids (computed from the registry) are always reported |
| **8 RESULTS** | per result: `tier` in `{configured, observed}` (`tested` is invalid in v1: no probe-evidence profile exists yet; `declared` is never valid on a HOLDS), `tier >= min_tier`, `tier <= cap(assertion)`; coverage `covered <= universe`, `estate_covered <= estate_universe`; a HOLDS needs `universe >= 1`, `covered * 10000 >= required_bp * universe` and `selected.to >= 1`; a HOLDS `valid_until > issued_at`; a warning when `selected.stop_at * 2 > estate_universe`; the derived status ([03](03-verdicts-tiers-coverage-freshness.md)) |
| **9 ACCEPTANCE POLICY** | for each `require` entry: present; HOLDS (VIOLATED, UNKNOWN or derived EXPIRED reject); tier at least `min_tier`; coverage at least the consumer threshold by **integer** cross-multiplication; an optional pinned digest; exceptions at most `max_exceptions`; the `stop_at` share; per-invariant `max_age` against `snapshot.at`; then **all** results: any VIOLATED that is not required is `invariant.unrequired_violation` (reject by default; `violations: warn` downgrades); policy `disclosure: complete`; `require_latest`; `std_registry: strict`; engine advisories |
| **10 OPTIONAL** | the audit anchor (the bundle's `anchors/<max_id>.json` or `--anchor-file`): an Ed25519 v2 signature by an estate `anchor` key valid at `at`, fields equal to the statement's, `digest` equal, estate equal ([B](B-anchor-v2.md)); a v1 HMAC anchor is `anchor.not_ed25519`; Merkle inclusion proofs when supplied |

### Notes on step 0 and 1 error assignment

The reader of [01](01-conventions.md) 2.1 assigns the `input.*` codes. A document that parses but is not canonical
is `schema.payload_not_canonical` (step 1). An envelope with a wrong key set or wrong types is
`schema.envelope_invalid`; a signature count other than one is `sig.count_invalid`; a signature that does not
decode to 64 bytes is `sig.malformed`; a value that is not canonical base64 is `schema.base64_invalid`.

## 4. Command line (normative subset)

```
paddock-verify [--policy F] [--max-age D] [--min-coverage P] [--require ID[:TIER]]... [--offline]
   [--dns-resolver SPEC]... [--dns-min-resolvers N] [--dns-record TXT] [--roots F] [--add-roots F] [--std-registry F]
   [--state-file F | --no-state] [--history required|if_available|off] [--history-depth N] [--anchor-file F]
   [--max-anchor-age D] [--proofs-dir D] [--keys F] [--revoked F] [--now T] [--allow-private] [--timeout S]
   [--json] [--quiet] [--no-color] [--explain CODE] [--print-roots] [--version]  TARGET
```

`--now`, `--dns-resolver file:`, `--state-file`, `--roots`, `--std-registry`, `--anchor-file`, `--json` and
`--offline` are the **normative conformance interface** every conforming command line exposes. All input and output
sits behind a fetcher and a resolver, so `verify(bundle, policy, now=, resolver=, state=)` is pure and embeddable.
Defaults: `--max-age 48h` (baseline), anchor age gap 2 hours. `--explain CODE` prints the message, class, step and
the section that defines the check.

## 5. JSON report

`--json` prints a document shaped like `schema/verifier-report.schema.json`:

```
{report_version, verifier{name,version}, spec:"1.0", now, target, profile:"baseline"|"policy", policy_sha256,
 decision:"accepted"|"rejected"|"unverifiable", exit, primary, reasons[{code, class, step, params, message}], warnings[],
 checks[{step, id, status:"pass"|"fail"|"unverifiable"|"skip"|"not_evaluated", codes[]}], subject,
 key{kid, custody, vendor_certified, dns_bound, dnssec}, statement{seq, issued_at, valid_until, snapshot_at,
 policy{total, enabled_std, enabled_custom, disclosed, disabled}, min_tier}, results[{invariant, verdict, status, tier,
 coverage{covered, universe, percent_floor, required_bp}, valid_until, exceptions}], human[]}
```

`params` hold only schema-validated tokens, so attacker text never reaches the terminal. `reasons` list the R and U
codes in step order; `warnings` list the W codes.

## 6. Time and state

The verifier trusts its host clock; `--now` exists for tests and audits. A state file records, per subject, the
highest `seq` seen and its digest, so a rollback is detected; it reduces rollback acceptance but cannot fix clock
manipulation. An unreadable state file is `chain.state_unreadable` (unverifiable).
