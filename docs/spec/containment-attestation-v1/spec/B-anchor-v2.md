<!-- SPDX-License-Identifier: Apache-2.0 -->
# Appendix B. Audit anchor v2

An issuer's audit log is a keyed hash chain. Periodically the head of the chain is **anchored**: written to storage
the issuer cannot silently rewrite. A v2 anchor adds an Ed25519 signature so that an outsider can attribute and
order anchors.

## 1. The public anchor document

A PCJ document in the bundle at `anchors/<max_id>.json`:

```
{"alg":"ed25519","at":"2026-12-01T08:59:40Z","estate":"e_3fq7m2xk5h6cnj4d2v5yb7wzta","hash_alg":"hmac-sha256","head":"<64 hex>","kid":"<KID>","max_id":99120,"sig":"<base64 of 64 bytes>","v":2}
```

* `at` is the anchor time floored to whole seconds. `hash_alg` is the **family only** (`sha256` or `hmac-sha256`; the
  HMAC key id is not published). `estate` replaces any customer identifier.
* **Signature input** = `b"paddock-anchor/v2\n" + PCJ(document without sig)`, by the estate's `anchor` key (a
  certified key with `usage: anchor`, valid at `at`).
* `audit_anchor.digest` in a statement is `sha256:` plus the SHA-256 of `PCJ(document including sig)`.

## 2. What an outsider can verify, and what not

An outsider can verify:

1. the anchor signature verifies under a certified, unrevoked estate `anchor` key;
2. its `estate` equals the statement's;
3. `at <= issued_at` and `issued_at - at <= 2 hours` (`--max-anchor-age`);
4. `max_id` and `at` never decrease across statements and no two anchors share a `max_id` with different `head`;
5. with an independent copy of the sink (a read-only listing, an auditor's mirror: `--anchor-file`) a byte
   comparison, which is the only check that survives a compromised issuer.

An outsider **cannot** verify that the audit rows are intact (the chain is a keyed hash, the key never leaves the
issuer) or that a given policy edit is in the log. An auditor with the key can check that. The chain is never
described as "publicly verifiable".

## 3. Verifier behaviour (step 10)

| Condition | Code |
|---|---|
| anchor file or `audit_anchor` field absent | `anchor.unavailable` (U; a warning if the policy marks it optional; a reject when policy `anchor: required` and the field is absent) |
| a v1 HMAC-only anchor offered | `anchor.not_ed25519` |
| signature or format invalid, or the key not an anchor key valid at `at` | `anchor.invalid` |
| a field or the digest differs from the statement's | `anchor.mismatch` |
| `issued_at - at` above the allowed gap | `anchor.too_old` |
| `max_id` lower than in the previous statement | `anchor.max_id_regressed` (step 6) |

A statement without an `audit_anchor` field is legal: anchoring is optional by default. A signature is Ed25519 over a
context that no statement or certificate signature can share, so an anchor signature never verifies as a statement
signature.
