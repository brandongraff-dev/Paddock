<!-- SPDX-License-Identifier: Apache-2.0 -->
# 01. Conventions and byte-level rules

Normative. Every implementation applies these rules before it interprets anything. They are deliberately stricter
than DSSE and in-toto norms: strictness costs nothing because producers are known, and every leniency is a place
where two implementations can disagree about what was signed.

## 1. Notation and grammar

| Name | Definition |
|---|---|
| **T** | `YYYY-MM-DDTHH:MM:SSZ`: exactly that shape (ASCII digits, uppercase `T` and `Z`), then calendar validated: years 2000 to 9999, no `:60`, no 30 February, leap years by the Gregorian rule. Offsets, fractions and lowercase are invalid. |
| **H** | `sha256:` followed by 64 lowercase hex characters. |
| **KID** | 32 lowercase hex characters: the first half of the SHA-256 of a raw 32-byte public key. |
| **ESTATE** | `e_` followed by 26 characters of `[a-z2-7]`: a random 128-bit chain identity, never derived from a customer identifier. |
| **INV** | `[a-z][a-z0-9]{0,31}:[a-z0-9][a-z0-9-]{0,63}`: an invariant id. The namespace `std:` is reserved for the standard library. |
| **UINT** | An integer from 0 to 2^53 - 1. |
| **SUBJECT** | `dns:<domain>` (lowercase, A-label, no trailing dot, labels of at most 63 and a total of at most 253 characters, at least two labels, no IP literal) or `paddock-estate:<ESTATE>`. |
| **hex** | Lowercase only. |

Optional fields are **omitted**, never `null`. A value of the wrong JSON type (for example the boolean `true`
where an integer is required) is invalid even though many languages treat booleans as integers.

## 2. Byte-level rules

### 2.1 PCJ: the signed JSON profile (a strict subset of RFC 8785)

PCJ applies to statements, key certificates, revocation lists, public anchor documents, Merkle leaf records and the
scope document: every document whose exact bytes are signed or hashed.

* The document is bytes that are pure ASCII `0x20` to `0x7E`. A BOM, any byte of `0x7F` or more and any control byte
  (including a trailing newline) is rejected.
* Value types: object, array, string, **non-negative integer**, boolean. No `null`, no float, no exponent, no
  fraction.
* Integers: base 10, `0` or `[1-9][0-9]*`, at most 2^53 - 1. `-0`, `+1`, `01`, `1.0` and `1e2` are rejected.
* Strings: characters `0x20` to `0x7E` **except `"` and `\`**. A conforming document therefore contains no escape
  sequence: any backslash means the document is not canonical. Object keys follow the same rule, are non-empty and
  unique.
* Objects: keys sorted by byte value (for ASCII identical to the UTF-16 code-unit order that RFC 8785 requires). No
  insignificant whitespace.
* Limits: nesting depth at most 16 (8 inside a statement), total size at most 1 MiB, enforced before parsing (length)
  and during it (depth).

**Strict parse and canonical round trip.** A reader parses the bytes with these rejections, in this order of
reporting:

| Condition | Reason code |
|---|---|
| more than 1 MiB | `input.too_large` |
| a byte of `0x7F` or more (including a BOM) | `input.not_ascii` |
| nesting deeper than the limit | `input.depth_exceeded` |
| a number that is not a plain in-range non-negative integer: `-0`, `01`, `+1`, `1.0`, `1e2`, `NaN`, `Infinity`, above 2^53 - 1, more than 16 digits | `input.number_invalid` |
| a repeated object key (also when the keys differ only by an escape, such as `"a"` and `"\u0061"`) | `input.duplicate_key` |
| anything else that is not JSON under this profile: `null`, trailing commas, comments, single quotes, a lone surrogate escape, a raw control character in a string, trailing data, empty input | `input.not_json` |

If the parse succeeds the reader re-encodes the value as PCJ and requires **byte equality** with the received
bytes; otherwise the document is `schema.payload_not_canonical`. This catches whitespace, escapes (including
`\u0041` and `\/`), unsorted keys, an empty key and any string that PCJ cannot hold. A validly signed but
non-canonical payload is therefore rejected too.

*Encoder rule.* Write the value as above. Nothing else is needed, and any RFC 8785 implementation yields the same
bytes for a conforming value. A producer MUST check the charset first and fail rather than escape.

*Pitfalls* (each has a vector): Python 3.11 and later raise `ValueError` for an integer over 4300 digits, which must
map to the same error as any other out-of-range number; a `ValueError` subclass for canonical errors must be caught
before `ValueError` or it is relabelled; a boolean is not an integer.

The unsigned outer files (the DSSE envelope, `keys.json`, `revoked.json` as an envelope, bundle conveniences) are
read with the same strict parse (ASCII, no duplicate keys, number rules, depth 16) but are **not** required to be
canonical: whitespace and escapes are accepted there.

### 2.2 base64

Standard alphabet, padding required, no whitespace, no line breaks, and `encode(decode(x)) == x`. The last rule
rejects non-zero trailing bits. The URL-safe alphabet and missing padding are `schema.base64_invalid`. This is
deliberately narrower than DSSE's "accept both". Digests and ids are lowercase hex, not base64.

### 2.3 Hashes

All hashes are SHA-256. Hashes that chain statements (`prev`, `anchor.digest`, proofs) are over **decoded payload
bytes**, so base64 and envelope variants never influence them.

### 2.4 DSSE pre-authentication encoding

```
PAE(type, payload) = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
```

`SP` is a single `0x20`; `LEN` is the ASCII decimal **byte** count with no leading zeros; `type` is the envelope's
`payloadType`, which MUST equal the constant expected for the document kind:

| Document | `payloadType` |
|---|---|
| statement | `application/vnd.in-toto+json` |
| key certificate (all usages) | `application/vnd.paddock.key-cert+json` |
| revocation list | `application/vnd.paddock.revocation-list+json` |

A signature is Ed25519, pure (no pre-hash), over the PAE of the **decoded** payload bytes. Signing the base64 text
or the raw payload instead of the PAE is the classic bug; vectors pin it. Signature contexts are mutually
non-prefix: `DSSEv1 ` (statements, certificates, revocation lists), `paddock-anchor/v2` followed by a line feed
(anchors), and, in the issuer's agent protocol, `paddock-agent-envelope/v1` and `paddock-enroll/v1`. A signature in
one context can never verify in another.

### 2.5 Ed25519

Every implementation applies these rules **before** calling its library, in this order:

1. The signature is exactly 64 bytes, else `sig.malformed`.
2. The public key is exactly 32 bytes, a canonical point encoding (y below 2^255 - 19, a point on the curve, and no
   "negative zero" with x = 0 and the sign bit set) and **not one of the eight small-order points**, else
   `sig.weak_key`.
3. `S < L` where `S` is bytes 32 to 63 read little-endian and `L = 2^252 + 27742317777372353535851937790883648493`,
   else `sig.noncanonical_s`.
4. The signature verifies, else `sig.invalid`.

The reason is practical: one widely deployed library accepts the identity public key with an identity signature
over **any** message, and engines differ on `S >= L`. `R` is not pre-checked; the residual cofactor ambiguity
requires a malicious signer, and a signer here is a certified key. The algorithm of a key comes from its
certificate, never from the envelope; an unknown algorithm is `sig.alg_unsupported` (unverifiable), never a
fallback. Vectors: RFC 8032 tests 1 to 3, `S + L`, the identity key with the identity signature, a 2-torsion key,
the eight small-order encodings, non-canonical encodings, a point off the curve.

### 2.6 Time

Instants compare as integers (seconds since 1970-01-01T00:00:00Z) parsed by a hand-written parser, because library
parsers vary by version. Windows are **end-exclusive**:

```
valid iff  issued_at - 300 <= now < valid_until
```

`now >= valid_until` is `time.expired` and is judged first. Producers floor engine timestamps to whole seconds
(flooring is conservative for `valid_until`). Durations in a policy are `<integer>(s|m|h|d)`, integer `0` or
`[1-9][0-9]*`, at most 2^53 - 1 seconds.

### 2.7 Frozen legacy encodings (informative)

Invariant digests and fact digests are SHA-256 values computed by the engine over its own frozen encoding, which
is not PCJ (it may contain a float such as `1.0`). They must not be changed, and to a verifier they are opaque
`sha256:<hex>` identifiers. The registry ([05](05-keys-certs-revocation-dns.md), `registry/std-registry.json`)
is the only place such a digest becomes trusted.

## 3. Size limits

| What | Limit |
|---|---|
| decoded statement payload | 256 KiB |
| DSSE envelope as received | 512 KiB |
| any other file read (`keys.json`, `revoked.json`, policy, proof) | 256 KiB (`keys.json` as hosted: 64 KiB) |
| everything read in one run | 8 MiB |
| JSON nesting | 8 in a statement, 16 anywhere else |
| results in a statement | 256 |
| any string in a statement | 512 bytes |
| a statement's `valid_until - issued_at` | 7 days |

A limit failure is a reject (`input.too_large`, `schema.limit_exceeded`, `input.depth_exceeded`): a hostile
publisher must not be able to exhaust a verifier.
