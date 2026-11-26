<!-- SPDX-License-Identifier: Apache-2.0 -->
# 05. Keys, certificates, revocation and DNS binding

Normative. Trust in a statement rests on **two independent anchors**, both required by default: a certificate chain
to a pinned root (the vendor anchor) and the subject's own DNS (the domain anchor).

## 1. Hierarchy

```
attestation ROOT   (offline, Ed25519, pinned in the verifier release, 10 years)
   |-- certifies, offline, yearly -->
ISSUER  (usage issue-cert, 1 year)         REVOKER  (usage revoke, 1 year, can only deny)
   |-- certifies, online -->
estate ATTEST key (usage attest, signs statements)      estate ANCHOR key (usage anchor, signs anchors)
```

* The chain length below the root is fixed at 2. A self-hoster MAY pin its own issuer as a root
  (`usage: "issue-cert"`) and use chain length 1.
* Trust roots are data shipped with the verifier: `[{"kid","public_key"(base64),"usage":"root"|"issue-cert","not_before","not_after"}]`.
  A build with no roots exits 2 with `config.no_trust_roots` unless `--roots` is given. Custom roots print
  "custom trust roots in use".
* Only the Ed25519 algorithm is defined in v1. `alg` is a per-key field; an unknown value is unverifiable.

## 2. Certificate

A DSSE envelope with `payloadType` `application/vnd.paddock.key-cert+json`, one signature by the parent key,
PCJ payload:

```json
{"_type":"https://paddock.dev/key-cert/v1","alg":"ed25519","custody":"hosted","estate":"e_3fq7m2xk5h6cnj4d2v5yb7wzta",
 "issuer_kid":"<parent kid>","kid":"<KID>","not_after":"2027-03-01T00:00:00Z","not_before":"2026-12-01T00:00:00Z",
 "public_key":"<base64 of the raw 32 bytes>","serial":17,"usage":"attest"}
```

* `usage` is `attest`, `anchor`, `issue-cert` or `revoke`. `estate` is present for `attest` and `anchor` and absent
  otherwise. `custody` is `hosted`, `byok-kms` or `byok-hsm`; a verifier prints it. There is **no domain** in a
  certificate: domains change, and a certificate would enumerate them.
* `kid` MUST equal the first 32 hex of the SHA-256 of `public_key` (`key.fingerprint_mismatch`). A child's validity
  window is clamped to its parent's. **Every certificate in the chain MUST be valid at the statement's `issued_at`**,
  not at "now" (`issuer.outside_validity`, `key.outside_validity`); the signing key's window must also contain
  `valid_until`.
* The usage must match the use: an anchor key cannot sign a statement, a statement key cannot sign an anchor
  (`key.cert_subject_mismatch`).
* Suggested windows (informative): root 10 years; issuer and revoker 1 year; estate key 365 days (rotate at 300) with
  certificate renewal every 90 days using the same key (a new serial), because the DNS record pins the key
  fingerprint and a certificate renewal must be free.

## 3. keys.json

A public, unsigned wrapper (every certificate inside is signed and authoritative):

```json
{"spec":"paddock-keys/v1","estate":"e_...","issuers":[<issuer cert envelope>],"revoker":<revoker cert envelope>,
 "keys":[{"kid":"...","usage":"attest","alg":"ed25519","public_key":"<b64>","custody":"hosted","not_before":"..","not_after":"..","cert":<cert envelope>}]}
```

Every unsigned entry field MUST equal the certificate payload (`key.cert_subject_mismatch`); a duplicate `kid`
makes the file `keys.invalid`. Key status is deliberately not in the file (it is mutable and unsigned). Retired
keys stay in the file so their history verifies.

## 4. Rollover

A new key K2 is created as pending 30 days before the old key K1 would be retired and its second TXT record is
published. The issuer observes K2 in DNS (two observations at least `min(TTL, 1 hour)` apart), then switches
signing. K1 stays listed; its TXT record may be removed after 2 x TTL. At most three kids are in DNS at once
(active, next, previous). The chain `seq`/`prev` continues across key rotation. Key status moves only forward:
pending, active, retiring, retired; any state to revoked; revoked is terminal.

## 5. Revocation list (`revoked.json`)

A DSSE envelope with `payloadType` `application/vnd.paddock.revocation-list+json`, signed by the **revoker** key
(or the issuer key), whose certificate is in `keys.json` and chains to a pinned root:

```json
{"_type":"https://paddock.dev/revocation-list/v1","estate":"e_...","seq":42,"issued_at":"<T>","next_update":"<T, issued_at + 24 h>",
 "revoked":[{"kid":"<kid>","reason":"key_compromise"|"superseded"|"cessation","revoked_at":"<T>"}],
 "superseded":[{"subject":"dns:example.com","min_seq":1843,"at":"<T>"}]}
```

* `key_compromise` rejects **every** statement signed by that key regardless of its claimed `issued_at` (a claimed
  time is attacker-controlled once a key is compromised) (`key.revoked`). `superseded` and `cessation` reject only
  statements with `issued_at >= revoked_at`; older ones warn `key.revoked_superseded`.
* `superseded[]` rejects statements of that subject with `seq < min_seq` (`chain.superseded`). It is written on every
  downgrade and when the issuer loses the ability to evaluate (then `min_seq = last_seq + 1`, meaning "no statement
  at or above this exists"). One entry per subject, at most 11.
* The list's own `seq` never goes backwards against a cached copy. A missing list is `revocation.missing`, one that
  fails verification is `revocation.unverifiable`, one with `now > next_update + 48 hours` is `revocation.stale`:
  all unverifiable, never accepted. The list is mandatory in every bundle and re-signed at least daily. A consumer
  policy `revocation: best_effort` downgrades these to warnings and the output then says "revocation NOT checked".
* An issuer revocation signed by the root ships with the verifier release (`issuer.revoked`).
* Honest bound: latency is up to the list's age; an offline copy of a statement is bounded by its own
  `valid_until`.

## 6. DNS key binding

### 6.1 Record

`_paddock-attest.<domain>` (the exact name, no parent climbing: `app.example.com` publishes under
`_paddock-attest.app.example.com`), TXT:

```
v=1; kid=<32hex>; fp=sha256:<64hex>[; keys=https://.../keys.json]
```

`fp` is the SHA-256 of the raw 32-byte public key; `kid` is its first 32 hex (the redundancy is checked, so a hand
edit cannot disagree). `keys` is optional (default `https://<domain>/.well-known/paddock/keys.json`); the bundle
root is the directory of the `keys` URL. It is a **location hint only**: everything fetched is authenticated by
certificate and `fp`, never by transport.

Sizes: minimal 117 bytes, 189 for a hosted short domain, 237 for a 60-character domain. A generator hard-fails above
450 bytes and warns above 255 (split strings are legal and joined with no separator); three records (active, next,
previous) stay under the EDNS budget.

### 6.2 Parser rules

One implementation, exercised by `vectors/primitives/dns-txt-parse.json`:

1. The strings of one TXT record are concatenated with no separator. The result MUST be ASCII and at most 1024
   bytes, else the record is **malformed**.
2. **Version pre-scan.** Split on `;`, drop one leading space per field. If exactly one field starts `v=` and its
   value is a plain token (`[A-Za-z0-9._-]{1,16}`) other than `1`, the record is **ignored** silently
   (forward compatibility); nothing else is parsed.
3. Otherwise: remove at most one trailing `;`; the record must not be empty; fields are separated by `;` followed by
   at most one space; a field has no other whitespace, tab or empty content. A field is `key=value` split at the
   **first** `=`; the key is `[a-z][a-z0-9_-]*` (lowercase: an uppercase tag is an unknown tag), the value is
   non-empty printable ASCII without `;` and without spaces.
4. A **duplicate key** (including unknown keys) makes the record malformed. Unknown keys are otherwise ignored.
5. Required: `v` equal to `1`, `kid` (32 lowercase hex), `fp` (`sha256:` plus 64 lowercase hex) with
   `fp[7:39] == kid`; optional `keys` must start with `https://` followed by at least one character (at most 300).
   Any failure makes the record malformed.
6. A malformed record is ignored with the warning `dns.record_ignored`. More than 8 records under the name, or more
   than 4096 bytes in total, is `dns.too_many_records` (reject: a denial-of-service guard).

### 6.3 What a verifier checks without trusting the publisher

1. Resolve the TXT with **its own** resolvers, never the publisher's. Resolver kinds (all standard library):
   `doh:<url>` (RFC 8484, EDNS0 with DO=1, compression pointers handled, 4 KiB cap; default Cloudflare and Google),
   `udp:<ip>[:port]` (TCP fallback on truncation), `system`, `file:<path>` (offline use and tests; several named
   resolvers make a disagreement expressible), and an injectable fake.
2. **Quorum**: all configured resolvers that answer must agree; at least `--dns-min-resolvers` (default 2 for the
   default DoH set, else 1) must answer (`dns.insufficient_resolvers`); disagreement is `dns.resolvers_disagree`.
   Never "accept the one that matches".
3. Parse; pick the records whose `kid` equals the signing key's. None (NXDOMAIN, no data, or no valid record) is
   `dns.no_binding`. SERVFAIL, timeout or transport failure is `dns.lookup_failed` (unverifiable).
4. `fp` equals the SHA-256 of the public key **in the certificate**, the certificate's key verifies the statement,
   the certificate chains to a pinned root, and the revocation list is fresh and does not list it. A different `fp`
   for the matching kid is `dns.mismatch`; the same kid with two fingerprints is `dns.record_conflict`. A foreign
   kid next to ours is fine (legitimate co-hosting).
5. Report `dnssec`: `ad_asserted`, `not_asserted` or `unknown`. The AD bit is the resolver's claim over its own
   channel; policy `dnssec: required` without it is `dns.dnssec_unproven`.
6. A retired key's old statements verify in `--history` mode with the binding reported as retired. Offline mode:
   `--dns-record "<txt>"` is reported as asserted by the operator and is `dns.skipped_offline` (unverifiable) when
   the policy requires DNS. A subject of the form `paddock-estate:` has no domain: `dns.not_applicable` (warning),
   and a policy requiring DNS rejects it.
7. Privacy: the resolver sees which domain is being verified. A registrar or DNS compromise defeats the domain
   anchor; the vendor certificate is the second, independent anchor and both are required by default.

A statement naming `dns:victim.com` is accepted for victim.com only if victim.com's own DNS record names this key
(the confused-deputy defence).

## 7. The standard registry and advisories

`registry/std-registry.json` is the **only** place a `std:` digest becomes trusted: the verifier cannot recompute
digests because that needs the engine's canonicaliser.

```json
{"registry_version":1,"rulesets":{"sha256:<ruleset>":{"engine":"0.3.0","std":{"std:no-internet-to-datastore":{"digest":"sha256:..","assertion":"unreachable","name":"No internet path reaches a data store","status":"current"}}}}}
```

`ruleset = sha256(PCJ({"std":[{"digest":..,"id":..},...sorted by id],"v":1}))` over the shipped library. `engine`
is the first engine version that shipped the ruleset. A statement whose ruleset is not in the registry is
`engine.ruleset_unknown` (unverifiable); a `std:` id that is not in the ruleset is `std.id_unknown`; a digest that
differs is `std.digest_mismatch`. An older ruleset has `status: deprecated` (accepted with a warning); `withdrawn`
rejects. `registry/advisories.json` lists engine versions with known defects that could produce a false HOLDS:
`{"advisories_version":1,"items":[{"id":"PA-ADV-0001","engine":"0.2.0","effect":"reject"|"warn","summary":"<ascii>"}]}`
(empty at the first release). A listed version is `engine.advisory`.
