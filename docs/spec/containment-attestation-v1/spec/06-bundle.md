<!-- SPDX-License-Identifier: Apache-2.0 -->
# 06. The bundle

A bundle is a static set of files. It is identical whether Paddock hosts it (prefix `/v1/public/attest/{domain}/`)
or the subject serves it (prefix `/.well-known/paddock/`). A verifier works from the files alone: if the publisher
is offline, verification of a bundle already fetched still works.

```
bundle.json                  {"spec":"paddock-attest-bundle/v1","domain":"example.com","generated_at":"<T>","head":{"seq":N,"digest":"sha256:.."},"paths":[...]}   (unsigned convenience)
keys.json                    05, section 3
revoked.json                 05, section 5 (DSSE)
attestation/latest.json      the DSSE envelope; byte-equal to attestation/<seq>.json (a mismatch is chain.latest_mismatch)
attestation/<seq>.json       immutable history (the last 60 are served)
attestation/index.json       [{"seq","statement_digest","issued_at","valid_until","kid"}], at most 60 entries, unsigned convenience
anchors/latest.json  anchors/<max_id>.json  anchors/index.json    public anchor documents (B); index entries {"max_id","at","kid"}
scope.json                   OPTIONAL, the scope document of 02 section 6
proofs/<seq>/<tree>.json     RESERVED for inclusion proofs; never served by hosted routes
```

* `statement_digest` and `head.digest` use the H form (`sha256:` plus hex) of the payload bytes.
* `index.json` and `bundle.json` are conveniences: the verifier never trusts them for a decision.
* Static hosts used by browsers need `Access-Control-Allow-Origin: *`.

## Discovery

`paddock-verify example.com` resolves `_paddock-attest.example.com` first for the `keys=` hint (its directory is the
bundle root), and otherwise uses `https://example.com/.well-known/paddock/`. A target may also be an explicit
`https://base/` URL, a single envelope file (siblings, or `--keys` and `--revoked`, supply the rest), or a
directory (the bundle root or its parent containing `.well-known/paddock`).

## Serving rules (for publishers)

* Strong `ETag: "sha256-<hex>"`; `Cache-Control`: `latest.json` `public, max-age=60`, `keys.json`
  `public, max-age=3600`, `revoked.json` `public, max-age=300`, numbered statements and anchors
  `public, max-age=31536000, immutable`. `X-Content-Type-Options: nosniff`, `Content-Type: application/json`.
* A publisher MUST write in an order such that a reader never sees `latest.json` before the signing key is listed in
  `keys.json`, and a revocation is never delayed behind a slow upload: `revoked.json`, `keys.json`, `anchors/*`,
  `attestation/<seq>.json`, `attestation/index.json`, `attestation/latest.json`, `bundle.json` last. After a push
  the publisher SHOULD read back `latest.json` and `revoked.json` and compare digests.
* Object size cap 512 KiB (`keys.json` 64 KiB). Inclusion proofs expose a leaf (node references, addresses) and are
  never part of a public bundle; the reserved path exists so owner-selected proofs can be added later without a
  format change.
* A hosting service SHOULD answer every non-served case (unknown, malformed, unpublished, failing, foreign) with
  the same response, so the route cannot be used to enumerate subjects.

## Verifier fetch rules

HTTPS only, no credentials, at most 3 redirects (https to https), 10 second timeout, `Accept-Encoding: identity`,
byte caps enforced while streaming, an IP-literal host refused, resolved loopback, link-local and private targets
refused unless `--allow-private` (the connect-time race is documented; embedders inject their own fetcher).
