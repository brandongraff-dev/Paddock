<!-- SPDX-License-Identifier: Apache-2.0 -->
# paddock-verify

An independent, offline verifier for Paddock **containment attestations**. A third party, such as an insurer
or a procurement team, can check that an attestation was really signed by a key the domain owner named in DNS,
that the key is certified and not revoked, that the statement is current, and what it does and does not say,
**without trusting Paddock or its servers**.

Apache-2.0. The only run-time dependency is [`cryptography`](https://pypi.org/project/cryptography/); Python 3.9
or newer. The format is specified in [`docs/spec/containment-attestation-v1`](../docs/spec/containment-attestation-v1/README.md).

```bash
pip install paddock-verify
paddock-verify example.com                       # fetch the bundle, check DNS, verify
paddock-verify --offline --dns-record "<txt>" ./bundle-dir
paddock-verify --policy acceptance.yaml --json example.com
```

Exit codes: `0` accepted, `1` rejected, `2` unverifiable, `64` usage error. Any unexpected failure exits `2`,
never `0`.

## What a pass means

A pass means: *a named issuer's engine, running invariants identified by their digests, searched the evidence
available to it at one time and found no counterexample; this much of the estate had live evidence; the key is
certified and named by the domain's DNS; the result is current until the printed time.* It does **not** mean the
organisation is secure. Every report prints the pinned limits text, and the verifier never prints a bare green
"pass". See `spec/12-conformance.md`, `spec/11-security-considerations.md` and the limits in
`spec/09-human-wording.md`.

## This package (P3.1 layer)

The byte-level modules are independent of the pipeline and are what other implementations must reproduce
exactly:

| Module | Rule |
|---|---|
| `jsonstrict`, `canon` | strict JSON reader and PCJ, the signed-JSON profile (spec 01 section 2.1) |
| `b64` | canonical standard base64 (2.2) |
| `merkle` | RFC 6962 blinded trees and RFC 9162 proofs (spec 04) |
| `dsse` | DSSE envelope parsing and the pre-authentication encoding (2.4) |
| `ed25519` | the specification's own pre-checks before any library call (2.5) |
| `timefmt` | strict timestamps and end-exclusive windows (2.6) |
| `limits` | every numeric limit, the pinned limits text, integer coverage arithmetic |
| `codes` | the stable reason codes (spec A) and the public UNKNOWN reason-code enum |
| `wording` | the verifier-owned sentences and the forbidden-vocabulary scan (spec 09) |

## Tests

```bash
pip install -e '.[dev]'
pytest -q
python ../docs/spec/containment-attestation-v1/conformance/run.py --help   # language-neutral conformance runner
```
