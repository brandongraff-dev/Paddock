<!-- SPDX-License-Identifier: Apache-2.0 -->
# Appendix C. Worked example

One complete statement, every byte reproducible. All values are produced by `tools/gen_vectors.py` and pinned in
`vectors/primitives/worked-example.json`; nothing here is typed by hand. The keys are the **public test keys**
derived from the conformance seeds ([12](12-conformance.md) section 2): never trust them.

## Keys and DNS

Test key `tenant-a`: seed `sha256(b"paddock-conformance-seed/v1/tenant-a")`; public key
`SSJYp+SRzsje7AY/OPHucOc6+STVMppqHDvdYR9OLmk=`; `kid = 2ceb61e24df5fde7c0ab24b2a2774fa4`. The DNS record that binds it:

```
_paddock-attest.example.com. 300 IN TXT "v=1; kid=2ceb61e24df5fde7c0ab24b2a2774fa4; fp=sha256:2ceb61e24df5fde7c0ab24b2a2774fa4cccecbb50a4b7f487b874c4baf7807a8; keys=https://example.com/.well-known/paddock/keys.json"
```

Anchor key `anchor-a`: public key `u45ixP3frxff11KsgHX0HrqrB5Om7isLnn4ye8ONzzQ=`, `kid = 9aef608fe4565a8f55947deec61af518`.
The public anchor document (PCJ), signed over `b"paddock-anchor/v2\n" + PCJ(document without sig)`:

```
{"alg":"ed25519","at":"2026-12-01T08:59:40Z","estate":"e_3fq7m2xk5h6cnj4d2v5yb7wzta","hash_alg":"hmac-sha256","head":"97bb9e1663d52746e2d4860a6ad168f63126e7282fe41897e8743cf24926b24b","kid":"9aef608fe4565a8f55947deec61af518","max_id":99120,"sig":"+FLKQ8G5lsu2UPyV9ymaUkkd+PTkWNCE7VO+S9b1/JAxhcjfbw1lAXXXm8gTeYlHjiBY0VYblJQ2eSHB8U6oBQ==","v":2}
```

`audit_anchor.digest = sha256:5f06ee2d93da06240f8c46c6d40844b0f8364a8142d2ee91bc3e83d7ba9ac0b8`.

## Commitments (with `commit_key` = 32 bytes of 0x01)

| Item | Value |
|---|---|
| empty tree root | `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| policy tree (three std rows) | `sha256:1ceecb33a4ca1bf921a3336c237c60c55068826cf4fe6bc83c6de172c061551d` |
| graph tree (three leaves) | `sha256:7b5165627f159516c5e6f40f4875c238fe2d607d816be24d320a9ad5da9580e7` |
| blind-spot tree of the first result (one leaf) | `sha256:ed05f1c6aa2391a9bd2ae7ab2aa47f239e20ab3741915a4cf8632c9a306dd8c0` |
| scope document | `{"entries":[{"kind":"domain","value":"example.com"}],"v":1}` |
| scope digest | `sha256:be3fe528ef2b63fbb572c9bf47918ef6eacb45d7233231581fbb06c193044b7c` |
| subject digest of `dns:example.com` | `sha256:2e93281bfa333b6ab13689eab03c2025404912f99af7b698f19f6ad678eb67e3` |
| limits digest | `sha256:330258fa3556e0417b000fa9cae4a2cd1853d4402a17762c5b030b1652d7c37f` |
| ruleset of the engine that shipped these std invariants | `sha256:b13ad8f0f157b2a037ce106ae96b692b09785be865259702dc45adf3fb15a299` |

The policy tree's leaves are ordered by leaf hash: `std:server-ssh-hardened` (`0e53fcfd...`),
`std:no-internet-to-datastore` (`23333591...`), `std:guest-cannot-reach-pos` (`afda932d...`).

## The statement

Two of the three enabled std invariants are disclosed; the third is simply not shown as holding, which
`policy.disclosed = 2` against `enabled_std = 3` makes visible.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicate": {
    "audit_anchor": {
      "at": "2026-12-01T08:59:40Z",
      "digest": "sha256:5f06ee2d93da06240f8c46c6d40844b0f8364a8142d2ee91bc3e83d7ba9ac0b8",
      "hash_alg": "hmac-sha256",
      "head": "97bb9e1663d52746e2d4860a6ad168f63126e7282fe41897e8743cf24926b24b",
      "kid": "9aef608fe4565a8f55947deec61af518",
      "max_id": 99120
    },
    "disclosure": {
      "custom": false,
      "verdicts": "holds_only"
    },
    "engine": {
      "name": "paddock-assurance",
      "ruleset": "sha256:b13ad8f0f157b2a037ce106ae96b692b09785be865259702dc45adf3fb15a299",
      "version": "0.3.0"
    },
    "estate": "e_3fq7m2xk5h6cnj4d2v5yb7wzta",
    "issued_at": "2026-12-01T09:00:00Z",
    "kid": "2ceb61e24df5fde7c0ab24b2a2774fa4",
    "limits": {
      "digest": "sha256:330258fa3556e0417b000fa9cae4a2cd1853d4402a17762c5b030b1652d7c37f",
      "id": "paddock-limits/1"
    },
    "policy": {
      "commitment": "sha256:1ceecb33a4ca1bf921a3336c237c60c55068826cf4fe6bc83c6de172c061551d",
      "disclosed": 2,
      "enabled_custom": 0,
      "enabled_std": 3,
      "total": 3,
      "versions": 3
    },
    "results": [
      {
        "assertion": "unreachable",
        "blind_spots": {
          "root": "sha256:ed05f1c6aa2391a9bd2ae7ab2aa47f239e20ab3741915a4cf8632c9a306dd8c0",
          "size": 1,
          "truncated": false
        },
        "coverage": {
          "covered": 41,
          "estate_covered": 118,
          "estate_universe": 120,
          "required_bp": 9500,
          "universe": 42
        },
        "digest": "sha256:a6a8227c5cc662a688f14fe5c79dbe929539369c6bd5639750e72c1b92298bc6",
        "exceptions": 0,
        "invariant": "std:no-internet-to-datastore",
        "max_age_s": 86400,
        "min_tier": "configured",
        "selected": {
          "from": 1,
          "stop_at": 3,
          "to": 4
        },
        "tier": "configured",
        "valid_until": "2026-12-02T08:40:00Z",
        "verdict": "HOLDS"
      },
      {
        "assertion": "host-config",
        "blind_spots": {
          "root": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "size": 0,
          "truncated": false
        },
        "coverage": {
          "covered": 3,
          "estate_covered": 118,
          "estate_universe": 120,
          "required_bp": 10000,
          "universe": 3
        },
        "digest": "sha256:e118308d1eb364979bffb1609cb40171c11006d38d4b6087b73cafdd5b2bb0f1",
        "exceptions": 0,
        "invariant": "std:server-ssh-hardened",
        "max_age_s": 21600,
        "min_tier": "configured",
        "selected": {
          "to": 3
        },
        "tier": "configured",
        "valid_until": "2026-12-01T14:50:00Z",
        "verdict": "HOLDS"
      }
    ],
    "scope": {
      "digest": "sha256:be3fe528ef2b63fbb572c9bf47918ef6eacb45d7233231581fbb06c193044b7c",
      "entries": 1,
      "private": 0,
      "unproven": 0
    },
    "seq": 1,
    "snapshot": {
      "at": "2026-12-01T08:57:12Z",
      "graph": {
        "root": "sha256:7b5165627f159516c5e6f40f4875c238fe2d607d816be24d320a9ad5da9580e7",
        "size": 3
      }
    },
    "valid_until": "2026-12-02T09:00:00Z"
  },
  "predicateType": "https://paddock.dev/attestation/containment/v1",
  "subject": [
    {
      "digest": {
        "sha256": "2e93281bfa333b6ab13689eab03c2025404912f99af7b698f19f6ad678eb67e3"
      },
      "name": "dns:example.com"
    }
  ]
}
```

The signed bytes are the PCJ form: **2536 bytes, SHA-256 `ccd9d6bcfa3d9ef1b18bd5cfb1f864d13d50f0239eb055d40f28e9ea5e6278db`**.

## Signature and envelope

The PAE begins `DSSEv1 28 application/vnd.in-toto+json 2` followed by the payload. The Ed25519 signature (base64) is

```
c5fOB7whPuYeD9wONEz/Ppl+zY5l3x5FxBz4qogxnjF8P4mg2ZzqMyunTj+XrkQF3WoGE12Ri6/6btdiBYyqBg==
```

and the envelope (here printed by a standard JSON library with its default separators; whitespace in the envelope is
not significant) is

```
{"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGUiOnsiYXVkaXRfYW5jaG9yIjp7ImF0IjoiMjAyNi0xMi0wMVQwODo1OTo0MFoiLCJkaWdlc3QiOiJzaGEyNTY6NWYwNmVlMmQ5M2RhMDYyNDBmOGM0NmM2ZDQwODQ0YjBmODM2NGE4MTQyZDJlZTkxYmMzZTgzZDdiYTlhYzBiOCIsImhhc2hfYWxnIjoiaG1hYy1zaGEyNTYiLCJoZWFkIjoiOTdiYjllMTY2M2Q1Mjc0NmUyZDQ4NjBhNmFkMTY4ZjYzMTI2ZTcyODJmZTQxODk3ZTg3NDNjZjI0OTI2YjI0YiIsImtpZCI6IjlhZWY2MDhmZTQ1NjVhOGY1NTk0N2RlZWM2MWFmNTE4IiwibWF4X2lkIjo5OTEyMH0sImRpc2Nsb3N1cmUiOnsiY3VzdG9tIjpmYWxzZSwidmVyZGljdHMiOiJob2xkc19vbmx5In0sImVuZ2luZSI6eyJuYW1lIjoicGFkZG9jay1hc3N1cmFuY2UiLCJydWxlc2V0Ijoic2hhMjU2OmIxM2FkOGYwZjE1N2IyYTAzN2NlMTA2YWU5NmI2OTJiMDk3ODViZTg2NTI1OTcwMmRjNDVhZGYzZmIxNWEyOTkiLCJ2ZXJzaW9uIjoiMC4zLjAifSwiZXN0YXRlIjoiZV8zZnE3bTJ4azVoNmNuajRkMnY1eWI3d3p0YSIsImlzc3VlZF9hdCI6IjIwMjYtMTItMDFUMDk6MDA6MDBaIiwia2lkIjoiMmNlYjYxZTI0ZGY1ZmRlN2MwYWIyNGIyYTI3NzRmYTQiLCJsaW1pdHMiOnsiZGlnZXN0Ijoic2hhMjU2OjMzMDI1OGZhMzU1NmUwNDE3YjAwMGZhOWNhZTRhMmNkMTg1M2Q0NDAyYTE3NzYyYzViMDMwYjE2NTJkN2MzN2YiLCJpZCI6InBhZGRvY2stbGltaXRzLzEifSwicG9saWN5Ijp7ImNvbW1pdG1lbnQiOiJzaGEyNTY6MWNlZWNiMzNhNGNhMWJmOTIxYTMzMzZjMjM3YzYwYzU1MDY4ODI2Y2Y0ZmU2YmM4M2M2ZGUxNzJjMDYxNTUxZCIsImRpc2Nsb3NlZCI6MiwiZW5hYmxlZF9jdXN0b20iOjAsImVuYWJsZWRfc3RkIjozLCJ0b3RhbCI6MywidmVyc2lvbnMiOjN9LCJyZXN1bHRzIjpbeyJhc3NlcnRpb24iOiJ1bnJlYWNoYWJsZSIsImJsaW5kX3Nwb3RzIjp7InJvb3QiOiJzaGEyNTY6ZWQwNWYxYzZhYTIzOTFhOWJkMmFlN2FiMmFhNDdmMjM5ZTIwYWIzNzQxOTE1YTRjZjg2MzJjOWEzMDZkZDhjMCIsInNpemUiOjEsInRydW5jYXRlZCI6ZmFsc2V9LCJjb3ZlcmFnZSI6eyJjb3ZlcmVkIjo0MSwiZXN0YXRlX2NvdmVyZWQiOjExOCwiZXN0YXRlX3VuaXZlcnNlIjoxMjAsInJlcXVpcmVkX2JwIjo5NTAwLCJ1bml2ZXJzZSI6NDJ9LCJkaWdlc3QiOiJzaGEyNTY6YTZhODIyN2M1Y2M2NjJhNjg4ZjE0ZmU1Yzc5ZGJlOTI5NTM5MzY5YzZiZDU2Mzk3NTBlNzJjMWI5MjI5OGJjNiIsImV4Y2VwdGlvbnMiOjAsImludmFyaWFudCI6InN0ZDpuby1pbnRlcm5ldC10by1kYXRhc3RvcmUiLCJtYXhfYWdlX3MiOjg2NDAwLCJtaW5fdGllciI6ImNvbmZpZ3VyZWQiLCJzZWxlY3RlZCI6eyJmcm9tIjoxLCJzdG9wX2F0IjozLCJ0byI6NH0sInRpZXIiOiJjb25maWd1cmVkIiwidmFsaWRfdW50aWwiOiIyMDI2LTEyLTAyVDA4OjQwOjAwWiIsInZlcmRpY3QiOiJIT0xEUyJ9LHsiYXNzZXJ0aW9uIjoiaG9zdC1jb25maWciLCJibGluZF9zcG90cyI6eyJyb290Ijoic2hhMjU2OmUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLCJzaXplIjowLCJ0cnVuY2F0ZWQiOmZhbHNlfSwiY292ZXJhZ2UiOnsiY292ZXJlZCI6MywiZXN0YXRlX2NvdmVyZWQiOjExOCwiZXN0YXRlX3VuaXZlcnNlIjoxMjAsInJlcXVpcmVkX2JwIjoxMDAwMCwidW5pdmVyc2UiOjN9LCJkaWdlc3QiOiJzaGEyNTY6ZTExODMwOGQxZWIzNjQ5NzliZmZiMTYwOWNiNDAxNzFjMTEwMDZkMzhkNGI2MDg3YjczY2FmZGQ1YjJiYjBmMSIsImV4Y2VwdGlvbnMiOjAsImludmFyaWFudCI6InN0ZDpzZXJ2ZXItc3NoLWhhcmRlbmVkIiwibWF4X2FnZV9zIjoyMTYwMCwibWluX3RpZXIiOiJjb25maWd1cmVkIiwic2VsZWN0ZWQiOnsidG8iOjN9LCJ0aWVyIjoiY29uZmlndXJlZCIsInZhbGlkX3VudGlsIjoiMjAyNi0xMi0wMVQxNDo1MDowMFoiLCJ2ZXJkaWN0IjoiSE9MRFMifV0sInNjb3BlIjp7ImRpZ2VzdCI6InNoYTI1NjpiZTNmZTUyOGVmMmI2M2ZiYjU3MmM5YmY0NzkxOGVmNmVhY2I0NWQ3MjMzMjMxNTgxZmJiMDZjMTkzMDQ0YjdjIiwiZW50cmllcyI6MSwicHJpdmF0ZSI6MCwidW5wcm92ZW4iOjB9LCJzZXEiOjEsInNuYXBzaG90Ijp7ImF0IjoiMjAyNi0xMi0wMVQwODo1NzoxMloiLCJncmFwaCI6eyJyb290Ijoic2hhMjU2OjdiNTE2NTYyN2YxNTk1MTZjNWU2ZjQwZjQ4NzVjMjM4ZmUyZDYwN2Q4MTZiZTI0ZDMyMGE5YWQ1ZGE5NTgwZTciLCJzaXplIjozfX0sInZhbGlkX3VudGlsIjoiMjAyNi0xMi0wMlQwOTowMDowMFoifSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vcGFkZG9jay5kZXYvYXR0ZXN0YXRpb24vY29udGFpbm1lbnQvdjEiLCJzdWJqZWN0IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiMmU5MzI4MWJmYTMzM2I2YWIxMzY4OWVhYjAzYzIwMjU0MDQ5MTJmOTlhZjdiNjk4ZjE5ZjZhZDY3OGViNjdlMyJ9LCJuYW1lIjoiZG5zOmV4YW1wbGUuY29tIn1dfQ==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"keyid": "2ceb61e24df5fde7c0ab24b2a2774fa4", "sig": "c5fOB7whPuYeD9wONEz/Ppl+zY5l3x5FxBz4qogxnjF8P4mg2ZzqMyunTj+XrkQF3WoGE12Ri6/6btdiBYyqBg=="}]}
```

(**3608 bytes**). `engine.version` is `0.3.0`, the engine that shipped this ruleset; a newer
engine with unchanged standard digests has the same ruleset.
