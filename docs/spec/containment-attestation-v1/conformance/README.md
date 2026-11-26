<!-- SPDX-License-Identifier: Apache-2.0 -->
# Conformance runner

`run.py` is a standard-library-only program that drives any verifier implementation over the corpus in
`../vectors` and prints a matrix. See [spec/12-conformance.md](../spec/12-conformance.md) for the design.

```bash
python run.py --list                                   # the cases and their tags
python run.py --impl "paddock-verify"                  # Level A: every case through a command line
python run.py --impl "python -m myverifier" --filter dns --json
python run.py --primitives-adapter ./my_adapter.py     # Level B: the primitive vectors
```

## What Level A runs

For each `vectors/cases/<id>/case.json` the runner copies `bundle/` into a temporary directory, applies the recipes
(`pad_file`, `write_file`) and executes

```
<impl> --json --offline --now <case.now> --roots <vectors/test-roots.json>
       [--dns-resolver file:<dns-N.json>]... [--state-file <state.json> | --no-state] [--policy <policy file>]
       [--anchor-file <path>] [--std-registry <path>] <case.args...> <target>
```

* `case.dns` is a resolver fixture written to a file; `{"resolvers": [fixture, ...]}` writes one file per resolver
  so disagreement and quorum can be expressed. `case.state`, `case.policy` (a JSON object, or `{"yaml": "..."}`) are
  written to files. `case.roots` is `test` (the default), `none` (the flag is omitted) or a path in the case.
* A case must state `exit`, `decision`, `codes`, `warnings` and `primary`; a missing one, or a report that is not a
  JSON object or has malformed `reasons`/`warnings`, is a failed case.
* It compares the exit code, `decision`, the **exact ordered** list of `reasons[].code` whose class is `R` or `U`,
  the set of `warnings[].code` (or plain strings), `primary` and `profile`.
* It scans stdout and stderr for the forbidden vocabulary after removing exactly the footer sentence, the pinned
  limits text and every invariant id and domain found in the case's input (including base64 payloads).

Exit status: `0` all checks passed, `1` at least one mismatch, `2` the runner could not run.

## Level B adapter

A module (a path to a `.py` file, or an importable name) that defines any subset of:

| Function | Contract |
|---|---|
| `pae(payload_type: str, payload: bytes) -> bytes` | the DSSE encoding |
| `b64_decode(text: str) -> bytes` | strict decode; raise on anything non-canonical |
| `pcj_parse(data: bytes) -> value` | strict parse **and** canonical round trip; raise on any rejection |
| `pcj_dumps(value) -> bytes` | canonical encoding; raise when the value cannot be encoded |
| `time_parse(text: str) -> int` | strict timestamp to epoch seconds; raise otherwise |
| `merkle_root(leaf_hashes: list[bytes]) -> bytes` | root over hashes in the given order |
| `merkle_verify(leaf, index, size, path, root) -> bool` | RFC 9162 inclusion check |
| `ed25519_verify(pub: bytes, message: bytes, sig: bytes) -> bool` | with the pre-checks of spec 01 section 2.5 |

Functions that are absent are skipped. An implementation may claim conformance only against a named `spec_version`
and the `MANIFEST.json` hash the runner prints.
