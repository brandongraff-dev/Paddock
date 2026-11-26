<!-- SPDX-License-Identifier: Apache-2.0 -->
# 08. Acceptance policy

An attestation lists what an issuer chose to disclose. **What a consumer requires of it is the consumer's decision.**
The acceptance policy is the product for insurers and procurement teams. The normative form is JSON
(`schema/acceptance-policy.schema.json`); a strict YAML subset is accepted as sugar.

```json
{"policy_version":1,
 "require":[{"invariant":"std:no-internet-to-datastore","verdict":"HOLDS","min_tier":"observed","min_coverage":"0.95","max_age":"24h","digest":"sha256:.."}],
 "max_age":"48h","min_coverage":"0.95","disclosure":"any","violations":"reject","max_exceptions":null,"max_stop_at_share":null,
 "trust":{"vendor_cert":"required","dns_binding":"required","dnssec":"off","revocation":"required","revocation_max_age":"72h"},
 "history":"if_available","std_registry":"strict","engine_advisories":"reject","anchor":"off","require_latest":false}
```

The values shown are the **baseline profile**, used when no `--policy` is given: authentic, chained to a pinned
root, bound by DNS (for `dns:` subjects), not revoked, current, `max_age` 48 hours, every disclosed HOLDS at least
95 percent covered, no disclosed violation, std digests pinned, and **nothing required of the content** (`require`
is empty and `disclosure` is `any`). The first output line then says
`profile: baseline (no acceptance policy given; nothing requires specific invariants)` and the JSON has
`"profile":"baseline"`; exit 0 then means only "authentic, current, honestly typed, nothing disclosed is violated".

## 1. Fields

| Field | Meaning |
|---|---|
| `require[]` | Entries with `invariant` (INV), `verdict` (only `HOLDS` is allowed), optional `min_tier`, `min_coverage`, `max_age` (against `snapshot.at`) and `digest` (pinned). A missing, VIOLATED, UNKNOWN or EXPIRED required invariant rejects. |
| `max_age` | Maximum age of `issued_at` and `snapshot.at`. |
| `min_coverage` | Threshold applied to every disclosed HOLDS, by integer cross-multiplication. |
| `disclosure` | `any` (default) or `complete`: `complete` requires `verdicts = all` and `disclosed == enabled_std + enabled_custom` (`policy.disclosure_incomplete`). The baseline never rejects partial disclosure by itself but always prints the counts and the missing std ids. |
| `violations` | `reject` (default) or `warn`. |
| `max_exceptions`, `max_stop_at_share` | Optional limits on declared exceptions and on the boundary share. `null` means no limit. |
| `trust` | `vendor_cert` `required`/`optional`; `dns_binding` `required`/`optional`; `dnssec` `off`/`required`; `revocation` `required`/`best_effort`; `revocation_max_age` (default 72h, never above the staleness rule). |
| `history` | `required`, `if_available` (default) or `off`. |
| `std_registry` | `strict` (default): an unknown ruleset or digest is not accepted; `warn`. |
| `engine_advisories` | `reject` (default) or `warn`. |
| `anchor` | `off` (default), `optional` or `required` (an absent `audit_anchor` field is then `anchor.unavailable` as a reject). |
| `require_latest` | `true` rejects when a newer statement exists (`chain.not_latest`). |
| `name` | Optional token naming the policy in the headline (default: the file name). |

Thresholds are parsed with an exact decimal of at most four places between 0 and 1 and converted to basis points
(`0.95` is 9500); anything else is `config.policy_invalid`. Durations are `<integer>(s|m|h|d)`. Command-line
overrides: `--max-age`, `--min-coverage`, `--require ID[:tier]`. The report prints `policy_sha256`: the SHA-256 of
the PCJ of the parsed policy (with decimals as strings).

## 2. The YAML subset ("PPY")

About 200 lines of parser, no external YAML library. Accepted:

* comments (`#` at the start of a line or after at least one space), blank lines, LF line endings, a file of at most
  64 KiB, ASCII only, nesting depth at most 6, indentation of exactly two spaces per level (a tab is an error);
* block mappings and block sequences; sequence items that are scalars, flow mappings
  (`- { invariant: std:x, verdict: HOLDS }`), flow sequences (`[a, b]`) or block mappings;
* flow mappings only as sequence items, with scalar values; flow sequences with scalar items (or as an item of a
  block sequence);
* double-quoted strings with only the escapes `\"` and `\\`;
* integers `0|[1-9][0-9]*`, decimals `[0-9]+\.[0-9]+` (kept as exact decimals), `true` and `false` in lowercase;
* bare strings matching `[A-Za-z0-9_.:/%+-]+` that are not one of the above (so `48h`, `std:x`, `sha256:ab12`,
  `95%`, `a/b.c+d_e-f` are strings; a bare scalar made of digits and colons is a string, not a number).

Rejected with `config.policy_invalid` and a line number: anchors and aliases, tags, block scalars (`|` and `>`),
multi-document markers (`---`, `...`), merge keys, the scalars `yes`, `no`, `on`, `off`, `~`, `null` in any
capitalisation (write `"off"` quoted where the string `off` is meant), duplicate keys (also nested and inside flow
mappings), depth over 6, a file over 64 KiB, non-ASCII, tabs, carriage returns, single-quoted strings, bare strings
with spaces or commas, a mapping value that is a flow mapping, a nested flow collection, a top-level sequence or
scalar, quoted keys, complex keys, and a null value (omit the key instead).

`vectors/primitives/policy-parse.json` pins the accept and reject table; CI compares the accepted cases with a full
YAML library's `safe_load` (development only). The MVP document's example parses unchanged:

```yaml
require:
  - { invariant: std:no-internet-to-datastore, verdict: HOLDS, min_tier: observed }
  - { invariant: std:server-ssh-hardened,       verdict: HOLDS }
max_age: 48h
min_coverage: 0.95
```
