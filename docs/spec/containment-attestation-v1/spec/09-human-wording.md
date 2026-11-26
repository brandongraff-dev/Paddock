<!-- SPDX-License-Identifier: Apache-2.0 -->
# 09. Human wording

Normative. **The verifier owns every sentence.** The statement carries enums, ids, hashes, integers and timestamps
and no free text; a verifier fills the templates below from those values only. The machine readable table is
`registry/wording-v1.json` (the verifier embeds a copy). Placeholders are filled from integers, strict timestamps,
enumerated tokens and names taken from the registry; the percentage is floored; nothing an issuer controls reaches
the output as free text.

## 1. Slot types

| Type | Accepted values |
|---|---|
| `uint` | integer 0 to 2^53 - 1 (never a boolean) |
| `time` | `YYYY-MM-DDTHH:MM:SSZ` |
| `name` | a registry name: printable ASCII, 1 to 120 characters, no quote, backtick, brace or backslash |
| `invid` | an invariant id (INV) |
| `phrase` | a phrase from the tables below or a fixed code message |
| `subject` | `dns:<domain>` or `paddock-estate:<estate id>` |
| `token` | `[A-Za-z0-9._:-]{1,64}` |
| `enum:<name>` | one of the keys of the enumeration; its phrase is substituted |

A slot value outside its type is an internal error, never printed. The custom-invariant line is the only place an
issuer-chosen id appears, in code style and next to the disclaimer; text is never generated from an id.

## 2. Templates

| Id | Template |
|---|---|
| `W-CHAIN-BROKEN` | This attestation does not link to the previous one: updates may have been withheld or replaced. |
| `W-CUSTOM-NAME` | Custom invariant `{id}` (defined by the operator; not reviewed by Paddock) |
| `W-DIGEST-CHANGED` | An invariant's definition changed since the previous attestation. |
| `W-DNS-UNBOUND` | The domain's DNS does not name the signing key: this attestation is not bound to the domain. |
| `W-ENGINE-ADVISORY` | The engine version that produced this attestation has a known defect advisory. |
| `W-EXC` | {n} declared exception(s) apply. |
| `W-EXPIRED-ATT` | EXPIRED: this attestation lapsed at {valid_until}. |
| `W-FOOTER` | A passing result means: no counterexample was found under this evidence, at this coverage, at this time. It is not a statement that the organisation is secure. |
| `W-HOLDS` | No counterexample found for "{name}", based on {tier_phrase}. {covered} of {universe} relevant assets had live evidence ({pct}%). Evidence current until {valid_until}. |
| `W-HOLDS-EXPIRED` | EXPIRED: the result for "{name}" was current until {valid_until}. It says nothing about now. |
| `W-KEY` | Signing key: {custody}; {cert}; {dns}; DNSSEC: {dnssec}. |
| `W-KEY-REVOKED` | The signing key has been revoked. |
| `W-POLICY` | {disclosed} of {enabled} enabled invariants are disclosed ({disabled} declared invariants are disabled). {k} enabled invariants are not shown as holding: they may be violated, undetermined, not yet evaluated, or not disclosed. The issuer chooses what to disclose. |
| `W-POLICY-SHRANK` | The set of declared invariants is smaller than in the previous attestation. |
| `W-ROLLBACK` | This attestation is older than one seen before: the sequence number went backwards. |
| `W-STD-MISSING` | Standard invariants enabled but not disclosed: {n}. |
| `W-STD-UNRECOGNISED` | A standard invariant's definition is not the one this verifier knows. |
| `W-SUPERSEDED` | A newer statement or a supersession notice exists for this subject: this attestation is out of date. |
| `W-UNKNOWN` | Undetermined for "{name}": {reason_phrase}. This is not a pass. |
| `W-VALID` | This attestation is correctly signed by a key bound to {subject}, was issued {issued_at} and is current until {valid_until}. It lists results of specific checks. It is not an assessment of overall security. |
| `W-VIOLATED` | A counterexample exists for "{name}" ({violations} found). |

## 3. Phrases

Tier phrases:

| Tier | Phrase |
|---|---|
| `configured` | configuration read from the systems (not tested from outside) |
| `declared` | statements made by the operator (not measured) |
| `observed` | observed network traffic or an outside-in scan |
| `tested` | a scope-approved active test |

Reason phrases (for `W-UNKNOWN`):

| Code | Phrase |
|---|---|
| `coverage_below_required` | coverage is below the floor the invariant requires |
| `empty_selector` | the invariant selects nothing |
| `evaluation_error` | the evaluation failed |
| `graph_incomplete` | the network model is incomplete |
| `host_evidence_unusable` | host evidence is missing, unsigned, partial or unusable |
| `invalid_definition` | the invariant definition is invalid |
| `other` | undetermined for a reason this verifier does not name |
| `possible_via_unknown_edges` | a path may exist through connections that are not fully known |
| `selection_too_large` | the selectors overlap too much to decide |
| `stale_or_missing_evidence` | evidence is stale or missing |
| `zone_unknown` | some assets have no known network zone |

Enumerations (for `W-KEY`):

| Enumeration | Value | Phrase |
|---|---|---|
| `cert` | `domain_only` | bound by the domain only, without a vendor certificate |
| `cert` | `vendor_certified` | vouched for by the vendor root |
| `custody` | `byok-hsm` | customer-held (HSM) |
| `custody` | `byok-kms` | customer-held (KMS) |
| `custody` | `hosted` | held by the issuer (hosted) |
| `dns` | `dns_bound` | named by the domain's DNS |
| `dns` | `dns_not_checked` | DNS binding not checked |
| `dns` | `dns_unbound` | not named by the domain's DNS |
| `dnssec` | `ad_asserted` | asserted by the resolver |
| `dnssec` | `not_asserted` | not asserted |
| `dnssec` | `unknown` | unknown |

Headlines: without a policy `VALID under baseline profile`; with a policy `ACCEPTED under policy <name>`;
otherwise `REJECTED: <primary message>` or `UNVERIFIABLE: <primary message>`, where the message is the fixed text of
the primary reason code. The first line of a baseline run is
`profile: baseline (no acceptance policy given; nothing requires specific invariants)`. Every report ends with the
`W-FOOTER` sentence and prints the pinned limits text (or a pointer to it).

## 4. The names of standard invariants

A `std:` result is named from the registry's `name`, never from the statement. The names are vetted against the
forbidden vocabulary and avoid the words "hardened" and "secure". A custom invariant is shown with `W-CUSTOM-NAME`.

## 5. Forbidden vocabulary

The verifier MUST NOT print, and the conformance runner scans every output for, these words (case-insensitive,
whole words): `secure`, `secured`, `safe`, `safely`, `protected`, `compliant`, `certified`, `guarantee`, `guaranteed`, `unhackable`, `breach-proof`, `passed`, `clean`, `proven`.

A *word* is a maximal run of letters, digits and underscores; a hyphenated compound counts when it, or any of
its hyphen-separated parts, is listed (so an id such as `acme:fully-secure` contains the word `secure`). Underscore
identifiers such as the JSON key `vendor_certified` are single words.

Before scanning, the runner removes **exactly**: the `W-FOOTER` sentence, the pinned limits text, and every invariant
id and domain taken from the input. A hostile custom id such as `acme:fully-secure` therefore cannot make an
honest verifier fail the scan, and cannot make it print the word outside code style next to the custom-invariant
disclaimer. The registry names and every template are scanned too.

## 6. The pinned limits text

`registry/limits-v1.txt` (id `paddock-limits/1`) is fixed text: ASCII, LF line endings, one final newline, 1636 bytes,
SHA-256 `330258fa3556e0417b000fa9cae4a2cd1853d4402a17762c5b030b1652d7c37f`. The statement's `limits.digest` is
`sha256:` plus that value. A verifier embeds the text of every id it knows; an unknown id is `limits.unknown` and a
digest that does not match is `limits.digest_mismatch`: both reject, because a statement that does not carry its
own limits is not an honest one.

```
1. This attestation lists, for each invariant named in it, whether a search of the evidence available to Paddock found a counterexample. HOLDS means that no counterexample was found under that evidence, that coverage and that freshness. It does not mean that the organisation, its systems or its network are secure.
2. It says nothing about invariants that are not listed. The policy counts show how many invariants are declared, enabled and disclosed; the issuer chooses which results to disclose.
3. It covers only assets for which Paddock had evidence. Assets without evidence are blind spots. Coverage figures are measured over the assets relevant to each invariant, and a result can hold while some assets are blind.
4. Evidence strength differs. "configured" means a configuration was read; it does not show that a system behaves as configured. "observed" means traffic or an outside scan was seen; not seeing something is not proof that it is absent. "tested" means an approved active test succeeded.
5. Host evidence is reported by software running on the host. A compromised host can report false data. This attestation does not detect malware, intrusions or misuse of valid credentials.
6. It is not a vulnerability assessment, a penetration test, an audit, a compliance certification or insurance, and it does not predict future conditions. It applies only to the named subject and only until the stated time.
7. The engine and its rules can contain defects. Check the published advisories for the engine version named in the attestation.
8. Identifiers in this attestation are labels chosen by the issuer, not endorsements.
```
