<!-- SPDX-License-Identifier: Apache-2.0 -->
# 03. Verdicts, evidence tiers, coverage and freshness

Normative for the meaning of the fields of [02](02-statement-predicate.md) and for the per-result checks of step 8
and the acceptance checks of step 9 ([07](07-verification-procedure.md)).

## 1. Verdicts

| Verdict | Meaning to a consumer |
|---|---|
| `HOLDS` | The engine searched the evidence available to it and found **no counterexample**, under the stated tier, coverage and freshness. It is not a statement that the thing is safe. |
| `VIOLATED` | A counterexample exists. Only the count is disclosed, never a witness. |
| `UNKNOWN` | Undetermined, for the reasons listed. It is **not a pass**. |
| `EXPIRED` | Derived, never stored and never issued: a HOLDS whose `valid_until` has been reached. It says nothing about now. |

* A verifier MUST NOT turn UNKNOWN into HOLDS, and MUST NOT aggregate verdicts into a score or print a bare "pass".
* `effective_status(result, t) = "EXPIRED"` iff `verdict == HOLDS` and `t >= result.valid_until`, else the verdict.
* A statement with `t >= valid_until` is `time.expired` as a whole.
* A disclosed VIOLATED rejects by default, whether or not the consumer required that invariant
  (`invariant.unrequired_violation`); a policy may downgrade this to a warning.
* The issuer never changes the verdict class it computed: UNKNOWN is never published as HOLDS and VIOLATED is never
  downgraded. In `holds_only` mode a result that is not HOLDS is simply not disclosed, which the counts make
  visible but cannot explain.

## 2. Evidence tiers

Ordered, weakest first:

| Tier | Phrase (verifier text) | Notes |
|---|---|---|
| `declared` | statements made by the operator (not measured) | Never valid on a published HOLDS. |
| `configured` | configuration read from the systems (not tested from outside) | Agent-signed host facts are `configured` and are never lifted by signature: a signature shows who sent a fact, not that it is true. |
| `observed` | observed network traffic or an outside-in scan | |
| `tested` | a scope-approved active test | Reserved: invalid in a v1 statement (`result.tier_invalid`) until a probe-evidence profile exists. |

* `tier` of a result is the **weakest** evidence relied on. An issuer copies it from the engine and never computes
  it or takes it from `min_tier`.
* A published HOLDS needs `tier >= max(min_tier, configured)` (`result.tier_below_min`).
* `tier <= cap(assertion)`: `configured` for `host-config`, `observed` otherwise (`result.tier_above_cap`).
* The statement-level tier a verifier prints is the **minimum** over the disclosed HOLDS tiers.

## 3. Coverage

Coverage is published as integers and compared with integer arithmetic. Floats make cross-language equality, and
rounding up past a threshold, possible.

* `covered` of `universe` is the figure relevant to the verdict; `estate_covered` of `estate_universe` is
  tenant-wide; `required_bp` is the floor applied, in basis points, the floor of the engine's value times 10000, so
  a statement never claims a stricter floor than the one that was applied.
* A result is covered enough iff `universe >= 1` **and** `covered <= universe` **and**
  `covered * 10000 >= required_bp * universe`. An empty universe is never covered (`result.universe_empty`); a HOLDS
  that fails the arithmetic is `result.coverage_inconsistent`.
* The consumer threshold is a decimal with at most four places between 0 and 1, converted to basis points exactly
  (`0.95` is 9500). A consumer threshold is applied by the same cross-multiplication
  (`coverage.below_threshold`).
* The percentage a verifier **displays** is `floor(covered * 100 / universe)`, so 41 of 42 shows 97 and never 98
  or 100.
* A HOLDS needs `selected.to >= 1` (`result.selected_empty`): a rule that selects nothing is vacuous. A verifier
  warns (`result.boundary_dominant`) when `selected.stop_at * 2 > estate_universe`, because boundary labels are
  chosen by the tenant and cover most of the estate.

Coverage counts assets that **had evidence**, not the true estate. A HOLDS can coexist with blind assets, and the
engine's rule for unknown edges applies regardless of the floor (limits text, item 3).

## 4. Freshness

* `result.valid_until` (HOLDS only) is the stalest relied-on fact plus `max_age`, floored to the second, and is
  strictly after `issued_at` (`result.valid_until_invalid`).
* `statement.valid_until` is only the issuance cap: default 24 hours, never more than 7 days
  (`time.ttl_excessive`).
* `snapshot.at <= issued_at <= snapshot.at + 900` (`time.window_invalid` otherwise); a consumer `max_age` applies
  to **both** `issued_at` and `snapshot.at` (`time.too_old`); a per-invariant `max_age` applies to `snapshot.at`
  (`invariant.age_exceeded`).
* A statement issued in the future beyond the 300 second skew allowance is `time.not_yet_valid`.
* Windows are end-exclusive ([01](01-conventions.md) 2.6).

## 5. What a consumer should take from each case

| Observed | Reading |
|---|---|
| HOLDS, current | "No counterexample found for this rule, based on this evidence tier, with this coverage, until this time." |
| HOLDS past its result `valid_until` | EXPIRED: says nothing about now. |
| VIOLATED | A counterexample exists (count only). |
| UNKNOWN | Undetermined: not a pass; the reason phrases say why. |
| absent | "Not disclosed": the policy counts say how many enabled invariants are not shown as holding. They may be violated, undetermined, not yet evaluated or withheld. The issuer chooses what to disclose. |

The honest consequence of `holds_only` disclosure is that a reader cannot distinguish violated from unknown from
withheld. Only the counts and the pinned limits text say so. A consumer who needs more can require
`disclosure: complete` ([08](08-acceptance-policy.md)).
