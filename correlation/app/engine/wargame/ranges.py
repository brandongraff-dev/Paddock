"""Twin-range evaluation harness for the Wargame engine.

This is the credibility keystone of ``docs/WARGAME.md`` §3 ("Measured
accuracy ... scored on seeded **twin ranges** ... The false-'closed' rate
is published per release") and §10 ("The false-'closed' rate on twin ranges
is under an agreed bound, and published").

A *twin range* is a synthetic environment whose answer we KNOW because we
built the topology and rules by hand: for every ``(entry, jewel)`` pair we
declare whether it is *truly open* (a route really exists in the model) or
*truly closed* (no route does). We then run the real backward-reachability
engine over that environment and compare its verdict to the hand truth.

The headline number is the **false-"closed" rate**: the fraction of pairs
the engine reports *closed* that are in fact open. A closure certificate
that says "closed" when the boundary is open is the one failure the whole
product cannot afford (``docs/WARGAME.md`` §3: "Nobody should trust a
certificate until that number exists"; "a certificate must never say closed
when open"). It must be 0 on the library.

DEFENSIVE. Everything here is a pure synthetic model: nodes, edges and
vendor-neutral rules. Nothing is exploited, probed or executed. All prose
that reaches a report goes through :func:`app.engine.wargame.safety.safe_text`.

Determinism. :func:`library` rebuilds the same cases every call; the engine
is deterministic; the metrics are plain counting. The same inputs always
yield an identical :class:`EvalReport`.
"""
from __future__ import annotations

from dataclasses import dataclass

from .environment import Environment
from .model import (
    Action,
    Edge,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)
from .safety import safe_text

# ---------------------------------------------------------------------------
# A range case and the scored results
# ---------------------------------------------------------------------------


@dataclass
class RangeCase:
    """One synthetic range with a hand-built ground truth.

    ``truly_open_pairs`` and ``truly_closed_pairs`` are ``(entry, jewel)``
    tuples. Their union is the *truth universe* the engine is scored on for
    this case; they must be disjoint. The truth is what we constructed by
    hand — we KNOW the answer because we built the topology and the rules.
    """

    id: str
    description: str
    environment: Environment
    truly_open_pairs: set[tuple[str, str]]
    truly_closed_pairs: set[tuple[str, str]]
    notes: str = ""

    @property
    def universe(self) -> set[tuple[str, str]]:
        return set(self.truly_open_pairs) | set(self.truly_closed_pairs)


@dataclass
class CaseResult:
    """How the engine scored on one :class:`RangeCase`.

    ``false_closed`` is the pairs the engine called *closed* that are truly
    *open* — the dangerous error. ``false_open`` is the reverse (noise, not
    a safety failure). ``correct`` is True when the engine's open/closed
    split over this case's universe matches the hand truth exactly.
    """

    case_id: str
    engine_open: set[tuple[str, str]]
    engine_closed: set[tuple[str, str]]
    false_closed: set[tuple[str, str]]
    false_open: set[tuple[str, str]]
    correct: bool


@dataclass
class EvalReport:
    """The scored library, with the published accuracy figures.

    Metric definitions (counts aggregated across every case; within a case
    the pairs are unique, and cases are kept separate so identical ids in
    two cases never collide):

    * ``false_closed_rate`` = |pairs the engine reports closed but are truly
      open| / |pairs the engine reports closed|, or ``0.0`` when the engine
      reports nothing closed. THIS IS THE HEADLINE NUMBER. A certificate
      must never say *closed* when the boundary is *open*, so this must be
      ``0.0`` on the published library.
    * ``closure_precision`` = |correctly closed| / |engine-closed|, where
      "correctly closed" is engine-closed pairs that are truly closed.
      Defined as ``1.0`` when the engine reports nothing closed (it made no
      false closed claim).
    * ``closure_recall`` = |correctly closed| / |truly closed|, i.e. how
      much of the real segmentation the engine proves. Defined as ``1.0``
      when there are no truly-closed pairs to find.
    * ``false_open_rate`` = |pairs the engine reports open but are truly
      closed| / |pairs the engine reports open|, or ``0.0`` when the engine
      reports nothing open. This is over-reporting (conservative noise),
      never a safety failure.

    A pair the engine marks *conditional* is counted as NOT closed (it is
    reported open/conditional), so a conditional path can never contribute a
    "closed" claim.
    """

    total_pairs: int
    closure_precision: float
    closure_recall: float
    false_closed_rate: float
    false_open_rate: float
    cases: list[CaseResult]
    summary: str


# ---------------------------------------------------------------------------
# Tiny, explicit builders for synthetic ranges
# ---------------------------------------------------------------------------


def _entry(nid: str, cidr: str) -> Node:
    return Node(id=nid, role=NodeRole.ENTRY, cidrs=(cidr,), reason="modelled entry")


def _entry_identity(nid: str) -> Node:
    """An address-less entry (an identity / third party). Reached only over
    ungoverned edges, never over a CIDR-matched rule."""
    return Node(id=nid, role=NodeRole.ENTRY, reason="identity principal")


def _mid(nid: str, cidr: str) -> Node:
    return Node(id=nid, role=NodeRole.INTERMEDIATE, cidrs=(cidr,))


def _jewel(nid: str, cidr: str) -> Node:
    return Node(
        id=nid, role=NodeRole.CROWN_JEWEL, cidrs=(cidr,), jewel_kind="data store"
    )


def _allow(rid: str) -> RuleSet:
    """A boundary that permits everything (one allow-any rule)."""
    return RuleSet(
        id=rid,
        rules=[
            Rule(
                id=rid + ".allow",
                action=Action.ALLOW,
                order=10,
                src_cidrs=("0.0.0.0/0",),
                dst_cidrs=("0.0.0.0/0",),
            )
        ],
        default_action=Action.DENY,
    )


def _deny_over_allow(rid: str, src: str, dst: str) -> RuleSet:
    """A higher-priority deny of ``src -> dst`` sitting above an allow-any.
    First-match means the deny wins: the boundary is closed for that pair."""
    return RuleSet(
        id=rid,
        rules=[
            Rule(
                id=rid + ".deny",
                action=Action.DENY,
                order=1,
                src_cidrs=(src,),
                dst_cidrs=(dst,),
            ),
            Rule(
                id=rid + ".allow",
                action=Action.ALLOW,
                order=50,
                src_cidrs=("0.0.0.0/0",),
                dst_cidrs=("0.0.0.0/0",),
            ),
        ],
        default_action=Action.DENY,
    )


def _deny_all(rid: str) -> RuleSet:
    """A boundary with no allow rule: default-deny closes it."""
    return RuleSet(id=rid, rules=[], default_action=Action.DENY)


def _conditional_allow(rid: str) -> RuleSet:
    """The only rule is a CONDITIONAL allow (App-ID / FQDN / mesh). The
    config cannot prove this boundary either open or closed; the engine must
    label it conditional and never call it closed."""
    return RuleSet(
        id=rid,
        rules=[
            Rule(
                id=rid + ".cond",
                action=Action.ALLOW,
                order=10,
                src_cidrs=("0.0.0.0/0",),
                dst_cidrs=("0.0.0.0/0",),
                conditional=True,
            )
        ],
        default_action=Action.DENY,
    )


def _misordered_allow(rid: str, src: str, dst: str) -> RuleSet:
    """A planted misconfiguration: an allow for ``src -> dst`` placed ABOVE
    the deny that was meant to close it, so first-match opens a pair that
    ought to be closed. The engine must report it OPEN (reality, not
    intent)."""
    return RuleSet(
        id=rid,
        rules=[
            Rule(
                id=rid + ".stray_allow",
                action=Action.ALLOW,
                order=1,
                src_cidrs=(src,),
                dst_cidrs=(dst,),
            ),
            Rule(
                id=rid + ".intended_deny",
                action=Action.DENY,
                order=10,
                src_cidrs=(src,),
                dst_cidrs=(dst,),
            ),
        ],
        default_action=Action.DENY,
    )


def _env(
    nodes: list[Node], rulesets: list[RuleSet], edges: list[Edge]
) -> Environment:
    env = Environment()
    for n in nodes:
        env.add_node(n)
    for rs in rulesets:
        env.add_ruleset(rs)
    for e in edges:
        env.add_edge(e)
    return env


# Address blocks (documentation / test ranges, RFC 5737 / RFC 1918).
_WEB = PortRange.single(Proto.TCP, 443)


# ---------------------------------------------------------------------------
# The library of hand-built ranges
# ---------------------------------------------------------------------------


def library() -> list[RangeCase]:
    """At least eight hand-built twin ranges, each with ground truth.

    Every case is small enough to verify by eye; the ground truth is what we
    constructed, not what the engine said.
    """
    cases: list[RangeCase] = []

    # 1. A single open path: entry -> jewel via one allow. ------------------
    e, j = "r1.internet", "r1.db"
    cases.append(
        RangeCase(
            id="single_open",
            description="One entry reaches one jewel through a single allow rule.",
            environment=_env(
                [_entry(e, "203.0.113.0/24"), _jewel(j, "10.1.0.0/24")],
                [_allow("r1.fw")],
                [Edge(src=e, dst=j, rule_set_id="r1.fw", port=_WEB)],
            ),
            truly_open_pairs={(e, j)},
            truly_closed_pairs=set(),
            notes="Baseline open: the engine must report open.",
        )
    )

    # 2. A path closed by a higher-priority deny. ---------------------------
    e, j = "r2.internet", "r2.db"
    cases.append(
        RangeCase(
            id="deny_closes",
            description="An allow-any boundary with a higher-priority deny on the pair.",
            environment=_env(
                [_entry(e, "203.0.113.0/24"), _jewel(j, "10.2.0.0/24")],
                [_deny_over_allow("r2.fw", "203.0.113.0/24", "10.2.0.0/24")],
                [Edge(src=e, dst=j, rule_set_id="r2.fw", port=_WEB)],
            ),
            truly_open_pairs=set(),
            truly_closed_pairs={(e, j)},
            notes="First-match deny wins; ground truth closed.",
        )
    )

    # 3. A two-hop path open through an intermediate. -----------------------
    e, m, j = "r3.internet", "r3.jump", "r3.db"
    cases.append(
        RangeCase(
            id="two_hop_open",
            description="Entry -> jump host -> jewel, both hops allowed.",
            environment=_env(
                [
                    _entry(e, "203.0.113.0/24"),
                    _mid(m, "10.3.1.0/24"),
                    _jewel(j, "10.3.9.0/24"),
                ],
                [_allow("r3.fw_a"), _allow("r3.fw_b")],
                [
                    Edge(src=e, dst=m, rule_set_id="r3.fw_a", port=_WEB),
                    Edge(src=m, dst=j, rule_set_id="r3.fw_b", port=_WEB),
                ],
            ),
            truly_open_pairs={(e, j)},
            truly_closed_pairs=set(),
            notes="Transitive open through one intermediate.",
        )
    )

    # 4. The only governing rule is CONDITIONAL. ----------------------------
    #    Ground truth: NOT closed. It must read open/conditional, never
    #    closed, proving the engine never claims closed on a conditional.
    e, j = "r4.internet", "r4.db"
    cases.append(
        RangeCase(
            id="conditional_only",
            description="The sole rule on the boundary is a conditional allow (App-ID/FQDN).",
            environment=_env(
                [_entry(e, "203.0.113.0/24"), _jewel(j, "10.4.0.0/24")],
                [_conditional_allow("r4.fw")],
                [Edge(src=e, dst=j, rule_set_id="r4.fw", port=_WEB)],
            ),
            truly_open_pairs={(e, j)},
            truly_closed_pairs=set(),
            notes=(
                "Config cannot prove this closed. Truth is NOT closed: it must "
                "count as open/conditional. The engine must never call it closed."
            ),
        )
    )

    # 5. A decoy branch that dead-ends; the real path is denied. ------------
    #    The jewel pair is closed because the only route to the jewel is cut;
    #    the decoy is reachable but is not on any route to the jewel.
    e, decoy, j = "r5.internet", "r5.decoy", "r5.db"
    cases.append(
        RangeCase(
            id="decoy_deadend",
            description="A reachable decoy segment that leads nowhere; the real jewel path is denied.",
            environment=_env(
                [
                    _entry(e, "203.0.113.0/24"),
                    _mid(decoy, "10.5.1.0/24"),
                    _jewel(j, "10.5.9.0/24"),
                ],
                [
                    _allow("r5.fw_decoy"),
                    _deny_over_allow("r5.fw_db", "203.0.113.0/24", "10.5.9.0/24"),
                ],
                [
                    # Reachable but dead-ends (no edge out of the decoy).
                    Edge(src=e, dst=decoy, rule_set_id="r5.fw_decoy", port=_WEB),
                    # The only edge to the jewel is denied.
                    Edge(src=e, dst=j, rule_set_id="r5.fw_db", port=_WEB),
                ],
            ),
            truly_open_pairs=set(),
            truly_closed_pairs={(e, j)},
            notes="Reaching a dead-end segment is not reaching the jewel; pair closed.",
        )
    )

    # 6. An identity / ungoverned-edge path (open) — subtly open. -----------
    #    No allow rule exists at all; a naive config-only engine that only
    #    believes an explicit allow would wrongly call this closed. The right
    #    answer is OPEN: an ungoverned adjacency (an identity assuming a role)
    #    is permitted by default.
    e, j = "r6.vendor_identity", "r6.db"
    cases.append(
        RangeCase(
            id="identity_ungoverned_open",
            description="An address-less identity reaches the jewel over an ungoverned edge (no rule).",
            environment=_env(
                [_entry_identity(e), _jewel(j, "10.6.0.0/24")],
                [],
                [
                    # rule_set_id=None -> ungoverned, permitted by default.
                    Edge(src=e, dst=j, rule_set_id=None, port=_WEB)
                ],
            ),
            truly_open_pairs={(e, j)},
            truly_closed_pairs=set(),
            notes=(
                "Subtly open: there is no allow rule, so a naive engine might call "
                "it closed. An ungoverned identity edge is open by default."
            ),
        )
    )

    # 7. A multi-hop where ONE hop is denied, so the whole route is closed. --
    e, m, j = "r7.internet", "r7.jump", "r7.db"
    cases.append(
        RangeCase(
            id="broken_middle_hop",
            description="Entry -> jump allowed, but jump -> jewel is denied, so the route is cut.",
            environment=_env(
                [
                    _entry(e, "203.0.113.0/24"),
                    _mid(m, "10.7.1.0/24"),
                    _jewel(j, "10.7.9.0/24"),
                ],
                [_allow("r7.fw_a"), _deny_all("r7.fw_b")],
                [
                    Edge(src=e, dst=m, rule_set_id="r7.fw_a", port=_WEB),
                    Edge(src=m, dst=j, rule_set_id="r7.fw_b", port=_WEB),
                ],
            ),
            truly_open_pairs=set(),
            truly_closed_pairs={(e, j)},
            notes="One denied hop breaks the only route; pair closed.",
        )
    )

    # 8. A planted misconfig: a stray allow opens a pair that ought to be
    #    closed. Ground truth is OPEN (config reality), and the engine must
    #    catch it rather than trusting the intended deny.
    e, j = "r8.internet", "r8.db"
    cases.append(
        RangeCase(
            id="planted_misconfig_open",
            description="A stray allow placed above the intended deny opens a boundary meant to be closed.",
            environment=_env(
                [_entry(e, "203.0.113.0/24"), _jewel(j, "10.8.0.0/24")],
                [_misordered_allow("r8.fw", "203.0.113.0/24", "10.8.0.0/24")],
                [Edge(src=e, dst=j, rule_set_id="r8.fw", port=_WEB)],
            ),
            truly_open_pairs={(e, j)},
            truly_closed_pairs=set(),
            notes=(
                "Intent was closed; the config is open because of a misordered "
                "allow. Truth is OPEN — the engine must report what the config does."
            ),
        )
    )

    # 9. Multiple entries and multiple jewels: a mixed open/closed matrix. ---
    e1, e2 = "r9.internet", "r9.partner_vpn"
    j1, j2 = "r9.cardholder_db", "r9.ehr"
    cases.append(
        RangeCase(
            id="multi_entry_multi_jewel",
            description="Two entries, two jewels: two pairs open, two closed (one by deny, one by no adjacency).",
            environment=_env(
                [
                    _entry(e1, "203.0.113.0/24"),
                    _entry(e2, "198.51.100.0/24"),
                    _jewel(j1, "10.90.10.0/24"),
                    _jewel(j2, "10.90.20.0/24"),
                ],
                [
                    _allow("r9.fw_e1_j1"),
                    _deny_over_allow("r9.fw_e1_j2", "203.0.113.0/24", "10.90.20.0/24"),
                    _allow("r9.fw_e2_j2"),
                ],
                [
                    Edge(src=e1, dst=j1, rule_set_id="r9.fw_e1_j1", port=_WEB),
                    Edge(src=e1, dst=j2, rule_set_id="r9.fw_e1_j2", port=_WEB),
                    Edge(src=e2, dst=j2, rule_set_id="r9.fw_e2_j2", port=_WEB),
                    # (e2 -> j1): no edge at all -> no adjacency -> closed.
                ],
            ),
            truly_open_pairs={(e1, j1), (e2, j2)},
            truly_closed_pairs={(e1, j2), (e2, j1)},
            notes="Open by allow, closed by deny, and closed by absent adjacency, in one model.",
        )
    )

    return cases


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _score_case(case: RangeCase) -> CaseResult:
    result = case.environment.reachability()
    universe = case.universe

    # A conditional pair is reported open/conditional, so fold conditional
    # pairs into the "not closed" set explicitly (they are already a subset
    # of open_pairs, but be defensive so a conditional path can never be
    # counted as closed).
    engine_open_all = set(result.open_pairs) | set(result.conditional_pairs)
    engine_open = engine_open_all & universe
    engine_closed = universe - engine_open

    false_closed = engine_closed & set(case.truly_open_pairs)
    false_open = engine_open & set(case.truly_closed_pairs)
    correct = not false_closed and not false_open

    return CaseResult(
        case_id=case.id,
        engine_open=engine_open,
        engine_closed=engine_closed,
        false_closed=false_closed,
        false_open=false_open,
        correct=correct,
    )


def score(cases: list[RangeCase]) -> EvalReport:
    """Run the real engine over each case and compute the published metrics.

    Deterministic: the engine is deterministic and the aggregation is plain
    counting over cases taken in order. Counts are summed per case (never
    unioned across cases) so identical ``(entry, jewel)`` ids in two
    different cases are never confused for one pair.
    """
    results = [_score_case(c) for c in cases]

    total_pairs = sum(len(c.universe) for c in cases)
    n_engine_closed = sum(len(r.engine_closed) for r in results)
    n_engine_open = sum(len(r.engine_open) for r in results)
    n_false_closed = sum(len(r.false_closed) for r in results)
    n_false_open = sum(len(r.false_open) for r in results)
    n_truly_closed = sum(len(c.truly_closed_pairs) for c in cases)

    # Correctly-closed = engine-closed pairs that really are closed.
    n_correct_closed = n_engine_closed - n_false_closed

    false_closed_rate = (
        n_false_closed / n_engine_closed if n_engine_closed else 0.0
    )
    false_open_rate = n_false_open / n_engine_open if n_engine_open else 0.0
    closure_precision = (
        n_correct_closed / n_engine_closed if n_engine_closed else 1.0
    )
    closure_recall = (
        n_correct_closed / n_truly_closed if n_truly_closed else 1.0
    )

    n_cases = len(results)
    n_correct_cases = sum(1 for r in results if r.correct)
    raw_summary = (
        f"Twin-range library: {n_cases} cases, {total_pairs} scored pairs; "
        f"{n_correct_cases}/{n_cases} cases match ground truth. "
        f"false-closed rate {false_closed_rate:.4f} "
        f"(the headline: the engine never says closed when open), "
        f"false-open rate {false_open_rate:.4f}, "
        f"closure precision {closure_precision:.4f}, "
        f"closure recall {closure_recall:.4f}."
    )
    summary = safe_text(raw_summary, "twin-range accuracy report")

    return EvalReport(
        total_pairs=total_pairs,
        closure_precision=closure_precision,
        closure_recall=closure_recall,
        false_closed_rate=false_closed_rate,
        false_open_rate=false_open_rate,
        cases=results,
        summary=summary,
    )


def run_library() -> EvalReport:
    """Score the built-in library — the published twin-range accuracy run."""
    return score(library())
