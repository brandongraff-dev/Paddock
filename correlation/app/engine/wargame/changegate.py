"""Change-impact proof — the Wargame change board's attachment.

The headline capability of ``docs/WARGAME.md`` §2.3: given a modelled
:class:`~app.engine.wargame.environment.Environment` and a
:class:`~app.engine.wargame.environment.ProposedChange`, say — *before the
change is applied* — what it would do to the crown-jewel attack surface and
to the traffic that is already flowing:

* **Routes it opens or closes** to each crown jewel, from the backward
  solver run before and after the edit.
* **Live flows it would break** (and any it would newly permit), by
  re-evaluating the affected boundaries' rule sets against observed flows.
* **Which boundaries it touches**, for the regulatory mapping (CDE, ESP,
  zone/conduit).

It is pure, deterministic, and advisory: it never applies the change to a
real network, sends a packet, or emits an exploit. :func:`apply_change`
already returns a *new* environment, so the before/after comparison mutates
nothing. Any human-facing summary is passed through :mod:`.safety` so it
can only ever read as impact, never as exploitation guidance.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import rules, safety
from .environment import Environment, ProposedChange, apply_change
from .model import Flow, Route, RuleSet


# ---------------------------------------------------------------------------
# Deltas
# ---------------------------------------------------------------------------

@dataclass
class RouteDelta:
    """One (entry, jewel) pair whose reachability changed.

    ``status`` is ``"opened"`` (the pair is more reachable after: closed ->
    open, closed -> conditional, or conditional -> open) or ``"closed"`` (open
    or conditional before, closed after). ``before`` / ``after`` give the
    pair's state on each side: ``"open"``, ``"conditional"`` (every route
    rests on runtime state the config can't prove — *possibly* open) or
    ``"closed"``. ``conditional`` is True for an opened pair whose new route is
    conditional ("opens a route, possibly"): never read as safe.
    ``example_route`` is a single representative route for the ticket — the
    first in the solver's stable order, from the side where the route exists
    (``after`` for an opened pair, ``before`` for a closed one). It is
    ``None`` only in the degenerate case where the pair carries no concrete
    route.
    """

    pair: tuple[str, str]
    status: str
    example_route: Route | None = None
    before: str = ""
    after: str = ""
    conditional: bool = False


#: Reachability rank of a pair state: a change that raises it opens a route.
_RANK = {"closed": 0, "conditional": 1, "open": 2}


def _pair_state(result, pair: tuple[str, str]) -> str:
    """``"open"`` / ``"conditional"`` / ``"closed"`` for one pair. A pair the
    solver reports as truncated is open (it never proves closure)."""
    if pair in set(result.conditional_pairs):
        return "conditional"
    if pair in set(result.open_pairs) or pair in set(
        getattr(result, "truncated_pairs", None) or ()
    ):
        return "open"
    return "closed"


@dataclass
class FlowImpact:
    """An observed flow whose verdict at a boundary flips with the change.

    ``status`` is ``"newly_denied"`` (allowed before, denied after — *what
    the change breaks*, the key output) or ``"newly_allowed"`` (denied
    before, allowed after). ``ruleset_id`` is the affected boundary the flip
    was found at.
    """

    flow: Flow
    ruleset_id: str
    status: str


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class ChangeImpact:
    """The full before/after proof for one proposed change.

    ``verdict`` is one of:

    * ``"safe"`` — no crown-jewel route opened (not even conditionally) and
      no live flow broken.
    * ``"opens_route_to_crown_jewel"`` — a new (entry, jewel) route appears,
      a closed pair becomes conditional (possibly open), or a conditional
      route becomes a definite one.
    * ``"breaks_live_flows"`` — an observed flow that was permitted is now
      denied.
    * ``"opens_and_breaks"`` — both of the above.
    """

    change_title: str
    routes_opened: list[RouteDelta] = field(default_factory=list)
    routes_closed: list[RouteDelta] = field(default_factory=list)
    newly_denied_flows: list[FlowImpact] = field(default_factory=list)
    newly_allowed_flows: list[FlowImpact] = field(default_factory=list)
    affected_boundaries: list[str] = field(default_factory=list)
    verdict: str = "safe"

    def summary(self) -> str:
        """A one-paragraph, impact-only summary for a change ticket.

        Mentions the counts that matter and is run through
        :func:`safety.safe_text`, so it can only ever describe outcomes —
        never exploitation steps. (It never contains any, but the guard is
        applied unconditionally so the contract holds for any future
        wording.)
        """
        title = self.change_title or "proposed change"
        parts = [
            f"Change impact for {title}: verdict {self.verdict}.",
            f"Crown-jewel routes opened: {len(self.routes_opened)}; "
            f"closed: {len(self.routes_closed)}.",
            f"Live flows newly denied (broken): {len(self.newly_denied_flows)}; "
            f"newly allowed: {len(self.newly_allowed_flows)}.",
        ]
        n_cond = sum(1 for d in self.routes_opened if d.conditional)
        if n_cond:
            parts.append(
                f"{n_cond} of the opened routes are conditional: they depend on "
                "runtime state the configuration can't prove, so treat them as "
                "possibly open."
            )
        if self.affected_boundaries:
            parts.append(
                "Boundaries touched: " + ", ".join(self.affected_boundaries) + "."
            )
        if self.newly_allowed_flows and self.verdict == "safe":
            parts.append(
                "No crown-jewel route opened, but the change would newly "
                "permit some observed traffic — review the newly allowed "
                "flows below."
            )
        text = " ".join(parts)
        return safety.safe_text(text, "Change impact summary withheld.")


# ---------------------------------------------------------------------------
# Flow verdict at one boundary (absent ruleset ⇒ deny)
# ---------------------------------------------------------------------------

def _flow_allowed(ruleset: RuleSet | None, flow: Flow) -> bool:
    """Whether ``ruleset`` permits ``flow``.

    A *missing* rule set denies by default: removing a firewall set drops the
    traffic it used to govern (so an allowed-before flow becomes newly
    denied), and adding one evaluates its rules from scratch. This keeps the
    before/after comparison symmetric — the side that lacks the control is
    always the conservative "deny" — rather than silently skipping the flow.
    """
    if ruleset is None:
        return False
    return rules.evaluate(
        ruleset, flow.src_ip, flow.dst_ip, flow.proto, flow.dst_port
    ).allowed


# ---------------------------------------------------------------------------
# The change gate
# ---------------------------------------------------------------------------

def evaluate_change(
    env: Environment,
    change: ProposedChange,
    *,
    flows: list[Flow] = (),
    max_hops: int = 8,
) -> ChangeImpact:
    """Compare ``env`` before and after ``change`` and report the impact.

    Runs the backward solver on both the current environment and the one
    :func:`apply_change` produces (computed once and reused), diffs the open
    (entry, jewel) pairs for route deltas, and re-evaluates each affected
    boundary against ``flows`` for the traffic the change would break or newly
    permit. Deterministic: identical inputs yield identical output.
    """
    before = env.reachability(max_hops=max_hops)
    after_env = apply_change(env, change)
    after = after_env.reachability(max_hops=max_hops)

    # -- route deltas -------------------------------------------------------
    # Diff each pair's state (closed < conditional < open), not just the open
    # sets, so a closed pair turning conditional, or a conditional route
    # turning definite, is reported as opening a route — never as "safe".
    def _example(result, pair: tuple[str, str]) -> Route | None:
        routes = result.routes_for(pair)
        if not routes:
            routes = [
                r for r in (getattr(result, "witness_routes", None) or ())
                if r.pair == pair
            ]
        return routes[0] if routes else None

    def _all_pairs(result) -> set[tuple[str, str]]:
        return (
            set(result.open_pairs)
            | set(result.closed_pairs)
            | set(result.conditional_pairs)
            | set(getattr(result, "truncated_pairs", None) or ())
        )

    routes_opened: list[RouteDelta] = []
    routes_closed: list[RouteDelta] = []
    for pair in sorted(_all_pairs(before) | _all_pairs(after)):
        was, now = _pair_state(before, pair), _pair_state(after, pair)
        if _RANK[now] > _RANK[was]:
            routes_opened.append(
                RouteDelta(
                    pair, "opened", _example(after, pair),
                    before=was, after=now, conditional=(now == "conditional"),
                )
            )
        elif now == "closed" and was != "closed":
            routes_closed.append(
                RouteDelta(pair, "closed", _example(before, pair), before=was, after=now)
            )

    # -- flow impact over the affected boundaries ---------------------------
    affected_ids = change.affected_ruleset_ids()
    newly_denied: list[FlowImpact] = []
    newly_allowed: list[FlowImpact] = []
    for flow in flows:
        for rid in affected_ids:
            was = _flow_allowed(env.rulesets.get(rid), flow)
            now = _flow_allowed(after_env.rulesets.get(rid), flow)
            if was and not now:
                newly_denied.append(FlowImpact(flow, rid, "newly_denied"))
            elif now and not was:
                newly_allowed.append(FlowImpact(flow, rid, "newly_allowed"))

    def _flow_key(fi: FlowImpact):
        return (fi.ruleset_id, fi.flow.src_ip, fi.flow.dst_ip, fi.flow.dst_port)

    newly_denied.sort(key=_flow_key)
    newly_allowed.sort(key=_flow_key)

    # -- verdict ------------------------------------------------------------
    opened = bool(routes_opened)
    broke = bool(newly_denied)
    if opened and broke:
        verdict = "opens_and_breaks"
    elif opened:
        verdict = "opens_route_to_crown_jewel"
    elif broke:
        verdict = "breaks_live_flows"
    else:
        verdict = "safe"

    return ChangeImpact(
        change_title=change.title,
        routes_opened=routes_opened,
        routes_closed=routes_closed,
        newly_denied_flows=newly_denied,
        newly_allowed_flows=newly_allowed,
        affected_boundaries=sorted(affected_ids),
        verdict=verdict,
    )


# ---------------------------------------------------------------------------
# Printable ticket attachment
# ---------------------------------------------------------------------------

def impact_table(impact: ChangeImpact) -> list[str]:
    """Render ``impact`` as printable lines for a change ticket / PR comment.

    Impact-only: pairs, counts and verdict, no exploitation detail. Every
    line is deterministic given the (already sorted) impact.
    """
    lines: list[str] = []
    title = impact.change_title or "proposed change"
    lines.append(f"Change-impact proof: {title}")
    lines.append(f"Verdict: {impact.verdict}")

    if impact.routes_opened:
        lines.append("Crown-jewel routes OPENED:")
        for d in impact.routes_opened:
            tail = ""
            if d.conditional:
                tail = "  (possibly: depends on runtime state the config can't prove)"
            elif d.before == "conditional":
                tail = "  (was conditional, now definite)"
            lines.append(f"  + {d.pair[0]} -> {d.pair[1]}{tail}")
    if impact.routes_closed:
        lines.append("Crown-jewel routes CLOSED:")
        for d in impact.routes_closed:
            lines.append(f"  - {d.pair[0]} -> {d.pair[1]}")

    if impact.newly_denied_flows:
        lines.append("Live flows the change would BREAK (newly denied):")
        for fi in impact.newly_denied_flows:
            f = fi.flow
            lines.append(
                f"  ! {f.src_ip} -> {f.dst_ip} {f.proto.value}/{f.dst_port} "
                f"at {fi.ruleset_id}"
            )
    if impact.newly_allowed_flows:
        lines.append("Flows the change would NEWLY ALLOW:")
        for fi in impact.newly_allowed_flows:
            f = fi.flow
            lines.append(
                f"  ~ {f.src_ip} -> {f.dst_ip} {f.proto.value}/{f.dst_port} "
                f"at {fi.ruleset_id}"
            )

    if impact.affected_boundaries:
        lines.append("Boundaries touched: " + ", ".join(impact.affected_boundaries))

    # Keep the whole attachment impact-only.
    safety.assert_safe_text("\n".join(lines))
    return lines
