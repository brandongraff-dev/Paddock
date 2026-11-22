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

    ``status`` is ``"opened"`` (no open route before, at least one after) or
    ``"closed"`` (open route before, none after). ``example_route`` is a
    single representative route for the ticket — the first in the solver's
    stable order, from the side where the route exists (``after`` for an
    opened pair, ``before`` for a closed one). It is ``None`` only in the
    degenerate case where the pair carries no concrete route.
    """

    pair: tuple[str, str]
    status: str
    example_route: Route | None = None


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

    * ``"safe"`` — no crown-jewel route opened and no live flow broken.
    * ``"opens_route_to_crown_jewel"`` — a new (entry, jewel) route appears.
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
    opened_pairs = after.open_pairs - before.open_pairs
    closed_pairs = before.open_pairs - after.open_pairs

    def _example(result, pair: tuple[str, str]) -> Route | None:
        routes = result.routes_for(pair)
        return routes[0] if routes else None

    routes_opened = sorted(
        (RouteDelta(pair, "opened", _example(after, pair)) for pair in opened_pairs),
        key=lambda d: d.pair,
    )
    routes_closed = sorted(
        (RouteDelta(pair, "closed", _example(before, pair)) for pair in closed_pairs),
        key=lambda d: d.pair,
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
            lines.append(f"  + {d.pair[0]} -> {d.pair[1]}")
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
