"""Human-readable output. The wording is fixed on purpose: a verdict says what was *not found*,
under which coverage and evidence, never that anything is "secure"."""
from __future__ import annotations

import datetime as dt

from .compile import Plan
from .evaluate import Result, Verdict, Witness
from .graph import ReachGraph


def _t(t: dt.datetime | None) -> str:
    return "-" if t is None else t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def _witness_line(w: Witness) -> str:
    parts = [w.hops[0].src]
    for h in w.hops:
        label = "?" if h.proto == "unknown" else f"{h.proto}/{h.ports or '*'} {h.basis}"
        parts.append(f"-[{label}]-> {h.dst}")
    flag = "confirmed" if w.confirmed else "unconfirmed"
    extra = ""
    if w.detail.get("disallowed_ports"):
        extra = f"  not allowed: {w.detail['disallowed_ports']}"
    return f"{' '.join(parts)}  ({len(w.hops)} hop{'s' if len(w.hops) != 1 else ''}, " \
           f"weakest {w.weakest_basis}, {flag}){extra}"


MEANING = {
    Verdict.HOLDS: "no counterexample found",
    Verdict.VIOLATED: "counterexample found",
    Verdict.UNKNOWN: "cannot be decided from the evidence",
}


def render_result(r: Result, now: dt.datetime) -> str:
    status = r.status_at(now)
    head = f"{status:<9} {r.invariant_id}"
    if r.verdict is Verdict.VIOLATED:
        head += f"  [{r.severity}] {r.violation_count} reachable target" \
                f"{'s' if r.violation_count != 1 else ''}"
    lines = [head, f"  {MEANING[r.verdict]}; coverage {r.coverage_covered}/{r.coverage_universe} "
                   f"known assets ({r.coverage_ratio:.0%}, need {r.coverage_required:.0%})"
                   + (f"; evidence tier {r.evidence_tier.value}" if r.evidence_tier else "")
                   + (f"; valid until {_t(r.valid_until)}" if r.valid_until else "")]
    if r.reasons and r.verdict is not Verdict.HOLDS:
        lines.append(f"  reason: {', '.join(r.reasons)}")
    for w in r.witnesses:
        lines.append(f"  {'witness' if r.verdict is Verdict.VIOLATED else 'possible'}: "
                     f"{_witness_line(w)}")
    if r.violation_count > len(r.witnesses):
        lines.append(f"  ... {r.violation_count - len(r.witnesses)} further target(s) reachable, mostly through the paths above")
    rel = [b for b in r.blind_spots if b.relevant]
    if rel:
        lines.append("  blind spots that matter: " + ", ".join(f"{b.node} ({b.reason})" for b in rel))
    other = len(r.blind_spots) - len(rel)
    if other:
        lines.append(f"  other blind assets (not on any possible path): {other}")
    if r.boundaries_reached:
        lines.append("  search stopped at application boundary: " + ", ".join(r.boundaries_reached))
    for e in r.exceptions_used:
        lines.append(f"  exception used: {e['target']} until {e['expires']}: {e['reason']}")
    if r.expired_exceptions:
        lines.append(f"  {len(r.expired_exceptions)} expired exception(s) ignored")
    return "\n".join(lines)


def render_explain(plan: Plan, g: ReachGraph, r: Result, now: dt.datetime) -> str:
    inv = plan.invariant
    sel = lambda s: "all nodes" if s is None else ", ".join(  # noqa: E731
        f"{k}={'|'.join(v)}" for k, v in
        (("id", s.id), ("zone", s.zone), ("tag", s.tag), ("kind", s.kind), ("class", s.cls)) if v)
    frm = g.select(inv.subjects.from_)
    to = g.select(inv.subjects.to)
    out = [
        f"{inv.id}  ({plan.kind.value}, severity {inv.severity})",
        f"  {inv.title}",
        f"  digest   {plan.digest}",
        f"  assert   {inv.assert_}"
        + (f" except ports {inv.ports}" if inv.ports else ""),
        f"  from     {sel(inv.subjects.from_)}  -> {len(frm)} node(s): "
        f"{', '.join(n.id for n in frm[:6])}{' ...' if len(frm) > 6 else ''}",
        f"  to       {sel(inv.subjects.to)}  -> {len(to)} node(s): "
        f"{', '.join(n.id for n in to[:6])}{' ...' if len(to) > 6 else ''}",
        f"  via      protocols {','.join(sorted(plan.protocols))}"
        + (f", ports {inv.via.ports}" if inv.via.ports else "")
        + f", up to {plan.max_hops} hop(s)"
        + (f", not passing through {sel(inv.via.stop_at)}" if inv.via.stop_at else ""),
        f"  evidence tier >= {plan.min_tier.value}, fresher than {inv.evidence.max_age}, "
        f"active confirmation: {inv.evidence.confirm} (not run in P0)",
        f"  coverage >= {plan.coverage_required:.0%} of known assets",
        f"  exceptions {len(inv.allow)} declared",
        "",
        "now evaluating against the supplied graph:",
        render_result(r, now),
    ]
    return "\n".join(out)
