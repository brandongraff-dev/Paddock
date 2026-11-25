"""Human-readable output. The wording is fixed on purpose: a verdict says what was *not found*,
under which coverage and evidence, never that anything is "secure"."""
from __future__ import annotations

import datetime as dt

from . import hostexpr as X
from . import hostfields as HF
from .compile import Plan, PlanKind
from .evaluate import Result, Verdict, Witness
from .graph import ReachGraph


def _t(t: dt.datetime | None) -> str:
    return "-" if t is None else t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


_DIR_WORDS = {"in": "inbound", "out": "outbound", "both": "inbound and outbound"}


def _host_witness_line(d: dict) -> str:
    """``web-1: host.sshd.maxauthtries <= 4 failed, observed 6 (configured, signed, 2026-12-01T08:30Z)``"""
    when = d.get("observed_at", "")[:16] + "Z" if d.get("observed_at") else "-"
    signed = "signed" if d.get("signed") == "true" else "UNSIGNED"
    return (f"{d.get('node', '?')}: {d.get('predicate', '?')} failed, observed {d.get('observed', '?')} "
            f"({d.get('tier', '?')}, {signed}, {when})")


def _witness_line(w: Witness) -> str:
    if not w.hops and "predicate" in w.detail:      # a failed host-config clause
        return _host_witness_line(w.detail)
    if not w.hops:    # a coverage gap: no path, just a node we cannot see into
        d = w.detail
        return f"{d.get('node', '?')}: not covered {_DIR_WORDS.get(d.get('direction', ''), '')}, " \
               f"{d.get('reason', 'unknown')}".replace(" ,", ",")
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
    covered_kind = r.assertion == "covered"
    host_kind = r.assertion == "host-config"
    if r.verdict is Verdict.VIOLATED:
        what = "uncovered node" if covered_kind else "violating host" if host_kind else "reachable target"
        head += f"  [{r.severity}] {r.violation_count} {what}{'s' if r.violation_count != 1 else ''}"
    need = f", need {r.coverage_required:.0%}" if r.coverage_required > 0 else ""
    if host_kind:
        h = r.hosts
        cov = (f"{h.get('selected', 0)} host(s): {h.get('holds', 0)} hold, {h.get('violated', 0)} "
               f"violated, {h.get('unknown', 0)} unknown ({r.relevant_ratio:.0%} decided{need})")
        lines = [head, f"  {MEANING[r.verdict]}; {cov}"
                       + (f"; evidence tier {r.evidence_tier.value}" if r.evidence_tier else "")
                       + (f"; valid until {_t(r.valid_until)}" if r.valid_until else "")]
    else:
        lines = [head, f"  {MEANING[r.verdict]}; coverage {r.relevant_covered}/{r.relevant_universe} "
                       f"relevant assets ({r.relevant_ratio:.0%}{need}; "
                       f"{r.coverage_covered}/{r.coverage_universe} known assets covered both ways)"
                       + (f"; evidence tier {r.evidence_tier.value}" if r.evidence_tier else "")
                       + (f"; valid until {_t(r.valid_until)}" if r.valid_until else "")]
    if r.reasons and r.verdict is not Verdict.HOLDS:
        lines.append(f"  reason: {', '.join(r.reasons)}")
    for w in r.witnesses:
        lines.append(f"  {'witness' if r.verdict is Verdict.VIOLATED else 'possible'}: "
                     f"{_witness_line(w)}")
    if r.violation_count > len(r.witnesses):
        more = r.violation_count - len(r.witnesses)
        lines.append(f"  ... {more} further uncovered node(s) not listed" if covered_kind else
                     f"  ... {more} further violating host(s) not listed" if host_kind else
                     f"  ... {more} further target(s) reachable, mostly through the paths above")
    rel = [b for b in r.blind_spots if b.relevant]
    if rel and not covered_kind:    # for 'covered' the witnesses already are the blind spots
        lines.append("  blind spots that matter: " + ", ".join(
            f"{b.node} ({b.collector + ': ' if b.collector else ''}{b.reason})" if b.direction == "host"
            else f"{b.node} ({b.reason}{'' if b.direction == 'both' else ', ' + b.direction})"
            for b in rel))
    other = len({b.node for b in r.blind_spots if not b.relevant})
    if other:
        lines.append(f"  other blind assets (not on any possible path): {other}")
    if r.boundaries_reached:
        lines.append("  search stopped at application boundary: " + ", ".join(r.boundaries_reached))
    for e in r.exceptions_used:
        lines.append(f"  exception used: {e['target']} until {e['expires']}: {e['reason']}")
    if r.expired_exceptions:
        lines.append(f"  {len(r.expired_exceptions)} expired exception(s) ignored")
    return "\n".join(lines)


def _render_explain_host(plan: Plan, g: ReachGraph, r: Result, now: dt.datetime) -> str:
    inv = plan.invariant
    assert plan.expr is not None
    sel = g.select(inv.subjects.to)
    s = inv.subjects.to
    sel_text = ", ".join(f"{k}={'|'.join(v)}" for k, v in
                         (("id", s.id), ("zone", s.zone), ("tag", s.tag), ("kind", s.kind),
                          ("class", s.cls)) if v) if s else "all nodes"
    fields = sorted({(lf.field, HF.REGISTRY[lf.field].collector) for lf in X.leaves(plan.expr)})
    out = [
        f"{inv.id}  ({plan.kind.value}, severity {inv.severity})",
        f"  {inv.title}",
        f"  digest   {plan.digest}",
        f"  assert   {X.to_text(plan.expr)}",
        f"  to       {sel_text}  -> {len(sel)} host(s): "
        f"{', '.join(n.id for n in sel[:6])}{' ...' if len(sel) > 6 else ''}",
        "  reads    " + ", ".join(f"{HF.REGISTRY[f].display()} ({c})" for f, c in fields),
        f"  needs    signed facts from {', '.join(plan.collectors)} that are fresher than "
        f"{inv.evidence.max_age}, tier >= {plan.min_tier.value}, with no conflict and exact "
        "(not approximate, not partial) where the field says so",
        f"  coverage >= {plan.coverage_required:.0%} of the selected hosts must hold",
        "",
        "now evaluating against the supplied graph:",
        render_result(r, now),
    ]
    return "\n".join(out)


def render_explain(plan: Plan, g: ReachGraph, r: Result, now: dt.datetime) -> str:
    if plan.kind is PlanKind.HOSTCONFIG:
        return _render_explain_host(plan, g, r, now)
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
        *([] if plan.kind is PlanKind.COVERED else [
            f"  from     {sel(inv.subjects.from_)}  -> {len(frm)} node(s): "
            f"{', '.join(n.id for n in frm[:6])}{' ...' if len(frm) > 6 else ''}"]),
        f"  to       {sel(inv.subjects.to)}  -> {len(to)} node(s): "
        f"{', '.join(n.id for n in to[:6])}{' ...' if len(to) > 6 else ''}",
        *([] if plan.kind is PlanKind.COVERED else [
            f"  via      protocols {','.join(sorted(plan.protocols))}"
            + (f", ports {inv.via.ports}" if inv.via.ports else "")
            + f", up to {plan.max_hops} hop(s)"
            + (f", not passing through {sel(inv.via.stop_at)}" if inv.via.stop_at else "")]),
        f"  evidence tier >= {plan.min_tier.value}, fresher than {inv.evidence.max_age}, "
        f"active confirmation: {inv.evidence.confirm} (not run in P0)",
        *([] if plan.kind is PlanKind.COVERED else
          [f"  coverage >= {plan.coverage_required:.0%} of known assets"]),
        f"  exceptions {len(inv.allow)} declared",
        "",
        "now evaluating against the supplied graph:",
        render_result(r, now),
    ]
    return "\n".join(out)
