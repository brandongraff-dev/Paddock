"""Turn a rule-aware :class:`Environment` into a full assessment bundle.

This is the pure, deterministic core of ``/compute-wargame`` over the
persisted twin: given an :class:`~app.engine.wargame.environment.Environment`
(assembled from parsed config + declared topology), it runs the backward
search, the three-way boundary agreement, the minimum-cost fix set, and the
signed closed-boundary certificates, and serialises them with
:func:`store.assemble_bundle`. ``main.py`` just loads the twin, calls this,
and persists the result.

No I/O and no database: ``issued_at`` is passed in, so the same environment
always yields an equal bundle. DEFENSIVE: pure model reasoning only — nothing
here executes, probes, or emits an exploit, payload or command.

Boundary agreement is computed per (entry, jewel) PAIR from the end-to-end
search (:func:`agreement.from_reachability`): the config verdict is the
search's (open / conditional / closed), never a direct-edge lookup. The probe
source is a REAL probe result only (``probes``); with none, it is UNKNOWN, so
a config-closed pair reads ``"proved_config"`` — not ``"pass"``, which is
reserved for config and a real active probe agreeing. (An earlier version fed
the model's own reachability back in as the "probe": circular evidence.)

Certificates are built and signed **only** for a CLOSED pair whose verdict is
``"pass"`` or ``"proved_config"``. Never for an open / ``fail_open`` pair,
never for a ``conditional`` one, never for a pair the search could not finish
(``truncated_pairs``). A ``proved_config`` certificate says in a stated
assumption that it is a no-packet proof with no probe behind it.

Signing uses the per-tenant :class:`signing.SigningKey` the caller passes
(``main.py`` derives it from ``WARGAME_SIGNING_KEY``). With none, the public
development key is used and every certificate is labelled
``key_id="unsigned-dev"`` with an ``unsigned_dev_signature`` assumption.
"""
from __future__ import annotations

from datetime import datetime
from typing import Mapping, Optional, Sequence

from . import agreement, certificate, mincut, report, signing, store
from .environment import Environment
from .model import Assumption, Corroboration, Edge, FixCandidate, Flow

#: The PUBLIC development key (re-exported for compatibility). A fingerprint
#: made with it is not a signature; see :mod:`.signing`.
DEMO_SIGNING_KEY = signing.DEMO_SIGNING_KEY

#: Assumption key on a certificate no active probe stands behind.
PROOF_BASIS_KEY = "proof_basis"
_CONFIG_ONLY_TEXT = (
    "Proved from the configuration and the modelled topology only (no packets "
    "sent); no active probe has tested this boundary."
)
_COVERAGE_UNKNOWN_TEXT = (
    "Model coverage of observed traffic has not been measured, so a path "
    "outside the model cannot be ruled out."
)


def _gating_cost_class(env: Environment, edge: Edge) -> str:
    """The cost class a fix on ``edge`` falls into: the gating rule's
    ``cost_class`` when the edge is governed by a known rule set, else the
    default ``"network_rule"``. The gating rule is the first-evaluated one
    (lowest ``(order, id)``) for a deterministic choice."""
    if edge.rule_set_id:
        rs = env.rulesets.get(edge.rule_set_id)
        if rs is not None and rs.rules:
            gating = min(rs.rules, key=lambda r: (r.order, r.id))
            return gating.cost_class
    return "network_rule"


def _fix_candidates(env: Environment) -> dict[str, FixCandidate]:
    """One :class:`FixCandidate` per distinct ``fix_candidate_id`` carried by
    the environment's edges (two directed edges sharing a candidate id — e.g.
    an adjacency cut both ways — collapse to one). Priced from the gating
    rule's cost class via :func:`mincut.cost_for`."""
    cands: dict[str, FixCandidate] = {}
    for edge in env.edges:
        fcid = edge.fix_candidate_id
        if not fcid or fcid in cands:
            continue
        cost_class = _gating_cost_class(env, edge)
        cands[fcid] = FixCandidate(
            id=fcid,
            kind="edge",
            cost_class=cost_class,
            description=f"cut {edge.src}->{edge.dst}",
            cost=mincut.cost_for(cost_class),
        )
    return cands


def assess_environment(
    env: Environment,
    *,
    label: str,
    config_hashes: list[str],
    issued_at: datetime,
    coverage_pct: Optional[float] = None,
    signing_key: Optional[signing.SigningKey] = None,
    probes: Optional[Mapping[tuple[str, str], bool]] = None,
    observed_flows: Sequence[Flow] = (),
    observation_window_days: int = 0,
) -> store.AssessmentBundle:
    """Run a full Wargame assessment over ``env`` and assemble the bundle.

    ``probes`` maps an ``(entry, jewel)`` pair to a REAL safe-check probe
    result (``True`` crossed, ``False`` blocked); a pair absent from it was
    not probed. ``observed_flows`` are real observed flows over
    ``observation_window_days`` (0 = none looked at). ``signing_key`` is the
    tenant's key; ``None`` falls back to the labelled development key.

    Deterministic and pure (see the module docstring). Pairs, reports and
    certificates are all produced in sorted order.
    """
    rr = env.reachability()
    probes = dict(probes or {})
    flows = list(observed_flows)
    if signing_key is None:
        signing_key = signing.Keyring().signing_key(None)

    open_pairs = set(rr.open_pairs)
    closed_pairs = set(rr.closed_pairs)
    conditional_pairs = set(rr.conditional_pairs)
    truncated_pairs = set(getattr(rr, "truncated_pairs", None) or ())

    # Pair-level agreement: config verdict from the search, probe only from a
    # real probe result, observation from real flows.
    reports = []
    reports_by_pair: dict[tuple[str, str], agreement.AgreementReport] = {}
    for pair in sorted(open_pairs | closed_pairs | truncated_pairs):
        entry, jewel = pair
        ag = agreement.from_reachability(
            rr, entry, jewel, env=env, probe=probes.get(pair), observed_flows=flows
        )
        reports.append(ag)
        reports_by_pair[pair] = ag

    # Certificates: only a pair the search proved closed (not open, not
    # conditional, not truncated) whose verdict is pass / proved_config.
    certificates_out = []
    certifiable = closed_pairs - open_pairs - conditional_pairs - truncated_pairs
    for pair in sorted(certifiable):
        ag = reports_by_pair[pair]
        if ag.verdict not in agreement.CERTIFIABLE_VERDICTS:
            continue
        entry, jewel = pair
        probed = ag.verdict == "pass"
        assumptions = [
            Assumption(
                "no_unmodelled_links",
                "No links outside the modelled topology.",
            )
        ]
        if not probed:
            assumptions.append(Assumption(PROOF_BASIS_KEY, _CONFIG_ONLY_TEXT))
        if coverage_pct is None:
            assumptions.append(Assumption("coverage", _COVERAGE_UNKNOWN_TEXT))
        cert = certificate.build_certificate(
            boundary_src=entry,
            boundary_dst=jewel,
            port=None,
            config_hashes=tuple(config_hashes),
            assumptions=assumptions,
            corroboration=Corroboration(
                observed_flows=0,
                window_days=max(0, int(observation_window_days)) if flows else 0,
                sensor_on_protected_side=False,
                probe_tested=probed,
            ),
            issued_at=issued_at,
            ttl_hours=24,
        )
        certificate.sign_with(cert, signing_key)
        certificates_out.append(cert)

    candidates = _fix_candidates(env)
    # Verified, not just solved: the fix set is applied to the model and the
    # search re-run until nothing it targeted is still open (lazy constraint
    # generation), so "cuts every route" holds for routes the enumeration
    # caps never listed, too.
    fs = mincut.verified_fix_set(
        env.nodes, env.edges, env.rulesets, candidates, result=rr
    )

    scorecard = report.build_scorecard(
        rr, agreement_reports=reports, coverage_pct=coverage_pct
    )

    return store.assemble_bundle(
        reachability=rr,
        scorecard=scorecard,
        agreement_reports=reports,
        certificates=certificates_out,
        fix_set=fs,
        fix_candidates=candidates,
        evidence_packs=(),
        label=label,
        metadata={
            "signing": "unsigned-dev" if signing_key.unsigned else "signed",
            "key_id": signing_key.kid,
            "probed_pairs": len(probes),
            "observed_flows": len(flows),
            "fix_set_verified": bool(fs.verified),
            "fix_set_solver": fs.solver,
            "fix_set_uncut_pairs": [list(p) for p in sorted(fs.uncut_pairs)],
            "fix_set_uncuttable_pairs": [list(p) for p in sorted(fs.uncuttable_pairs)],
        },
    )


def assess_unproven_environment(
    env: Environment,
    *,
    label: str = "auto",
) -> store.AssessmentBundle:
    """Assess a model that carries NO rule data (the legacy asset graph via
    ``graph_adapter``: every hop INFERRED).

    Such a model can show a route exists (inferred), but finding no route in
    it proves nothing: the graph simply may not contain the link. So no pair
    is counted closed (they are ``unproven_pairs``; closure is 0% and the
    board line says closure is unproven), no boundary verdict is issued, and
    no certificate is ever produced. Coverage is unmeasured.
    """
    rr = env.reachability()
    sc = report.build_scorecard(rr, coverage_pct=None, closure_proven=False)
    return store.assemble_bundle(
        reachability=rr,
        scorecard=sc,
        label=label,
        metadata={
            "closure_basis": "none: inferred graph without rule data",
            "unproven_pairs": sc.closure.unproven_pairs,
        },
    )
