"""Cold-start heuristic prior: deterministic, bounded, monotonic, explainable."""
from __future__ import annotations

from app import features as F
from app.risk_model import PRIOR_WEIGHTS, RiskRanker


def _prior_ranker() -> RiskRanker:
    r = RiskRanker(min_labels=12)
    res = r.train([])  # no labels -> prior
    assert res.cold_start is True
    assert res.algo == "heuristic_prior"
    return r


def _score(ranker: RiskRanker, raw: dict) -> float:
    return ranker.score_rows([{**raw, "finding_id": "x"}])[0]["ml_risk"]


def test_prior_weights_sum_to_one() -> None:
    assert abs(sum(PRIOR_WEIGHTS.values()) - 1.0) < 1e-9


def test_prior_is_cold_start_without_labels() -> None:
    r = RiskRanker()
    res = r.train([])
    assert res.cold_start is True
    assert res.feature_importance == PRIOR_WEIGHTS


def test_prior_deterministic() -> None:
    r = _prior_ranker()
    raw = {"severity": "high", "kev": True, "reachability": "reachable"}
    assert _score(r, raw) == _score(r, raw)


def test_prior_bounds_zero_and_hundred() -> None:
    r = _prior_ranker()
    assert _score(r, {}) == 0.0
    full = {
        "severity": "critical", "kev": True, "reachability": "reachable",
        "internet_exposed": True, "on_attack_path": True, "blast_score": 100,
    }
    assert _score(r, full) == 100.0


def test_prior_monotonic_in_kev() -> None:
    r = _prior_ranker()
    base = {"severity": "medium"}
    assert _score(r, {**base, "kev": True}) > _score(r, {**base, "kev": False})


def test_prior_monotonic_in_reachability() -> None:
    r = _prior_ranker()
    s0 = _score(r, {"reachability": "unreachable"})
    s1 = _score(r, {"reachability": "potential"})
    s2 = _score(r, {"reachability": "reachable"})
    assert s0 < s1 < s2


def test_prior_monotonic_in_exposure() -> None:
    r = _prior_ranker()
    assert _score(r, {"internet_exposed": True}) > _score(r, {"internet_exposed": False})


def test_prior_rationale_top_signals() -> None:
    r = _prior_ranker()
    out = r.score_rows([{
        "finding_id": "f1", "severity": "critical", "kev": True,
        "reachability": "reachable", "internet_exposed": True,
    }])[0]
    rationale = out["rationale"]
    assert 0 < len(rationale) <= r.top_k
    # sorted by |contribution| desc; kev (0.22) should lead when present
    assert rationale[0]["feature"] == "kev"
    assert rationale[0]["contribution"] > 0
    for item in rationale:
        assert set(item) == {"feature", "contribution", "value"}


def test_prior_score_shape() -> None:
    r = _prior_ranker()
    out = r.score_rows([{"finding_id": "f1", "severity": "low"}])[0]
    assert set(out) == {"finding_id", "ml_risk", "features", "rationale"}
    assert set(out["features"]) == set(F.FEATURE_NAMES)
