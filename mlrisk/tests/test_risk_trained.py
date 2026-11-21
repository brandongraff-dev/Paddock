"""Trained risk ranker on a synthetic labeled set (scikit-learn present)."""
from __future__ import annotations

import pytest

from app.risk_model import RiskRanker, sklearn_available

pytestmark = pytest.mark.skipif(
    not sklearn_available(), reason="scikit-learn not installed"
)


def _synthetic_labeled(n: int = 40) -> list[dict]:
    """Half acted-on (real, high-signal), half dismissed (noise, low-signal)."""
    rows: list[dict] = []
    for i in range(n // 2):
        rows.append({
            "finding_id": f"hot-{i}",
            "severity": "critical" if i % 2 == 0 else "high",
            "cvss": 9.0, "epss": 0.6, "kev": True,
            "reachability": "reachable", "on_attack_path": True,
            "max_path_exploitability": 80, "internet_exposed": True,
            "blast_score": 75, "prod_env": True, "age_days": 20,
            "rule_source": "cve_match", "label": 1,
        })
    for i in range(n - n // 2):
        rows.append({
            "finding_id": f"cold-{i}",
            "severity": "low" if i % 2 == 0 else "info",
            "cvss": 2.0, "epss": 0.01, "kev": False,
            "reachability": "unreachable", "on_attack_path": False,
            "max_path_exploitability": 0, "internet_exposed": False,
            "blast_score": 5, "prod_env": False, "age_days": 200,
            "rule_source": "header_check", "label": 0,
        })
    return rows


def test_trained_path_not_cold_start() -> None:
    r = RiskRanker(min_labels=12, min_per_class=5)
    res = r.train(_synthetic_labeled(40))
    assert res.cold_start is False
    assert res.algo in ("gradient_boosting", "logistic_regression")
    assert res.n_samples == 40
    assert "precision_at_k" in res.metrics
    assert res.feature_importance  # non-empty


def test_trained_separates_hot_from_cold() -> None:
    r = RiskRanker(min_labels=12, min_per_class=5)
    r.train(_synthetic_labeled(40))
    hot = r.score_rows([{
        "finding_id": "q1", "severity": "critical", "cvss": 9.5, "epss": 0.7,
        "kev": True, "reachability": "reachable", "on_attack_path": True,
        "max_path_exploitability": 90, "internet_exposed": True,
        "blast_score": 80, "prod_env": True, "rule_source": "cve_match",
    }])[0]
    cold = r.score_rows([{
        "finding_id": "q2", "severity": "info", "cvss": 1.0, "epss": 0.0,
        "kev": False, "reachability": "unreachable", "on_attack_path": False,
        "max_path_exploitability": 0, "internet_exposed": False,
        "blast_score": 0, "prod_env": False, "rule_source": "header_check",
    }])[0]
    assert 0.0 <= cold["ml_risk"] <= 100.0
    assert 0.0 <= hot["ml_risk"] <= 100.0
    assert hot["ml_risk"] > cold["ml_risk"]


def test_trained_rationale_top_k() -> None:
    r = RiskRanker(min_labels=12, min_per_class=5, top_k=3)
    r.train(_synthetic_labeled(40))
    out = r.score_rows([{
        "finding_id": "q1", "severity": "critical", "kev": True,
        "reachability": "reachable", "rule_source": "cve_match",
    }])[0]
    assert len(out["rationale"]) <= 3
    for item in out["rationale"]:
        assert set(item) == {"feature", "contribution", "value"}


def test_single_class_labels_fall_back_to_prior() -> None:
    rows = [{"finding_id": f"a{i}", "severity": "high", "label": 1}
            for i in range(30)]
    r = RiskRanker(min_labels=12)
    res = r.train(rows)
    assert res.cold_start is True
    assert res.algo == "heuristic_prior"
    assert "single-class" in res.metrics.get("reason", "")


def test_too_few_labels_uses_prior() -> None:
    rows = [{"finding_id": f"a{i}", "severity": "high",
             "label": i % 2} for i in range(6)]
    r = RiskRanker(min_labels=12)
    res = r.train(rows)
    assert res.cold_start is True
    assert res.algo == "heuristic_prior"
