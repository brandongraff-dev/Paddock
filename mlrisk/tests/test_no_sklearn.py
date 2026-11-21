"""Degraded path: the service must work with scikit-learn absent.

We monkeypatch the guarded imports to simulate a build without sklearn and
assert the risk ranker falls back to the heuristic prior and the anomaly
detector falls back to the z-score path — both still producing scores.
"""
from __future__ import annotations

from app import anomaly as anomaly_mod
from app import risk_model as risk_mod
from app.risk_model import RiskRanker


def test_ranker_falls_back_to_prior_without_sklearn(monkeypatch) -> None:
    monkeypatch.setattr(risk_mod, "_load_sklearn", lambda: None)
    assert risk_mod.sklearn_available() is False

    # Plenty of well-separated labels, but no sklearn -> prior anyway.
    rows = [{"finding_id": f"a{i}", "severity": "critical", "kev": True,
             "label": 1} for i in range(20)]
    rows += [{"finding_id": f"b{i}", "severity": "low", "kev": False,
              "label": 0} for i in range(20)]
    r = RiskRanker(min_labels=12)
    res = r.train(rows)
    assert res.cold_start is True
    assert res.algo == "heuristic_prior"
    assert "scikit-learn unavailable" in res.metrics.get("reason", "")

    # And it still scores every finding.
    scored = r.score_rows([
        {"finding_id": "x", "severity": "critical", "kev": True,
         "reachability": "reachable"},
        {"finding_id": "y", "severity": "info"},
    ])
    assert len(scored) == 2
    assert scored[0]["ml_risk"] > scored[1]["ml_risk"]


def test_anomaly_falls_back_to_zscore_without_sklearn(monkeypatch) -> None:
    monkeypatch.setattr(anomaly_mod, "_load_iforest", lambda: None)
    assert anomaly_mod.iforest_available() is False

    subjects = [
        {"subject_type": "host", "subject_label": f"h{i}",
         "open_port_count": 2, "tech_count": 3, "crit_high_count": 0,
         "finding_count": 1, "blast_score": 10, "recent_change_count": 1}
        for i in range(8)
    ]
    subjects.append({
        "subject_type": "host", "subject_label": "outlier",
        "open_port_count": 25, "tech_count": 3, "crit_high_count": 0,
        "finding_count": 1, "blast_score": 10, "recent_change_count": 1,
    })
    anoms = anomaly_mod.detect_subject_anomalies(subjects)
    assert anoms
    assert anoms[0]["subject_label"] == "outlier"
    assert anoms[0]["algo"] == "zscore_mad"
