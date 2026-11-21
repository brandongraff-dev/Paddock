"""Anomaly detector: z-score fallback flags obvious outliers; velocity ratio."""
from __future__ import annotations

import numpy as np

from app import anomaly as anomaly_mod


def _normal_hosts(n: int = 8) -> list[dict]:
    return [
        {"subject_type": "host", "subject_id": None, "subject_label": f"host-{i}",
         "open_port_count": 2, "tech_count": 3, "crit_high_count": 0,
         "finding_count": 2, "blast_score": 15, "recent_change_count": 1}
        for i in range(n)
    ]


def test_zscore_matrix_flags_obvious_port_outlier() -> None:
    rows = _normal_hosts(8)
    rows.append({
        "subject_type": "host", "subject_label": "noisy",
        "open_port_count": 20, "tech_count": 3, "crit_high_count": 0,
        "finding_count": 2, "blast_score": 15, "recent_change_count": 1,
    })
    _, matrix = anomaly_mod.build_subject_matrix(rows)
    scores, drivers = anomaly_mod.zscore_mad_scores(matrix)
    assert np.argmax(scores) == len(rows) - 1          # the noisy host
    assert drivers[-1] == anomaly_mod.SUBJECT_FEATURES.index("open_port_count")
    assert scores[-1] >= 60


def test_detect_subject_anomalies_reason_mentions_ports() -> None:
    rows = _normal_hosts(8)
    rows.append({
        "subject_type": "host", "subject_label": "noisy",
        "open_port_count": 20, "tech_count": 3, "crit_high_count": 0,
        "finding_count": 2, "blast_score": 15, "recent_change_count": 1,
    })
    anoms = anomaly_mod.detect_subject_anomalies(rows)
    assert anoms
    top = anoms[0]
    assert top["subject_label"] == "noisy"
    assert "port" in top["reason"].lower()
    assert "median" in top["reason"].lower()
    assert 0 <= top["score"] <= 100
    assert top["severity"] in {"info", "low", "medium", "high", "critical"}
    assert set(top["features"]) == set(anomaly_mod.SUBJECT_FEATURES)


def test_no_anomaly_when_uniform() -> None:
    anoms = anomaly_mod.detect_subject_anomalies(_normal_hosts(10))
    assert anoms == []


def test_empty_subjects_safe() -> None:
    assert anomaly_mod.detect_subject_anomalies([]) == []
    scores, drivers = anomaly_mod.zscore_mad_scores(np.zeros((0, 6)))
    assert len(scores) == 0


def test_velocity_anomaly_flags_spike() -> None:
    rows = [
        {"subject_id": None, "subject_label": "calm.example.com",
         "recent_count": 1, "recent_rate": 1.0, "baseline_rate": 1.0},
        {"subject_id": None, "subject_label": "spike.example.com",
         "recent_count": 10, "recent_rate": 10.0, "baseline_rate": 1.0},
    ]
    anoms = anomaly_mod.detect_velocity_anomalies(rows, threshold_ratio=3.0)
    assert len(anoms) == 1
    a = anoms[0]
    assert a["subject_type"] == "change_velocity"
    assert a["subject_label"] == "spike.example.com"
    assert "baseline" in a["reason"].lower()
    assert a["features"]["ratio"] >= 3.0


def test_velocity_ignores_tiny_recent_counts() -> None:
    rows = [{"subject_label": "quiet", "recent_count": 1,
             "recent_rate": 1.0, "baseline_rate": 0.0}]
    # even with a 0 baseline, a single recent change is below min_recent
    assert anomaly_mod.detect_velocity_anomalies(rows, min_recent=3) == []


def test_severity_mapping_monotonic() -> None:
    assert anomaly_mod._severity_for(90) == "high"
    assert anomaly_mod._severity_for(75) == "medium"
    assert anomaly_mod._severity_for(55) == "low"
    assert anomaly_mod._severity_for(10) == "info"
