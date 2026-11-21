"""Anomaly detector over the attack surface — statistical outliers the rules
don't encode.

Two kinds, both learned from the platform's OWN surface:

  * SUBJECT anomalies (host / asset): a feature vector per subject
    (open_port_count, tech_count, finding severity counts, blast, recent change
    count). IsolationForest (contamination configurable) when scikit-learn is
    present; a robust z-score / MAD fallback otherwise.

  * CHANGE-VELOCITY anomalies: a subject's recent surface_changes rate compared
    to its own trailing baseline ("change velocity 5x baseline").

Every anomaly carries a HUMAN-READABLE ``reason`` naming the driving feature and
the peer median, a 0-100 ``score`` (higher = more anomalous) and a severity.

scikit-learn is reached only through ``_load_iforest()`` (guarded, patchable) so
the z-score fallback keeps working without it.
"""
from __future__ import annotations

import logging
from typing import Any

import numpy as np

log = logging.getLogger("mlrisk.anomaly")

# Subject feature order (host / asset). Documented + stable.
SUBJECT_FEATURES: list[str] = [
    "open_port_count",
    "tech_count",
    "crit_high_count",
    "finding_count",
    "blast_score",
    "recent_change_count",
]

# Human-readable templates, keyed by feature, filled with (value, peer median).
_REASON_TEMPLATES: dict[str, str] = {
    "open_port_count": "host exposes {v:g} ports; peer median {m:g}",
    "tech_count": "runs {v:g} technologies; peer median {m:g}",
    "crit_high_count": "has {v:g} high/critical findings; peer median {m:g}",
    "finding_count": "has {v:g} findings; peer median {m:g}",
    "blast_score": "blast score {v:g}; peer median {m:g}",
    "recent_change_count": "{v:g} recent changes; peer median {m:g}",
}


def _load_iforest() -> Any | None:
    """Guarded, patchable import of IsolationForest. ``None`` if unavailable."""
    try:
        from sklearn.ensemble import IsolationForest
    except Exception:  # pragma: no cover - exercised via monkeypatch
        return None
    return IsolationForest


def iforest_available() -> bool:
    return _load_iforest() is not None


def _severity_for(score: float) -> str:
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    if score >= 50:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# matrix helpers (pure)
# ---------------------------------------------------------------------------
def build_subject_matrix(
    subjects: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], np.ndarray]:
    """Return the subjects unchanged + an (n, 6) float matrix in SUBJECT_FEATURES order."""
    matrix = np.zeros((len(subjects), len(SUBJECT_FEATURES)), dtype=float)
    for i, s in enumerate(subjects):
        for j, name in enumerate(SUBJECT_FEATURES):
            try:
                matrix[i, j] = float(s.get(name, 0) or 0)
            except (TypeError, ValueError):
                matrix[i, j] = 0.0
    return subjects, matrix


def zscore_mad_scores(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Robust per-row anomaly score via max feature |modified z-score| (MAD).

    Returns ``(scores_0_100, driver_feature_index)``. Robust to outliers because
    it centres on the median and scales by the MAD, not the mean/std (so one
    extreme row can't hide itself by inflating the spread).
    """
    n, d = matrix.shape
    if n == 0:
        return np.zeros(0), np.zeros(0, dtype=int)
    median = np.median(matrix, axis=0)
    abs_dev = np.abs(matrix - median)
    mad = np.median(abs_dev, axis=0)
    meanad = np.mean(abs_dev, axis=0)
    # Prefer MAD (0.6745 scales it to an approx normal std). When MAD is 0 —
    # common when most peers share a value but one is extreme — fall back to the
    # mean absolute deviation (1.2533 scales it similarly) so the outlier is
    # still caught. A genuinely constant feature stays at scale 1 with z forced
    # to 0 so it contributes no anomaly.
    scale = np.where(
        mad > 0, mad / 0.6745,
        np.where(meanad > 0, meanad * 1.2533, 1.0),
    )
    constant = (mad <= 0) & (meanad <= 0)
    z = np.abs(matrix - median) / scale
    z = np.where(constant, 0.0, z)
    driver = np.argmax(z, axis=1)
    peak = z[np.arange(n), driver]
    # Map |z| to 0-100: z=3.5 -> ~100 (a common robust-outlier threshold).
    scores = np.clip(peak / 3.5 * 100.0, 0.0, 100.0)
    return scores, driver


def _iforest_scores(matrix: np.ndarray, contamination: float) -> np.ndarray | None:
    cls = _load_iforest()
    if cls is None or matrix.shape[0] < 4:
        return None
    try:
        contamination = min(max(contamination, 1e-3), 0.5)
        model = cls(contamination=contamination, random_state=42, n_estimators=100)
        model.fit(matrix)
        # decision_function: lower = more anomalous. Normalize to 0-100.
        raw = model.decision_function(matrix)
        lo, hi = float(raw.min()), float(raw.max())
        if hi - lo < 1e-9:
            return np.zeros(matrix.shape[0])
        norm = (hi - raw) / (hi - lo)  # 0 (normal) .. 1 (anomalous)
        return np.clip(norm * 100.0, 0.0, 100.0)
    except Exception:  # pragma: no cover - defensive
        log.exception("IsolationForest failed; caller will use z-score fallback")
        return None


def _reason_for(subject: dict[str, Any], matrix: np.ndarray, idx: int, driver: int,
                median: np.ndarray) -> str:
    name = SUBJECT_FEATURES[driver]
    v = float(matrix[idx, driver])
    m = float(median[driver])
    tmpl = _REASON_TEMPLATES.get(name, "%s {v:g}; peer median {m:g}" % name)
    return tmpl.format(v=v, m=m)


# ---------------------------------------------------------------------------
# public detection
# ---------------------------------------------------------------------------
def detect_subject_anomalies(
    subjects: list[dict[str, Any]],
    contamination: float = 0.1,
    threshold: float = 60.0,
) -> list[dict[str, Any]]:
    """Flag outlier hosts/assets. ``subjects`` rows carry SUBJECT_FEATURES plus
    ``subject_type`` / ``subject_id`` / ``subject_label``.
    """
    subjects, matrix = build_subject_matrix(subjects)
    if matrix.shape[0] == 0:
        return []

    median = np.median(matrix, axis=0)
    # z-score drives the human reason either way (it names the driving feature).
    z_scores, drivers = zscore_mad_scores(matrix)
    if_scores = _iforest_scores(matrix, contamination)
    algo = "isolation_forest" if if_scores is not None else "zscore_mad"
    scores = if_scores if if_scores is not None else z_scores

    out: list[dict[str, Any]] = []
    for i, subject in enumerate(subjects):
        score = float(scores[i])
        if score < threshold:
            continue
        driver = int(drivers[i])
        reason = _reason_for(subject, matrix, i, driver, median)
        out.append({
            "subject_type": subject.get("subject_type", "host"),
            "subject_id": subject.get("subject_id"),
            "subject_label": subject.get("subject_label", "unknown"),
            "score": round(score, 2),
            "severity": _severity_for(score),
            "reason": reason,
            "features": {
                name: float(matrix[i, j]) for j, name in enumerate(SUBJECT_FEATURES)
            },
            "algo": algo,
        })
    out.sort(key=lambda a: a["score"], reverse=True)
    return out


def detect_velocity_anomalies(
    rows: list[dict[str, Any]],
    threshold_ratio: float = 3.0,
    min_recent: int = 3,
) -> list[dict[str, Any]]:
    """Change-velocity anomalies.

    Each row: {subject_id, subject_label, recent_rate, baseline_rate}
    where ``recent_rate`` is changes/day in the recent window and
    ``baseline_rate`` is the trailing per-day baseline. Flags when the recent
    rate exceeds ``threshold_ratio`` x baseline (with a small floor so a brand-
    new baseline of 0 doesn't divide by zero).
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        recent = float(row.get("recent_rate", 0) or 0)
        baseline = float(row.get("baseline_rate", 0) or 0)
        recent_count = float(row.get("recent_count", recent) or 0)
        if recent_count < min_recent:
            continue
        denom = max(baseline, 0.1)
        ratio = recent / denom
        if ratio < threshold_ratio:
            continue
        score = float(np.clip((ratio / threshold_ratio) * 60.0, 0.0, 100.0))
        reason = f"change velocity {ratio:.1f}x baseline ({recent:g}/day vs {baseline:g}/day)"
        out.append({
            "subject_type": "change_velocity",
            "subject_id": row.get("subject_id"),
            "subject_label": row.get("subject_label", "surface"),
            "score": round(score, 2),
            "severity": _severity_for(score),
            "reason": reason,
            "features": {
                "recent_rate": recent,
                "baseline_rate": baseline,
                "ratio": round(ratio, 3),
            },
            "algo": "velocity_ratio",
        })
    out.sort(key=lambda a: a["score"], reverse=True)
    return out
