"""Adaptive risk ranker: train on analyst triage, score all open findings.

Two modes, chosen automatically:

  * TRAINED (``cold_start=false``) — when there are >= ``min_labels`` labeled
    samples with both classes present. Fits a GradientBoostingClassifier (or a
    LogisticRegression when the rarer class is tiny), evaluates on a holdout
    (AUC/accuracy + precision@k) and derives feature importances from the model.
    ``ml_risk = P(acted-on) * 100``.

  * HEURISTIC PRIOR (``cold_start=true``) — the cold-start path, also used when
    scikit-learn is unavailable or labels are single-class. A TRANSPARENT,
    documented weighted sum of normalized features -> 0-100. Still scores every
    open finding; the weights ARE the explanation.

Explainability (both modes): each score carries a ``rationale`` = the top-k
(feature, signed contribution) pairs. Contribution = weight (prior) or
model-importance/coefficient (trained) * the finding's normalized feature value.

Labels come from the ``ml_training_labels`` view: 1 = acted-on/resolved,
0 = dismissed, NULL = unlabeled (ignored for training).

scikit-learn is imported through ``_load_sklearn()`` ONLY — a guarded, lazily
patchable import so the service boots and the prior path works without it.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np

from . import features as features_mod

log = logging.getLogger("mlrisk.risk")


# ---------------------------------------------------------------------------
# Heuristic prior — the cold-start model. Positive weights only, so the score
# is MONOTONIC in each signal. Normalized feature maxima sum the weights to
# 1.0, i.e. the prior's ceiling is exactly 100.
# ---------------------------------------------------------------------------
PRIOR_WEIGHTS: dict[str, float] = {
    "kev": 0.22,               # known-exploited is the strongest single signal
    "reachability": 0.20,      # reachable code/vuln beats theoretical
    "severity_ordinal": 0.18,  # classic severity
    "internet_exposed": 0.15,  # internet exposure
    "on_attack_path": 0.15,    # sits on a modelled attack path
    "blast_score": 0.10,       # blast radius if it falls
}
assert abs(sum(PRIOR_WEIGHTS.values()) - 1.0) < 1e-9


def _load_sklearn() -> Any | None:
    """Guarded, patchable import of the sklearn bits we need.

    Returns a namespace-ish dict, or ``None`` if scikit-learn is unavailable.
    Tests monkeypatch this to ``lambda: None`` to exercise the degraded path.
    """
    try:
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, roc_auc_score
        from sklearn.model_selection import train_test_split
    except Exception:  # pragma: no cover - exercised via monkeypatch
        return None
    return {
        "GradientBoostingClassifier": GradientBoostingClassifier,
        "LogisticRegression": LogisticRegression,
        "roc_auc_score": roc_auc_score,
        "accuracy_score": accuracy_score,
        "train_test_split": train_test_split,
    }


def sklearn_available() -> bool:
    return _load_sklearn() is not None


@dataclass
class TrainResult:
    algo: str
    cold_start: bool
    n_samples: int
    metrics: dict[str, Any]
    feature_importance: dict[str, float]
    notes: str = ""


@dataclass
class RiskRanker:
    """Holds the fitted estimator (or prior) and scores findings."""

    min_labels: int = 12
    min_per_class: int = 5
    top_k: int = 4

    _model: Any | None = field(default=None, repr=False)
    _importance: dict[str, float] = field(default_factory=dict)
    algo: str = "heuristic_prior"
    cold_start: bool = True
    n_samples: int = 0

    # ------------------------------------------------------------------
    # training
    # ------------------------------------------------------------------
    def train(
        self,
        labeled_rows: list[dict[str, Any]],
        now: datetime | None = None,
    ) -> TrainResult:
        """Fit from labeled rows; fall back to the prior when we can't/ shouldn't."""
        X: list[list[float]] = []
        y: list[int] = []
        for row in labeled_rows:
            label = row.get("label")
            if label is None:
                continue
            X.append(features_mod.build_vector(row, now))
            y.append(int(label))
        self.n_samples = len(y)

        sk = _load_sklearn()
        classes = set(y)
        reason = None
        if sk is None:
            reason = "scikit-learn unavailable"
        elif self.n_samples < self.min_labels:
            reason = f"only {self.n_samples} labels (< MIN_LABELS={self.min_labels})"
        elif len(classes) < 2:
            reason = "labels are single-class"

        if reason is not None:
            return self._use_prior(reason)

        return self._fit(sk, np.asarray(X, dtype=float), np.asarray(y, dtype=int))

    def _use_prior(self, reason: str) -> TrainResult:
        self._model = None
        self.algo = "heuristic_prior"
        self.cold_start = True
        self._importance = dict(PRIOR_WEIGHTS)
        log.info("risk ranker: heuristic prior (%s)", reason)
        return TrainResult(
            algo=self.algo,
            cold_start=True,
            n_samples=self.n_samples,
            metrics={"mode": "heuristic_prior", "reason": reason},
            feature_importance=self._importance,
            notes=f"cold-start heuristic prior: {reason}",
        )

    def _fit(self, sk: dict[str, Any], X: np.ndarray, y: np.ndarray) -> TrainResult:
        counts = {int(c): int((y == c).sum()) for c in set(y.tolist())}
        rarer = min(counts.values())
        use_gb = rarer >= self.min_per_class and self.n_samples >= 25
        algo = "gradient_boosting" if use_gb else "logistic_regression"

        # Holdout for honest metrics when the split can keep both classes.
        Xtr, Xte, ytr, yte = X, X, y, y
        if self.n_samples >= 2 * max(2, self.min_per_class):
            try:
                Xtr, Xte, ytr, yte = sk["train_test_split"](
                    X, y, test_size=0.25, random_state=42, stratify=y
                )
            except ValueError:
                Xtr, Xte, ytr, yte = X, X, y, y

        if use_gb:
            model = sk["GradientBoostingClassifier"](random_state=42)
        else:
            model = sk["LogisticRegression"](max_iter=1000, class_weight="balanced")
        model.fit(Xtr, ytr)
        self._model = model
        self.algo = algo
        self.cold_start = False

        # Feature importance: tree importances, else |coef|.
        if hasattr(model, "feature_importances_"):
            imp = np.asarray(model.feature_importances_, dtype=float)
        else:
            coef = np.asarray(model.coef_, dtype=float).ravel()
            imp = np.abs(coef)
        total = float(imp.sum()) or 1.0
        self._importance = {
            name: round(float(v) / total, 6)
            for name, v in zip(features_mod.FEATURE_NAMES, imp)
        }

        metrics = self._holdout_metrics(sk, model, Xte, yte)
        log.info("risk ranker trained: %s n=%d metrics=%s", algo, self.n_samples, metrics)
        return TrainResult(
            algo=algo,
            cold_start=False,
            n_samples=self.n_samples,
            metrics=metrics,
            feature_importance=self._importance,
            notes=f"trained {algo}; class counts {counts}",
        )

    def _holdout_metrics(
        self, sk: dict[str, Any], model: Any, Xte: np.ndarray, yte: np.ndarray
    ) -> dict[str, Any]:
        metrics: dict[str, Any] = {"mode": "trained"}
        try:
            proba = model.predict_proba(Xte)[:, 1]
        except Exception:  # pragma: no cover - defensive
            proba = model.predict(Xte).astype(float)
        try:
            if len(set(yte.tolist())) > 1:
                metrics["auc"] = round(float(sk["roc_auc_score"](yte, proba)), 4)
        except Exception:  # pragma: no cover
            pass
        try:
            preds = (proba >= 0.5).astype(int)
            metrics["accuracy"] = round(float(sk["accuracy_score"](yte, preds)), 4)
        except Exception:  # pragma: no cover
            pass
        metrics["precision_at_k"] = self._precision_at_k(proba, yte)
        return metrics

    @staticmethod
    def _precision_at_k(proba: np.ndarray, y_true: np.ndarray, k: int | None = None) -> float:
        n = len(proba)
        if n == 0:
            return 0.0
        k = k or min(10, n)
        order = np.argsort(proba)[::-1][:k]
        top = y_true[order]
        return round(float((top == 1).sum()) / float(k), 4)

    # ------------------------------------------------------------------
    # scoring
    # ------------------------------------------------------------------
    def score_rows(
        self, rows: list[dict[str, Any]], now: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Score every row -> {finding_id, ml_risk, features, rationale}."""
        out: list[dict[str, Any]] = []
        for row in rows:
            vec = features_mod.build_vector(row, now)
            if self._model is None:
                risk, rationale = self._prior_score(vec)
            else:
                risk, rationale = self._model_score(vec)
            out.append({
                "finding_id": row.get("finding_id") or row.get("id"),
                "ml_risk": round(float(risk), 2),
                "features": dict(zip(features_mod.FEATURE_NAMES, vec)),
                "rationale": rationale[: self.top_k],
            })
        return out

    def _prior_score(self, vec: list[float]) -> tuple[float, list[dict[str, Any]]]:
        norm = dict(zip(features_mod.FEATURE_NAMES, features_mod.normalize_vector(vec)))
        raw = dict(zip(features_mod.FEATURE_NAMES, vec))
        contributions: list[dict[str, Any]] = []
        total = 0.0
        for name, weight in PRIOR_WEIGHTS.items():
            points = 100.0 * weight * norm[name]
            total += points
            if points > 0:
                contributions.append({
                    "feature": name,
                    "contribution": round(points, 2),
                    "value": round(raw[name], 4),
                })
        contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)
        return max(0.0, min(100.0, total)), contributions

    def _model_score(self, vec: list[float]) -> tuple[float, list[dict[str, Any]]]:
        arr = np.asarray([vec], dtype=float)
        try:
            proba = float(self._model.predict_proba(arr)[0, 1])
        except Exception:  # pragma: no cover - defensive
            proba = float(self._model.predict(arr)[0])
        risk = 100.0 * proba

        # Signed contribution = importance (or signed coef) * normalized value.
        norm = features_mod.normalize_vector(vec)
        signed = self._signed_weights()
        raw = dict(zip(features_mod.FEATURE_NAMES, vec))
        contributions: list[dict[str, Any]] = []
        for name, nval, w in zip(features_mod.FEATURE_NAMES, norm, signed):
            contrib = w * nval * 100.0
            if abs(contrib) < 1e-9:
                continue
            contributions.append({
                "feature": name,
                "contribution": round(contrib, 2),
                "value": round(raw[name], 4),
            })
        contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)
        return max(0.0, min(100.0, risk)), contributions

    def _signed_weights(self) -> list[float]:
        """Per-feature signed weight for the rationale.

        LogisticRegression -> signed coefficients (direction matters).
        GradientBoosting    -> non-negative importances.
        """
        model = self._model
        if model is not None and hasattr(model, "coef_"):
            coef = np.asarray(model.coef_, dtype=float).ravel()
            denom = float(np.abs(coef).sum()) or 1.0
            return [float(c) / denom for c in coef]
        return [self._importance.get(name, 0.0) for name in features_mod.FEATURE_NAMES]
