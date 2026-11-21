"""Feature engineering for the risk ranker — PURE and well-tested.

This module turns a raw per-finding dict (as produced by ``db.fetch_feature_rows``)
into a fixed-length numeric vector. It has NO database or sklearn dependency so it
can be unit-tested in isolation and is deterministic.

====================================================================
FEATURE ORDER (authoritative — ``FEATURE_NAMES``)
====================================================================
 0  severity_ordinal          info=0 low=1 medium=2 high=3 critical=4
 1  cvss                       CVSS base score, 0-10 (0 if unknown)
 2  epss                       EPSS probability, 0-1 (0 if unknown)
 3  kev                        on CISA KEV? 0/1
 4  reachability               reachable=2, potential=1, else (unreachable/unknown)=0
 5  on_attack_path             finding's asset sits on an attack path? 0/1
 6  max_path_exploitability    max exploitability of those paths, 0-100 (0 if none)
 7  internet_exposed           asset internet-exposed? 0/1
 8  blast_score                blast-radius score, 0-100 (0 if unknown)
 9  prod_env                   asset in a production environment? 0/1
10  age_days                   days since finding.first_seen (>=0)
11  rs_cve_match               rule_source one-hot: cve_match
12  rs_sca                     rule_source one-hot: sca
13  rs_sast                    rule_source one-hot: sast
14  rs_exposed_file            rule_source one-hot: exposed_file
15  rs_secret_scan             rule_source one-hot: secret_scan
16  rs_nuclei                  rule_source one-hot: nuclei
17  rs_tls                     rule_source one-hot: tls_check / tls_grade
18  rs_header                  rule_source one-hot: header_check
19  is_sca                     convenience flag (== rs_sca)
20  is_sast                    convenience flag (== rs_sast)

Missing / malformed values degrade to a safe default (0 / 'unknown') — see the
coercion helpers below. ``build_vector`` never raises on a partial row.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

FEATURE_NAMES: list[str] = [
    "severity_ordinal",
    "cvss",
    "epss",
    "kev",
    "reachability",
    "on_attack_path",
    "max_path_exploitability",
    "internet_exposed",
    "blast_score",
    "prod_env",
    "age_days",
    "rs_cve_match",
    "rs_sca",
    "rs_sast",
    "rs_exposed_file",
    "rs_secret_scan",
    "rs_nuclei",
    "rs_tls",
    "rs_header",
    "is_sca",
    "is_sast",
]

N_FEATURES = len(FEATURE_NAMES)

SEVERITY_ORDINAL: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

REACHABILITY_ORDINAL: dict[str, int] = {
    "reachable": 2,
    "potential": 1,
    "unreachable": 0,
    "unknown": 0,
}

# rule_source -> one-hot feature name. Values not listed here produce an
# all-zero one-hot block (e.g. policy, chain, manual, takeover).
RULE_SOURCE_ONEHOT: dict[str, str] = {
    "cve_match": "rs_cve_match",
    "sca": "rs_sca",
    "sast": "rs_sast",
    "exposed_file": "rs_exposed_file",
    "secret_scan": "rs_secret_scan",
    "nuclei": "rs_nuclei",
    "tls_check": "rs_tls",
    "tls_grade": "rs_tls",
    "header_check": "rs_header",
}

# Per-feature normalizer to [0, 1] used by the heuristic prior and by the
# rationale (contribution = weight-or-importance * normalized_value).
_MAX = {
    "severity_ordinal": 4.0,
    "cvss": 10.0,
    "max_path_exploitability": 100.0,
    "blast_score": 100.0,
    "reachability": 2.0,
    "age_days": 365.0,
}


# ---------------------------------------------------------------------------
# coercion helpers
# ---------------------------------------------------------------------------
def _to_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default
    if out != out:  # NaN
        return default
    return out


def _to_bool01(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return 1.0 if value else 0.0
    if isinstance(value, str):
        return 1.0 if value.strip().lower() in {"1", "true", "yes", "on", "t"} else 0.0
    return 0.0


def _severity_ordinal(value: Any) -> float:
    if isinstance(value, str):
        return float(SEVERITY_ORDINAL.get(value.strip().lower(), 0))
    return 0.0


def _reachability_ordinal(value: Any) -> float:
    if isinstance(value, str):
        return float(REACHABILITY_ORDINAL.get(value.strip().lower(), 0))
    return 0.0


def _age_days(raw: dict[str, Any], now: datetime | None) -> float:
    if raw.get("age_days") is not None:
        return max(0.0, _to_float(raw.get("age_days")))
    first_seen = raw.get("first_seen")
    if first_seen is None:
        return 0.0
    now = now or datetime.now(timezone.utc)
    dt = _coerce_dt(first_seen)
    if dt is None:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (now - dt).total_seconds() / 86400.0
    return max(0.0, delta)


def _coerce_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# vector builders
# ---------------------------------------------------------------------------
def build_vector(raw: dict[str, Any], now: datetime | None = None) -> list[float]:
    """Build the fixed-length feature vector for one finding row.

    ``raw`` keys (all optional, missing -> safe default):
      severity, cvss, epss, kev, reachability, on_attack_path,
      max_path_exploitability, internet_exposed, blast_score, prod_env,
      first_seen (or age_days), rule_source
    """
    rule_source = raw.get("rule_source")
    onehot_name = RULE_SOURCE_ONEHOT.get(
        rule_source.strip().lower() if isinstance(rule_source, str) else "", ""
    )

    values: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    values["severity_ordinal"] = _severity_ordinal(raw.get("severity"))
    values["cvss"] = max(0.0, min(10.0, _to_float(raw.get("cvss"))))
    values["epss"] = max(0.0, min(1.0, _to_float(raw.get("epss"))))
    values["kev"] = _to_bool01(raw.get("kev"))
    values["reachability"] = _reachability_ordinal(raw.get("reachability"))
    values["on_attack_path"] = _to_bool01(raw.get("on_attack_path"))
    values["max_path_exploitability"] = max(
        0.0, min(100.0, _to_float(raw.get("max_path_exploitability")))
    )
    values["internet_exposed"] = _to_bool01(raw.get("internet_exposed"))
    values["blast_score"] = max(0.0, min(100.0, _to_float(raw.get("blast_score"))))
    values["prod_env"] = _to_bool01(raw.get("prod_env"))
    values["age_days"] = _age_days(raw, now)
    if onehot_name:
        values[onehot_name] = 1.0
    values["is_sca"] = 1.0 if onehot_name == "rs_sca" else 0.0
    values["is_sast"] = 1.0 if onehot_name == "rs_sast" else 0.0

    return [values[name] for name in FEATURE_NAMES]


def feature_dict(raw: dict[str, Any], now: datetime | None = None) -> dict[str, float]:
    """``build_vector`` keyed by feature name (handy for the stored features JSON)."""
    return dict(zip(FEATURE_NAMES, build_vector(raw, now)))


def normalize_vector(vector: list[float] | Any) -> list[float]:
    """Normalize a feature vector to roughly [0, 1] per feature.

    Used by the heuristic prior and the rationale so that a 'contribution' is
    weight/importance * normalized_value and signals are comparable.
    0/1 flags and one-hots pass through; bounded numerics are divided by their
    documented max and clipped.
    """
    out: list[float] = []
    for name, val in zip(FEATURE_NAMES, vector):
        v = float(val)
        cap = _MAX.get(name)
        if cap:
            v = v / cap
        out.append(max(0.0, min(1.0, v)))
    return out
