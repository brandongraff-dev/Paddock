"""Feature-vector correctness + missing-value handling (pure, no DB)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import features as F


def _idx(name: str) -> int:
    return F.FEATURE_NAMES.index(name)


def test_feature_names_order_and_length() -> None:
    # The documented order must not drift.
    assert F.FEATURE_NAMES[:11] == [
        "severity_ordinal", "cvss", "epss", "kev", "reachability",
        "on_attack_path", "max_path_exploitability", "internet_exposed",
        "blast_score", "prod_env", "age_days",
    ]
    assert F.N_FEATURES == len(F.FEATURE_NAMES) == 21


def test_full_vector_values() -> None:
    now = datetime(2026, 1, 11, tzinfo=timezone.utc)
    raw = {
        "severity": "critical",
        "cvss": 9.8,
        "epss": 0.5,
        "kev": True,
        "reachability": "reachable",
        "on_attack_path": True,
        "max_path_exploitability": 80,
        "internet_exposed": True,
        "blast_score": 70,
        "prod_env": True,
        "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "rule_source": "cve_match",
    }
    vec = F.build_vector(raw, now=now)
    assert vec[_idx("severity_ordinal")] == 4
    assert vec[_idx("cvss")] == 9.8
    assert vec[_idx("epss")] == 0.5
    assert vec[_idx("kev")] == 1
    assert vec[_idx("reachability")] == 2
    assert vec[_idx("on_attack_path")] == 1
    assert vec[_idx("max_path_exploitability")] == 80
    assert vec[_idx("internet_exposed")] == 1
    assert vec[_idx("blast_score")] == 70
    assert vec[_idx("prod_env")] == 1
    assert vec[_idx("age_days")] == 10
    assert vec[_idx("rs_cve_match")] == 1
    assert vec[_idx("is_sca")] == 0
    assert vec[_idx("is_sast")] == 0


def test_missing_values_default_safely() -> None:
    vec = F.build_vector({})  # entirely empty row must not raise
    assert len(vec) == F.N_FEATURES
    assert all(v == 0.0 for v in vec)


def test_partial_and_malformed_values() -> None:
    raw = {"severity": "nonsense", "cvss": "oops", "epss": None,
           "reachability": "???", "blast_score": float("nan")}
    vec = F.build_vector(raw)
    assert vec[_idx("severity_ordinal")] == 0
    assert vec[_idx("cvss")] == 0
    assert vec[_idx("epss")] == 0
    assert vec[_idx("reachability")] == 0
    assert vec[_idx("blast_score")] == 0


def test_reachability_ordinal_levels() -> None:
    assert F.build_vector({"reachability": "reachable"})[_idx("reachability")] == 2
    assert F.build_vector({"reachability": "potential"})[_idx("reachability")] == 1
    assert F.build_vector({"reachability": "unreachable"})[_idx("reachability")] == 0
    assert F.build_vector({"reachability": "unknown"})[_idx("reachability")] == 0


def test_rule_source_onehot_exclusive() -> None:
    for src, feat in [
        ("cve_match", "rs_cve_match"), ("sca", "rs_sca"), ("sast", "rs_sast"),
        ("exposed_file", "rs_exposed_file"), ("secret_scan", "rs_secret_scan"),
        ("nuclei", "rs_nuclei"), ("tls_check", "rs_tls"), ("tls_grade", "rs_tls"),
        ("header_check", "rs_header"),
    ]:
        vec = F.build_vector({"rule_source": src})
        onehot = [vec[_idx(n)] for n in F.FEATURE_NAMES if n.startswith("rs_")]
        assert sum(onehot) == 1.0, src
        assert vec[_idx(feat)] == 1.0, src


def test_rule_source_unknown_all_zero_onehot() -> None:
    vec = F.build_vector({"rule_source": "policy"})
    onehot = [vec[_idx(n)] for n in F.FEATURE_NAMES if n.startswith("rs_")]
    assert sum(onehot) == 0.0


def test_is_sca_sast_flags() -> None:
    assert F.build_vector({"rule_source": "sca"})[_idx("is_sca")] == 1
    assert F.build_vector({"rule_source": "sca"})[_idx("is_sast")] == 0
    assert F.build_vector({"rule_source": "sast"})[_idx("is_sast")] == 1


def test_age_days_from_iso_string_and_explicit() -> None:
    now = datetime(2026, 1, 20, tzinfo=timezone.utc)
    vec = F.build_vector({"first_seen": "2026-01-10T00:00:00Z"}, now=now)
    assert vec[_idx("age_days")] == 10
    vec2 = F.build_vector({"age_days": 3.5}, now=now)
    assert vec2[_idx("age_days")] == 3.5
    # age never goes negative on a future first_seen
    vec3 = F.build_vector({"first_seen": now + timedelta(days=5)}, now=now)
    assert vec3[_idx("age_days")] == 0.0


def test_normalize_vector_bounds() -> None:
    raw = {"severity": "critical", "cvss": 9.8, "reachability": "reachable",
           "max_path_exploitability": 100, "blast_score": 100, "age_days": 999}
    norm = F.normalize_vector(F.build_vector(raw))
    assert all(0.0 <= v <= 1.0 for v in norm)
    assert norm[_idx("severity_ordinal")] == 1.0
    assert abs(norm[_idx("cvss")] - 0.98) < 1e-9
    assert norm[_idx("reachability")] == 1.0
    assert norm[_idx("age_days")] == 1.0  # clipped


def test_feature_dict_roundtrip() -> None:
    raw = {"severity": "high", "rule_source": "sast"}
    d = F.feature_dict(raw)
    assert set(d) == set(F.FEATURE_NAMES)
    assert d["severity_ordinal"] == 3
    assert d["is_sast"] == 1
