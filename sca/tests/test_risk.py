from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.risk import abandoned, confusion, malicious, pinning, typosquat


# --------------------------------------------------------------------------
# typosquat
# --------------------------------------------------------------------------
def test_levenshtein_basic():
    assert typosquat.levenshtein("abc", "abc") == 0
    assert typosquat.levenshtein("react", "raect") == 2
    assert typosquat.levenshtein("lodash", "lodahs") == 2
    assert typosquat.levenshtein("abc", "xyzabc", cap=2) == 3  # cap short-circuit


def test_typosquat_flags_lookalike_not_exact():
    comps = [
        {"ecosystem": "npm", "name": "reqeust", "version": "1.0.0"},   # request typo
        {"ecosystem": "npm", "name": "express", "version": "4.0.0"},   # exact popular
        {"ecosystem": "npm", "name": "totally-unique-xyz", "version": "1.0.0"},
    ]
    risks = typosquat.detect(comps, max_distance=2)
    names = {r["name"] for r in risks}
    assert "reqeust" in names          # flagged: distance 1 from "request"
    assert "express" not in names      # exact match excluded
    assert "totally-unique-xyz" not in names
    r = next(r for r in risks if r["name"] == "reqeust")
    assert r["risk_type"] == "typosquat"
    assert r["detail"]["resembles"] == "request"


# --------------------------------------------------------------------------
# dependency confusion
# --------------------------------------------------------------------------
def test_confusion_flags_scoped_and_internal():
    comps = [
        {"ecosystem": "npm", "name": "@acme/internal-utils", "version": "1.0.0"},
        {"ecosystem": "PyPI", "name": "acme-internal-client", "version": "2.0.0"},
        {"ecosystem": "npm", "name": "express", "version": "4.0.0"},
    ]
    risks = confusion.detect(comps)
    names = {r["name"] for r in risks}
    assert "@acme/internal-utils" in names
    assert "acme-internal-client" in names
    assert "express" not in names
    assert all(r["risk_type"] == "dependency_confusion" for r in risks)


def test_confusion_public_name_raises_severity():
    comps = [{"ecosystem": "npm", "name": "@acme/internal-utils", "version": "1.0.0"}]
    risks = confusion.detect(comps, public_names=["@acme/internal-utils"])
    assert risks[0]["severity"] == "high"
    assert risks[0]["detail"]["public_name_exists"] is True


# --------------------------------------------------------------------------
# pinning
# --------------------------------------------------------------------------
def test_pinning_flags_ranges():
    comps = [
        {"ecosystem": "npm", "name": "a", "version": "^1.2.3"},
        {"ecosystem": "npm", "name": "b", "version": "1.2.3"},
        {"ecosystem": "PyPI", "name": "c", "version": "",
         "metadata": {"spec": "c>=1.0", "unpinned": True}},
    ]
    risks = pinning.detect(comps)
    names = {r["name"] for r in risks}
    assert "a" in names and "c" in names
    assert "b" not in names
    assert all(r["severity"] == "low" for r in risks)


# --------------------------------------------------------------------------
# abandoned
# --------------------------------------------------------------------------
def test_abandoned_flags_old_release():
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    comps = [
        {"ecosystem": "npm", "name": "stale", "version": "1.0.0"},
        {"ecosystem": "npm", "name": "fresh", "version": "2.0.0"},
    ]
    last = {
        "npm|stale": "2020-01-01T00:00:00Z",   # ~4y -> abandoned
        "npm|fresh": "2023-10-01T00:00:00Z",   # recent
    }
    risks = abandoned.detect(comps, last, now=now, max_age_days=730)
    names = {r["name"] for r in risks}
    assert "stale" in names and "fresh" not in names


def test_abandoned_offline_safe():
    # no metadata -> no risks, no crash
    assert abandoned.detect([{"ecosystem": "npm", "name": "x", "version": "1"}], None) == []
    assert abandoned.detect([{"ecosystem": "npm", "name": "x", "version": "1"}], {}) == []


# --------------------------------------------------------------------------
# malicious / yanked
# --------------------------------------------------------------------------
def test_malicious_from_osv_results():
    comps = [{"ecosystem": "npm", "name": "evil-lib", "version": "6.6.6"}]
    osv_results = {"npm|evil-lib|6.6.6": [{"osv_id": "MAL-2023-0001", "malicious": True}]}
    risks = malicious.detect(comps, osv_results)
    assert len(risks) == 1
    assert risks[0]["risk_type"] == "malicious_version"
    assert risks[0]["severity"] == "critical"


def test_yanked_from_keys():
    comps = [{"ecosystem": "PyPI", "name": "oops", "version": "1.2.3"}]
    risks = malicious.detect(comps, {}, yanked_keys={"PyPI|oops|1.2.3"})
    assert len(risks) == 1
    assert risks[0]["risk_type"] == "yanked"


def test_typosquat_transposition_is_one_edit_and_high_severity():
    # Swapped letters are the most common real squat; OSA scores them as 1.
    assert typosquat.typo_distance("reqeust", "request") == 1
    assert typosquat.levenshtein("reqeust", "request") == 2
    r = typosquat.detect([{"ecosystem": "npm", "name": "reqeust", "version": "1"}])[0]
    assert r["severity"] == "high" and r["detail"]["edit_distance"] == 1


def test_typosquat_short_names_need_a_closer_match():
    comps = [
        {"ecosystem": "npm", "name": "xs", "version": "1"},       # 2 chars: never compared
        {"ecosystem": "npm", "name": "axois", "version": "1"},    # 5 chars, 1 swap from axios
        {"ecosystem": "npm", "name": "vxyz", "version": "1"},     # 4 chars, 2 edits from vue: no
    ]
    names = {r["name"] for r in typosquat.detect(comps, max_distance=2)}
    assert names == {"axois"}


def test_typosquat_popular_neighbours_are_not_flagged():
    # eslint/tslint, react/preact... are both legit and popular -> exact matches.
    comps = [{"ecosystem": "npm", "name": n, "version": "1"} for n in ("eslint", "tslint", "jest", "next")]
    comps.append({"ecosystem": "PyPI", "name": "requests", "version": "2"})
    assert typosquat.detect(comps, max_distance=2) == []


def test_typosquat_is_per_ecosystem():
    comps = [{"ecosystem": "PyPI", "name": "reqeusts", "version": "1"},
             {"ecosystem": "crates.io", "name": "reqeusts", "version": "1"}]
    hits = typosquat.detect(comps)
    assert [(h["ecosystem"], h["detail"]["resembles"]) for h in hits] == [("PyPI", "requests")]


def test_typosquat_two_edits_only_count_on_long_names():
    comps = [{"ecosystem": "npm", "name": "parse5", "version": "7"},          # 2 from parcel
             {"ecosystem": "npm", "name": "expresss-js", "version": "1"}]     # long, 2 from express? no
    assert [h["name"] for h in typosquat.detect(comps)] == []
    long_hit = typosquat.detect([{"ecosystem": "npm", "name": "socket.oi", "version": "1"},
                                 {"ecosystem": "npm", "name": "jsonwebtokne", "version": "1"}])
    assert {h["detail"]["resembles"] for h in long_hit} == {"socket.io", "jsonwebtoken"}
