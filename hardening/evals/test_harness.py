"""Self-tests for the detection-quality harness.

    pytest hardening/evals/test_harness.py

The scoring/judging/isolation tests need only PyYAML. The end-to-end test at
the bottom runs the real scope engine when the orchestrator's dependencies
are installed (the CI `evals` job installs them) and skips otherwise.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402
from engines import ADAPTERS  # noqa: E402


def _case(cid, expect, engine="x"):
    return harness.Case(engine=engine, id=cid, expect=set(expect), data={})


# --------------------------------------------------------------------------- #
# scoring + judging
# --------------------------------------------------------------------------- #

def test_score_counts_tp_fp_fn_tn_per_detector():
    outcomes = [
        harness.Outcome(_case("p1", ["a"]), {"a"}),        # a: TP
        harness.Outcome(_case("p2", ["a"]), set()),        # a: FN
        harness.Outcome(_case("n1", []), {"a"}),           # a: FP
        harness.Outcome(_case("n2", []), set()),           # a: TN
        harness.Outcome(_case("p3", ["b"]), {"b", "a"}),   # b: TP, a: FP
    ]
    s = harness.score(outcomes, ["a", "b"])
    a, b = s["a"], s["b"]
    assert (a.tp, a.fp, a.fn, a.tn) == (1, 2, 1, 1)
    assert a.positives == 2 and a.negatives == 3
    assert a.precision == pytest.approx(1 / 3) and a.recall == pytest.approx(0.5)
    assert a.misses == ["p2"] and a.false_alarms == ["n1", "p3"]
    assert (b.tp, b.fp, b.fn) == (1, 0, 0) and b.precision == 1.0


def test_undeclared_detector_still_gets_a_row():
    s = harness.score([harness.Outcome(_case("n", []), {"surprise"})], ["a"])
    assert "surprise" in s and s["surprise"].fp == 1


def test_judge_enforces_floors_coverage_and_noop():
    th = {"defaults": {"precision": 1.0, "recall": 1.0},
          "detectors": {"e/lenient": {"recall": 0.5}}}
    outcomes = [
        harness.Outcome(_case("p1", ["ok", "lenient", "noop"]), {"ok", "lenient"}),
        harness.Outcome(_case("p2", ["lenient"]), set()),
        harness.Outcome(_case("n1", []), set()),
    ]
    scores = harness.score(outcomes, ["ok", "lenient", "noop", "untested"])
    v = {x.detector: x for x in harness.judge("e", scores, th)}
    assert v["ok"].ok
    assert v["lenient"].ok and v["lenient"].min_recall == 0.5   # 0.5 >= 0.5
    assert not v["noop"].ok and any("never fires" in r for r in v["noop"].reasons)
    assert not v["untested"].ok and any("no positive" in r for r in v["untested"].reasons)


def test_judge_requires_a_negative_lookalike():
    outcomes = [harness.Outcome(_case("p1", ["a"]), {"a"})]
    (v,) = harness.judge("e", harness.score(outcomes, ["a"]), {"defaults": {}})
    assert not v.ok and any("negative" in r for r in v.reasons)


def test_precision_regression_fails():
    outcomes = [harness.Outcome(_case("p", ["a"]), {"a"}),
                harness.Outcome(_case("n", []), {"a"})]
    (v,) = harness.judge("e", harness.score(outcomes, ["a"]),
                         {"defaults": {"precision": 0.9, "recall": 1.0}})
    assert not v.ok and any("precision 0.50 < 0.90" in r for r in v.reasons)


# --------------------------------------------------------------------------- #
# running adapters: no-op and crash are failures, never silent passes
# --------------------------------------------------------------------------- #

class _FakeAdapter:
    name = "fake"
    service = "hardening"  # any existing dir; nothing is imported from it
    detectors = ["d"]

    def __init__(self, fn):
        self._fn = fn

    def detect(self, imp, case, ctx):
        return self._fn(case)


def _cases():
    return [_case("p", ["d"], "fake"), _case("n", [], "fake")]


def test_noop_engine_fails_the_gate():
    res = harness.run_engine(_FakeAdapter(lambda c: set()), _cases(), {"defaults": {}})
    assert not res.ok
    assert "never fires" in harness.render_table([res])


def test_crashing_engine_fails_the_gate():
    def boom(c):
        raise RuntimeError("rules file missing")
    res = harness.run_engine(_FakeAdapter(boom), _cases(), {"defaults": {}})
    assert not res.ok
    assert "CRASH on case p" in harness.render_table([res])


def test_perfect_engine_passes():
    res = harness.run_engine(_FakeAdapter(lambda c: set(c.expect)), _cases(), {"defaults": {}})
    assert res.ok


def test_engine_that_fails_to_import_is_reported(tmp_path):
    class Broken(_FakeAdapter):
        service = str(tmp_path)

        def prepare(self, imp):
            return imp("app.does_not_exist")

    res = harness.run_engine(Broken(lambda c: set()), _cases(), {"defaults": {}})
    assert not res.ok and res.error and "ModuleNotFoundError" in res.error


# --------------------------------------------------------------------------- #
# module isolation (every service package is called `app`)
# --------------------------------------------------------------------------- #

def test_service_modules_isolates_same_named_packages(tmp_path):
    for name in ("one", "two"):
        pkg = tmp_path / name / "app"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text(f"WHO = {name!r}\n")
    with harness.service_modules(tmp_path / "one") as imp:
        assert imp("app").WHO == "one"
    assert "app" not in sys.modules
    with harness.service_modules(tmp_path / "two") as imp:
        assert imp("app").WHO == "two"
    assert "app" not in sys.modules


# --------------------------------------------------------------------------- #
# range files
# --------------------------------------------------------------------------- #

def test_range_loader_rejects_bad_files(tmp_path):
    dup = tmp_path / "dup.yaml"
    dup.write_text("engine: x\ncases:\n  - {id: a, expect: []}\n  - {id: a, expect: []}\n")
    with pytest.raises(harness.RangeError, match="duplicate"):
        harness.load_ranges([dup])
    noexp = tmp_path / "noexp.yaml"
    noexp.write_text("engine: x\ncases:\n  - {id: a}\n")
    with pytest.raises(harness.RangeError, match="expect"):
        harness.load_ranges([noexp])
    bad = tmp_path / "bad.yaml"
    bad.write_text("engine: x\ncases:\n  - id: a\n    note: 'x' y\n")
    with pytest.raises(harness.RangeError, match="invalid YAML"):
        harness.load_ranges([bad])
    noeng = tmp_path / "noeng.yaml"
    noeng.write_text("cases: []\n")
    with pytest.raises(harness.RangeError, match="engine"):
        harness.load_ranges([noeng])


def test_shipped_ranges_cover_every_detector_both_ways():
    cases = harness.load_ranges()
    assert {c.engine for c in cases} == set(ADAPTERS)
    for name, adapter in ADAPTERS.items():
        mine = [c for c in cases if c.engine == name]
        declared = adapter.detectors or sorted({d for c in mine for d in c.expect})
        for d in declared:
            assert any(d in c.expect for c in mine), f"{name}/{d}: no positive case"
            assert any(d not in c.expect for c in mine), f"{name}/{d}: no negative case"
        if name != "scope":  # scope's detectors partition every outcome (reject|canonical)
            assert any(not c.expect for c in mine), f"{name}: no pure look-alike case"


def test_sast_range_is_big_enough_and_multilingual():
    sast = [c for c in harness.load_ranges() if c.engine == "sast"]
    assert len(sast) >= 30
    langs = {c.data.get("lang", "python") for c in sast}
    assert {"python", "javascript", "go"} <= langs
    for lang in ("python", "javascript", "go"):
        mine = [c for c in sast if c.data.get("lang", "python") == lang]
        assert any(c.expect for c in mine) and any(not c.expect for c in mine)


def test_thresholds_reference_real_detectors():
    th = harness.load_thresholds()
    cases = harness.load_ranges()
    for key, floors in th["detectors"].items():
        engine, _, det = key.partition("/")
        assert engine in ADAPTERS, f"thresholds: unknown engine in {key}"
        known = set(ADAPTERS[engine].detectors) | {d for c in cases if c.engine == engine
                                                   for d in c.expect}
        assert det in known, f"thresholds: unknown detector {key}"
        assert set(floors) <= {"precision", "recall"}
        assert all(0.0 <= float(v) <= 1.0 for v in floors.values())


def test_known_weakness_floors_name_their_cases():
    """Every floor below 1.0 must be explained by a case marked KNOWN in its note."""
    th = harness.load_thresholds()
    known = {(c.engine, c.id) for c in harness.load_ranges() if "KNOWN" in (c.note or "")}
    lowered = [k for k, v in th["detectors"].items() if any(float(x) < 1.0 for x in v.values())]
    engines_with_known = {e for e, _ in known}
    for key in lowered:
        assert key.split("/")[0] in engines_with_known, key


# --------------------------------------------------------------------------- #
# end to end on a real engine (needs orchestrator deps)
# --------------------------------------------------------------------------- #

_ORCH_DEPS = all(importlib.util.find_spec(m) for m in ("pydantic_settings", "asyncpg"))


@pytest.mark.skipif(not _ORCH_DEPS, reason="orchestrator dependencies not installed")
def test_scope_engine_end_to_end():
    import run

    assert run.main(["--engine", "scope"]) == 0
