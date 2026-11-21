"""Detection-quality harness: seeded ranges -> precision/recall -> gate.

A *range* is a YAML file of labelled cases for one engine. Every case says
which detectors SHOULD fire on it (``expect``); a case with ``expect: []`` is
a look-alike that must stay silent. The harness runs the engine's real
detection code in-process, compares what fired with what was expected, and
aggregates per detector:

    TP  expected and fired           FP  fired but not expected
    FN  expected but did not fire    TN  neither (look-alike stayed silent)

``precision = TP / (TP + FP)`` and ``recall = TP / (TP + FN)``. Both are
compared with ``thresholds.yaml``; any detector below its floor, any detector
that has no positive or no negative case, and any engine that fires nothing
at all (the "silent no-op" failure that once shipped SAST and typosquat dark)
fails the gate.

Engines live in separate service packages that all call themselves ``app``.
``service_modules`` swaps them in and out of ``sys.modules`` so each adapter
imports the real package from its own directory, in this one process.
"""
from __future__ import annotations

import contextlib
import importlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import yaml

ROOT = Path(__file__).resolve().parents[2]
EVALS = Path(__file__).resolve().parent
RANGES = EVALS / "ranges"
THRESHOLDS = EVALS / "thresholds.yaml"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Case:
    engine: str
    id: str
    expect: set[str]
    data: dict[str, Any]
    source: str = ""
    note: str | None = None


@dataclass
class Outcome:
    case: Case
    fired: set[str]
    error: str | None = None


@dataclass
class Score:
    detector: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    positives: int = 0
    negatives: int = 0
    misses: list[str] = field(default_factory=list)       # FN case ids
    false_alarms: list[str] = field(default_factory=list)  # FP case ids

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None


@dataclass
class Verdict:
    detector: str
    ok: bool
    reasons: list[str]
    min_precision: float
    min_recall: float


# --------------------------------------------------------------------------- #
# Loading ranges
# --------------------------------------------------------------------------- #

class RangeError(ValueError):
    pass


def load_ranges(paths: Iterable[Path] | None = None) -> list[Case]:
    """Load every ``ranges/**/*.yaml``. Validates ids are unique per engine
    and that every case has ``id`` + ``expect``."""
    files = sorted(paths) if paths is not None else sorted(RANGES.rglob("*.yaml"))
    cases: list[Case] = []
    seen: set[tuple[str, str]] = set()
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RangeError(f"{f.name}: invalid YAML: {exc}") from exc
        engine = doc.get("engine")
        if not engine:
            raise RangeError(f"{f}: missing top-level 'engine'")
        defaults = doc.get("defaults") or {}
        for raw in doc.get("cases") or []:
            if "id" not in raw or "expect" not in raw:
                raise RangeError(f"{f}: every case needs 'id' and 'expect' ({raw!r:.80})")
            key = (engine, str(raw["id"]))
            if key in seen:
                raise RangeError(f"{f}: duplicate case id {raw['id']!r} for engine {engine}")
            seen.add(key)
            data = {**defaults, **{k: v for k, v in raw.items() if k not in ("id", "expect")}}
            cases.append(Case(engine=engine, id=str(raw["id"]), expect=set(raw["expect"] or []),
                              data=data, source=f.name, note=raw.get("note")))
    return cases


def load_thresholds(path: Path = THRESHOLDS) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    doc.setdefault("defaults", {"precision": 1.0, "recall": 1.0})
    doc.setdefault("detectors", {})
    return doc


# --------------------------------------------------------------------------- #
# Module isolation: every service package is called `app`
# --------------------------------------------------------------------------- #

def _purge(prefix: str = "app") -> None:
    for name in [m for m in sys.modules if m == prefix or m.startswith(prefix + ".")]:
        del sys.modules[name]


@contextlib.contextmanager
def service_modules(service_dir: Path) -> Iterator[Callable[[str], Any]]:
    """Make ``import app...`` resolve to ``service_dir/app`` for the duration.

    Yields an ``imp(name)`` helper. Restores ``sys.path`` and purges the
    service's modules on exit so the next engine gets its own ``app``.
    """
    saved = list(sys.path)
    _purge()
    importlib.invalidate_caches()
    sys.path.insert(0, str(service_dir))
    try:
        yield importlib.import_module
    finally:
        _purge()
        sys.path[:] = saved
        importlib.invalidate_caches()


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def score(outcomes: list[Outcome], detectors: Iterable[str]) -> dict[str, Score]:
    """Aggregate TP/FP/FN/TN per detector. ``detectors`` is the engine's full
    detector list, so a detector that never fires still gets a row."""
    scores = {d: Score(d) for d in detectors}
    for o in outcomes:
        for d in set(o.case.expect) | set(o.fired):
            scores.setdefault(d, Score(d))
        for d, s in scores.items():
            exp, got = d in o.case.expect, d in o.fired
            if exp:
                s.positives += 1
            else:
                s.negatives += 1
            if exp and got:
                s.tp += 1
            elif exp:
                s.fn += 1
                s.misses.append(o.case.id)
            elif got:
                s.fp += 1
                s.false_alarms.append(o.case.id)
            else:
                s.tn += 1
    return scores


def judge(engine: str, scores: dict[str, Score], thresholds: dict[str, Any]) -> list[Verdict]:
    defaults = thresholds.get("defaults", {})
    per = thresholds.get("detectors", {})
    out: list[Verdict] = []
    for name, s in sorted(scores.items()):
        key = f"{engine}/{name}"
        t = {**defaults, **(per.get(key) or {})}
        min_p, min_r = float(t.get("precision", 1.0)), float(t.get("recall", 1.0))
        reasons: list[str] = []
        if s.positives == 0:
            reasons.append("no positive case (detector is untested)")
        if s.negatives == 0:
            reasons.append("no negative look-alike case")
        p, r = s.precision, s.recall
        if s.positives and (r is None or r + 1e-9 < min_r):
            reasons.append(f"recall {r or 0:.2f} < {min_r:.2f}")
        if s.tp + s.fp and p is not None and p + 1e-9 < min_p:
            reasons.append(f"precision {p:.2f} < {min_p:.2f}")
        if s.positives and s.tp == 0:
            reasons.append("never fires (silent no-op?)")
        out.append(Verdict(name, not reasons, reasons, min_p, min_r))
    return out


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #

@dataclass
class EngineResult:
    engine: str
    outcomes: list[Outcome]
    scores: dict[str, Score]
    verdicts: list[Verdict]
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and all(v.ok for v in self.verdicts) and not any(
            o.error for o in self.outcomes)


def run_engine(adapter, cases: list[Case], thresholds: dict[str, Any]) -> EngineResult:
    """``adapter`` exposes ``name``, ``service`` (dir under ROOT), ``detectors``
    and ``detect(imp, case) -> set[str]``; ``prepare(imp)`` is optional."""
    outcomes: list[Outcome] = []
    try:
        with service_modules(ROOT / adapter.service) as imp:
            ctx = adapter.prepare(imp) if hasattr(adapter, "prepare") else None
            for c in cases:
                try:
                    # Detectors outside the declared list are kept: they get a
                    # row with no positives, which fails as "untested".
                    outcomes.append(Outcome(c, set(adapter.detect(imp, c, ctx))))
                except Exception as exc:  # noqa: BLE001 -- a crash is a failure, not a skip
                    outcomes.append(Outcome(c, set(), error=f"{type(exc).__name__}: {exc}"))
    except Exception as exc:  # noqa: BLE001 -- engine failed to import
        return EngineResult(adapter.name, [], {}, [], error=f"{type(exc).__name__}: {exc}")
    scores = score(outcomes, adapter.detectors)
    return EngineResult(adapter.name, outcomes, scores, judge(adapter.name, scores, thresholds))


def _fmt(v: float | None) -> str:
    return "  -  " if v is None else f"{v:5.2f}"


def render_table(results: list[EngineResult], verbose: bool = False) -> str:
    lines = []
    hdr = (f"{'engine':<14} {'detector':<36} {'pos':>4} {'neg':>4} {'TP':>4} {'FP':>4} "
           f"{'FN':>4} {'prec':>5} {'rec':>5} {'min p/r':>9}  status")
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for res in results:
        if res.error:
            lines.append(f"{res.engine:<14} {'<engine failed to load>':<36} ERROR: {res.error}")
            continue
        verdicts = {v.detector: v for v in res.verdicts}
        for name, s in sorted(res.scores.items()):
            v = verdicts[name]
            status = "ok" if v.ok else "FAIL: " + "; ".join(v.reasons)
            lines.append(
                f"{res.engine:<14} {name:<36} {s.positives:>4} {s.negatives:>4} {s.tp:>4} "
                f"{s.fp:>4} {s.fn:>4} {_fmt(s.precision)} {_fmt(s.recall)} "
                f"{v.min_precision:4.2f}/{v.min_recall:4.2f}  {status}"
            )
            if verbose or not v.ok:
                if s.misses:
                    lines.append(f"{'':<14}   missed (FN): {', '.join(s.misses)}")
                if s.false_alarms:
                    lines.append(f"{'':<14}   false alarm (FP): {', '.join(s.false_alarms)}")
        for o in res.outcomes:
            if o.error:
                lines.append(f"{res.engine:<14}   CRASH on case {o.case.id}: {o.error}")
    return "\n".join(lines)


def to_json(results: list[EngineResult]) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": all(r.ok for r in results), "engines": {}}
    for r in results:
        out["engines"][r.engine] = {
            "ok": r.ok, "error": r.error, "cases": len(r.outcomes),
            "detectors": {
                n: {"tp": s.tp, "fp": s.fp, "fn": s.fn, "tn": s.tn,
                    "positives": s.positives, "negatives": s.negatives,
                    "precision": s.precision, "recall": s.recall,
                    "misses": s.misses, "false_alarms": s.false_alarms}
                for n, s in r.scores.items()
            },
        }
    return out
