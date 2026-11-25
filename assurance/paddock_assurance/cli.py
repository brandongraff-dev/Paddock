"""``paddock-invariants``: lint, explain and test invariants against a reach-graph file.

Host-config invariants (``assert:`` is a predicate or ``{all|any|not: ...}`` over host facts) are
linted, evaluated and explained the same way; ``fields`` lists what a predicate may read.

Exit codes (``test``): 0 every invariant HOLDS, 1 any VIOLATED, 2 none violated but some UNKNOWN
or EXPIRED, 3 bad input. ``lint``: 0 ok, 3 invalid. A ``covered`` invariant that finds uncovered
nodes is VIOLATED (exit 1) like any other: the gap is the counterexample.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Optional

from . import hostexpr as X
from . import hostfields as HF
from .compile import CompileError, Plan, PlanKind, compile_text
from .evaluate import Verdict, evaluate
from .graph import GraphError, ReachGraph
from .parse import ParseError
from .render import render_explain, render_result
from .stdlib import list_std, std_text

EXIT_OK, EXIT_VIOLATED, EXIT_UNKNOWN, EXIT_INPUT = 0, 1, 2, 3


class InputError(Exception):
    pass


def _load(ref: str) -> tuple[str, str]:
    """``(label, yaml text)`` for a file path or a ``std:`` id."""
    if ref.startswith("std:"):
        try:
            return ref, std_text(ref)
        except KeyError as exc:
            raise InputError(f"{ref}: no such standard invariant (try: paddock-invariants std)") \
                from exc
    p = Path(ref)
    try:
        return ref, p.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"{ref}: cannot read file ({exc.strerror})") from exc


def _plans(refs: list[str]) -> list[tuple[str, Plan]]:
    out: list[tuple[str, Plan]] = []
    seen: set[str] = set()
    for ref in refs:
        label, text = _load(ref)
        try:
            plan = compile_text(text)
        except ParseError as exc:
            raise InputError(f"{label}:\n  " + "\n  ".join(exc.problems)) from exc
        except CompileError as exc:
            raise InputError(f"{label}: {exc}") from exc
        if plan.id in seen:
            raise InputError(f"{label}: duplicate invariant id {plan.id}")
        seen.add(plan.id)
        out.append((label, plan))
    return out


def _now(arg: Optional[str], graph: Optional[ReachGraph]) -> dt.datetime:
    if arg:
        try:
            t = dt.datetime.fromisoformat(arg)
        except ValueError as exc:
            raise InputError(f"--now: bad timestamp {arg!r}") from exc
        if t.tzinfo is None:
            raise InputError("--now needs a timezone (use Z)")
        return t.astimezone(dt.timezone.utc)
    if graph is not None and graph.now is not None:
        return graph.now
    return dt.datetime.now(dt.timezone.utc)


def _graph(path: str) -> ReachGraph:
    try:
        return ReachGraph.from_file(path)
    except OSError as exc:
        raise InputError(f"{path}: cannot read graph ({exc.strerror})") from exc
    except GraphError as exc:
        raise InputError(f"{path}: {exc}") from exc


def cmd_lint(a: argparse.Namespace) -> int:
    plans = _plans(a.invariants)
    for label, plan in plans:
        print(f"ok  {plan.id}  {plan.digest[:19]}…  ({label})")
        if plan.kind is PlanKind.HOSTCONFIG and plan.expr is not None:
            print(f"      host-config: {X.to_text(plan.expr)}")
            print(f"      reads facts from: {', '.join(plan.collectors)}")
    return EXIT_OK


def cmd_fields(_: argparse.Namespace) -> int:
    """The closed registry of host fields a host-config predicate may read."""
    for spec in HF.catalog():
        flags = " derived" if spec.derived else ""
        shown = spec.display(("<" + spec.param.name + ">",) if spec.param else ())
        print(f"{shown:<46} "
              f"{spec.type:<10} {spec.collector:<10} max tier {spec.max_tier.value}{flags}")
        print(f"    {spec.doc}")
    return EXIT_OK


def cmd_std(_: argparse.Namespace) -> int:
    for sid in list_std():
        print(sid)
    return EXIT_OK


def cmd_test(a: argparse.Namespace) -> int:
    plans = _plans(a.invariants)
    g = _graph(a.graph)
    now = _now(a.now, g)
    results = [evaluate(p, g, now) for _, p in plans]
    if a.json:
        print(json.dumps({"evaluated_at": now.isoformat().replace("+00:00", "Z"),
                          "results": [r.to_dict() for r in results]}, indent=2, sort_keys=True))
    else:
        print("\n\n".join(render_result(r, now) for r in results))
    if any(r.verdict is Verdict.VIOLATED for r in results):
        return EXIT_VIOLATED
    if any(r.status_at(now) != "HOLDS" for r in results):
        return EXIT_UNKNOWN
    return EXIT_OK


def cmd_explain(a: argparse.Namespace) -> int:
    (_, plan), = _plans([a.invariant])
    g = _graph(a.graph)
    now = _now(a.now, g)
    print(render_explain(plan, g, evaluate(plan, g, now), now))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="paddock-invariants",
                                 description="Declare what must never be reachable; search for counterexamples.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    lint = sub.add_parser("lint", help="parse, validate and compile invariants")
    lint.add_argument("invariants", nargs="+", help="YAML file or std:<id>")
    lint.set_defaults(fn=cmd_lint)
    st = sub.add_parser("std", help="list the shipped standard invariants")
    st.set_defaults(fn=cmd_std)
    fl = sub.add_parser("fields", help="list the host fields a host-config predicate may read")
    fl.set_defaults(fn=cmd_fields)
    t = sub.add_parser("test", help="evaluate invariants against a reach-graph JSON file")
    t.add_argument("invariants", nargs="+", help="YAML file or std:<id>")
    t.add_argument("--graph", required=True, help="reach-graph JSON")
    t.add_argument("--now", help="evaluate as of this ISO-8601 time (default: graph 'now', else clock)")
    t.add_argument("--json", action="store_true", help="machine-readable output")
    t.set_defaults(fn=cmd_test)
    e = sub.add_parser("explain", help="show the plan, what the selectors resolve to, and the verdict")
    e.add_argument("invariant", help="YAML file or std:<id>")
    e.add_argument("--graph", required=True)
    e.add_argument("--now")
    e.set_defaults(fn=cmd_explain)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
