#!/usr/bin/env python3
"""Detection-quality gate. Runs every seeded range through the real engines,
prints precision/recall per detector, and exits non-zero on regression.

    python hardening/evals/run.py                 # all engines
    python hardening/evals/run.py --engine sast   # one engine
    python hardening/evals/run.py -v --json out.json

Exit codes: 0 all detectors at/above threshold; 1 regression (or an engine
failed to load / crashed on a case); 2 bad range or threshold file.
See docs/EVALS.md for how to add a case from a customer report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402
from engines import ADAPTERS  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--engine", action="append", choices=sorted(ADAPTERS),
                    help="run only this engine (repeatable)")
    ap.add_argument("--json", type=Path, help="also write machine-readable results here")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every FN/FP case id")
    a = ap.parse_args(argv)

    try:
        cases = harness.load_ranges()
        thresholds = harness.load_thresholds()
    except (harness.RangeError, OSError, ValueError) as exc:
        print(f"evals: bad range/threshold file: {exc}", file=sys.stderr)
        return 2

    unknown = sorted({c.engine for c in cases} - set(ADAPTERS))
    if unknown:
        print(f"evals: ranges reference unknown engines: {unknown}", file=sys.stderr)
        return 2

    results = []
    for name in a.engine or sorted(ADAPTERS):
        engine_cases = [c for c in cases if c.engine == name]
        if not engine_cases:
            print(f"evals: engine {name!r} has no cases", file=sys.stderr)
            return 1
        results.append(harness.run_engine(ADAPTERS[name], engine_cases, thresholds))

    print(harness.render_table(results, verbose=a.verbose))
    total = sum(len(r.outcomes) for r in results)
    ok = all(r.ok for r in results)
    print(f"\n{total} cases across {len(results)} engines: "
          f"{'PASS' if ok else 'FAIL -- detection quality regressed'}")
    if a.json:
        a.json.write_text(json.dumps(harness.to_json(results), indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
