# SPDX-License-Identifier: AGPL-3.0-or-later
"""Expand a whole-app fixture: ``python cli/tests/guard/support/expand_app.py <app-dir> <dst>``.

Gate 5 of 11.2 and the CI wheel job scan an expanded copy of ``vulnerable-app`` and
``clean-app``, never the in-repo path. Also importable: ``expand_app(src, dst)``.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_GUARD_TESTS = str(_HERE.parent)


def expand_app(src: str | Path, dst: str | Path) -> dict:
    if _GUARD_TESTS not in sys.path:
        sys.path.insert(0, _GUARD_TESTS)
    import support  # type: ignore[import-not-found]

    srcp = Path(src)
    sub = [p for p in (srcp / "a", srcp / "b") if p.is_dir()]
    if sub and not (srcp / "package.json").exists() and not any(srcp.glob("dot-*")):
        # vulnerable-app is split into a/ (G2a) and b/ (G2b); merge both into one tree.
        out: dict = {}
        for part in sub:
            out.update(support.expand_fixture(part, dst))
        return out
    return support.expand_fixture(srcp, dst)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: expand_app.py <app-dir> <dst>", file=sys.stderr)
        return 2
    src, dst = Path(args[0]), Path(args[1])
    if not src.is_dir():
        print("expand_app: not a directory: %s" % src.name, file=sys.stderr)
        return 2
    expand_app(src, dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
