#!/usr/bin/env python3
"""Export the orchestrator's OpenAPI spec to docs/api/openapi.json, deterministically.

    python scripts/export_openapi.py            # (re)write docs/api/openapi.json
    python scripts/export_openapi.py --check    # exit 1 if the committed file is stale
    python scripts/export_openapi.py --out -    # print to stdout

The spec is built from the FastAPI app in-process (no server, no database):
keys are sorted, indentation is fixed and the file ends with a newline, so the
same code always produces byte-identical output. CI runs ``--check``; the SDKs
(sdk/python, sdk/typescript) are generated from the committed file.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "docs" / "api" / "openapi.json"


def build_spec() -> dict:
    # Importing the app must not depend on the operator's environment.
    os.environ.setdefault("AUTH_MODE", "enforce")
    sys.path.insert(0, str(ROOT / "orchestrator"))
    from app.main import create_app  # noqa: E402

    spec = create_app().openapi()
    # Pin the advertised server-agnostic metadata the SDKs rely on.
    spec.setdefault("info", {})["x-api-lifecycle"] = {
        "stable_prefix": "/v1",
        "policy": "docs/API.md#versioning-and-deprecation",
    }
    return spec


def render(spec: dict) -> str:
    return json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="output path, or '-' for stdout")
    ap.add_argument("--check", action="store_true", help="fail if the committed spec differs")
    a = ap.parse_args(argv)

    text = render(build_spec())
    if a.out == "-":
        sys.stdout.write(text)
        return 0
    out = Path(a.out)
    if a.check:
        current = out.read_text(encoding="utf-8") if out.exists() else ""
        if current == text:
            print(f"OK: {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out} is up to date")
            return 0
        diff = difflib.unified_diff(
            current.splitlines(), text.splitlines(), "committed", "generated", lineterm="", n=2
        )
        lines = list(diff)
        sys.stdout.write("\n".join(lines[:200]) + ("\n... (diff truncated)\n" if len(lines) > 200 else "\n"))
        print(
            "\nERROR: docs/api/openapi.json is stale. Regenerate with:\n"
            "    make api-regen      (or: python scripts/export_openapi.py)\n"
            "and commit the result (plus the regenerated SDKs).",
            file=sys.stderr,
        )
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} ({len(json.loads(text).get('paths', {}))} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
