# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare Guard's token regex families with locally available gitleaks and detect-secrets rules (D6).

Model-written patterns can coincide with third-party rules, and the clean-room rule (never copy
Semgrep, TruffleHog or GPL text) is best effort, so this tool looks for coincidence and reports it;
G2a and G2b record the outcome in ``docs/guard/sources/similarity-a.md`` and ``similarity-b.md``.
It reads rule files that already exist on this machine (never the network) and skips silently when
there are none. Usable as a library or as ``python similarity.py FAMILIES.json`` where the JSON is
``{"family-name": "regex source"}``.
"""
from __future__ import annotations

import ast
import difflib
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

THRESHOLD = 0.9
_MAX_FILE = 2_000_000
_NOISE = re.compile(r"\\b|\(\?:|\(\?i\)|\^|\$|\\A|\\Z")


@dataclass(frozen=True)
class Rule:
    source: str   # file the rule came from
    rule_id: str
    regex: str


@dataclass(frozen=True)
class Match:
    family: str
    other: Rule
    ratio: float


def discover_rule_files(env: dict[str, str] | None = None) -> list[Path]:
    """Existing gitleaks TOML files and detect-secrets plugin sources; empty when there are none."""
    e = os.environ if env is None else env
    roots: list[Path] = [Path(p) for p in e.get("PADDOCK_GUARD_SIMILARITY_DIRS", "").split(os.pathsep) if p]
    home = Path(os.path.expanduser("~"))
    roots += [home / ".config" / "gitleaks", Path("/etc/gitleaks"), Path("/usr/share/gitleaks"), Path("/usr/local/share/gitleaks")]
    out: list[Path] = []
    for r in roots:
        if r.is_file():
            out.append(r)
        elif r.is_dir():
            out += sorted(r.rglob("gitleaks*.toml"))[:20]
    for entry in sys.path:
        base = Path(entry) / "detect_secrets" / "plugins"
        if base.is_dir():
            out += sorted(base.glob("*.py"))
    return [p for p in out if p.is_file() and p.stat().st_size <= _MAX_FILE]


def load_rules(paths: list[Path]) -> list[Rule]:
    rules: list[Rule] = []
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if p.suffix == ".toml":
            try:
                doc = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, RecursionError, ValueError):
                continue
            for r in doc.get("rules", []):
                if isinstance(r, dict) and isinstance(r.get("regex"), str):
                    rules.append(Rule(p.name, str(r.get("id", "?")), r["regex"]))
        elif p.suffix == ".py":
            try:
                tree = ast.parse(text)
            except (SyntaxError, RecursionError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "compile" and node.args:
                    a = node.args[0]
                    if isinstance(a, ast.Constant) and isinstance(a.value, str) and len(a.value) > 6:
                        rules.append(Rule(p.name, "compile@%d" % node.lineno, a.value))
    return rules


def normalise(rx: str) -> str:
    return _NOISE.sub("", rx).replace(" ", "").lower()


def compare(families: dict[str, str], rules: list[Rule], threshold: float = THRESHOLD) -> list[Match]:
    """Rules whose normalised regex is at least ``threshold`` similar to a Guard family."""
    out: list[Match] = []
    norm_rules = [(r, normalise(r.regex)) for r in rules]
    for name, rx in sorted(families.items()):
        n = normalise(rx)
        if not n:
            continue
        for r, nr in norm_rules:
            if not nr:
                continue
            ratio = 1.0 if n == nr else difflib.SequenceMatcher(None, n, nr).ratio()
            if ratio >= threshold:
                out.append(Match(name, r, round(ratio, 3)))
    return out


def families_from_objects(objs) -> dict[str, str]:
    """``{name: regex source}`` from objects with ``name`` and ``regex`` (a compiled pattern or a string)."""
    out: dict[str, str] = {}
    for o in objs:
        name = getattr(o, "name", None)
        rx = getattr(o, "regex", None) or getattr(o, "pattern", None)
        if isinstance(name, str) and rx is not None:
            out[name] = rx.pattern if hasattr(rx, "pattern") else str(rx)
    return out


def report(matches: list[Match], n_rules: int, n_files: int) -> str:
    lines = ["Similarity check against %d local third-party rule(s) from %d file(s)." % (n_rules, n_files)]
    if n_files == 0:
        lines.append("No gitleaks or detect-secrets rule files were found on this machine, so nothing was compared.")
    elif not matches:
        lines.append("No Guard family is at least %.0f%% similar to a local rule." % (THRESHOLD * 100))
    for m in matches:
        lines.append("- %s is %.0f%% similar to %s in %s" % (m.family, m.ratio * 100, m.other.rule_id, m.other.source))
    return "\n".join(lines) + "\n"


def run(families: dict[str, str], env: dict[str, str] | None = None) -> tuple[list[Match], int, int]:
    files = discover_rule_files(env)
    rules = load_rules(files)
    return compare(families, rules), len(rules), len(files)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: similarity.py FAMILIES.json", file=sys.stderr)
        return 2
    families = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    matches, n_rules, n_files = run(families)
    sys.stdout.write(report(matches, n_rules, n_files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
