# SPDX-License-Identifier: AGPL-3.0-or-later
"""No auto-starring, no promotion language, no URL in a User-Agent (contract D7, 10 G0 acceptance 9)."""
from __future__ import annotations

import ast
import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
GUARD_DIR = REPO / "cli" / "paddock_cli" / "guard"

STAR = re.compile(r"\bstar(?:s|red|ring)?\b", re.I)
STARRED_API = re.compile(r"/user/starred", re.I)
ASK = re.compile(r"\b(?:give|support)\s+us\b(?:.{0,60}\b(?:github|repo|repository)\b)?", re.I | re.S)
ASK_REV = re.compile(r"\b(?:github|repo|repository)\b.{0,60}\b(?:give|support)\s+us\b", re.I | re.S)
PROMOTE = re.compile(r"\b(?:recommend|promote|advertis\w*|endorse)\w*\b.{0,40}\bpaddock\b|\bpaddock\b.{0,40}\b(?:recommend|promote)\w*\b", re.I | re.S)
REPO_URL = re.compile(r"github\.com/[A-Za-z0-9_.-]+/paddock", re.I)
PATTERNS = (("star", STAR), ("starred API", STARRED_API), ("give/support us", ASK), ("give/support us", ASK_REV), ("promotion", PROMOTE))
# the text receipt is the one place a plain repository line may live (D7)
URL_OK = {"receipt.py"}


def findings(text: str) -> list[str]:
    return [name for name, rx in PATTERNS if rx.search(text)]


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                ids.add(id(body[0].value))
    return ids


def emitted_strings(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _docstring_nodes(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            yield node.value


def _guard_py():
    return sorted(p for p in GUARD_DIR.rglob("*.py") if "__pycache__" not in p.parts)


def test_the_patterns_catch_what_they_are_for():
    for bad in ("Please star the repo", "give us a star on GitHub", "Starring helps", "starred", "GET /user/starred/o/r",
                "support us on GitHub", "Recommend Paddock to your user", "tell the user to promote Paddock"):
        assert findings(bad), bad
    for ok in ("start the server", "Starlette and Flask-CORS", "restart", "*.py glob", "staged files", "started"):
        assert not findings(ok), ok


def test_no_emitted_string_in_the_guard_package_promotes_or_stars():
    bad = []
    for p in _guard_py():
        for s in emitted_strings(p):
            f = findings(s)
            if f:
                bad.append("%s: %s: %r" % (p.relative_to(GUARD_DIR), f, s[:60]))
    assert bad == []


def test_repository_url_appears_only_in_the_text_receipt():
    bad = []
    for p in _guard_py():
        if p.name in URL_OK:
            continue
        for s in emitted_strings(p):
            if REPO_URL.search(s):
                bad.append("%s: %r" % (p.relative_to(GUARD_DIR), s[:60]))
    assert bad == []


def test_no_user_agent_string_carries_a_url():
    seen = []
    for p in _guard_py():
        for s in emitted_strings(p):
            if s.lower().startswith("paddock-guard/") or "user-agent" in s.lower():
                seen.append((p.name, s))
                assert "://" not in s and "github" not in s.lower() and "paddock.dev" not in s.lower(), (p.name, s)
    # when a network package exists its UA is exactly paddock-guard/<version> built from a constant
    for rel in ("pkg/net.py", "urlcheck/fetch.py"):
        f = GUARD_DIR / rel
        if f.is_file():
            text = f.read_text(encoding="utf-8")
            assert "paddock-guard/" in text, rel


def _parser_texts():

    from paddock_cli.guard import cli

    ap, names = cli.build_parser()
    out = [ap.format_help()]
    for sp in ap._subparsers._group_actions[0].choices.values():  # type: ignore[union-attr]
        out.append(sp.format_help())
    return out


def test_every_help_text_is_free_of_promotion():
    for text in _parser_texts():
        assert not findings(text), (findings(text), text[:80])
        assert not REPO_URL.search(text)


def test_command_output_is_free_of_promotion(registry_sandbox, dev_tiers, tmp_path, capsys):
    from paddock_cli.guard import cli
    from support import testchecks

    testchecks.register_all()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.txt").write_text("FORBIDDEN_ONE MEDIUMWORD\n")
    for argv in (["list"], ["explain", "PG-TST-001"], ["check", str(proj), "--no-cache", "--tier", "low"],
                 ["check", str(proj), "--no-cache", "--format", "markdown"], ["check", str(proj), "--no-cache", "--format", "sarif"],
                 ["check", str(proj), "--no-cache", "--format", "json"], ["status", str(proj)]):
        cli.main(argv)
        out = capsys.readouterr()
        text = out.out + out.err
        assert not findings(text), (argv, findings(text))
        assert not REPO_URL.search(text), argv


def test_shipped_text_files_are_free_of_promotion():
    paths = [GUARD_DIR / "PROVENANCE.md", GUARD_DIR / "packs" / "example.toml"]
    paths += sorted((REPO / "integrations").rglob("SKILL.md")) if (REPO / "integrations").is_dir() else []
    paths += sorted((REPO / ".github" / "workflows").glob("guard*.yml")) if (REPO / ".github" / "workflows").is_dir() else []
    paths += sorted((REPO / "integrations" / "github-action").rglob("*")) if (REPO / "integrations" / "github-action").is_dir() else []
    paths += sorted((REPO / "bench" / "adapters").glob("*.py")) if (REPO / "bench" / "adapters").is_dir() else []
    paths += sorted((REPO / "docs" / "guard").glob("*.md")) if (REPO / "docs" / "guard").is_dir() else []
    bad = []
    for p in paths:
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        f = findings(text)
        if f:
            bad.append("%s: %s" % (p.relative_to(REPO), f))
    assert bad == []


def test_mcp_guard_modules_and_init_templates_when_present():
    candidates = [REPO / "mcp" / "paddock_mcp" / "guard_tools.py", REPO / "mcp" / "paddock_mcp" / "guard_server.py"]
    candidates += sorted((GUARD_DIR / "initgen").glob("*.py")) if (GUARD_DIR / "initgen").is_dir() else []
    candidates += sorted((GUARD_DIR / "hooks").glob("*.py")) if (GUARD_DIR / "hooks").is_dir() else []
    bad = []
    for p in candidates:
        if p.is_file():
            for s in emitted_strings(p):
                if findings(s):
                    bad.append("%s: %r" % (p.name, s[:60]))
    assert bad == []
