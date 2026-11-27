# SPDX-License-Identifier: AGPL-3.0-or-later
"""Only the network modules may open sockets; only gitutil starts processes (contract D7, D31, 10 G0 acceptance 9)."""
from __future__ import annotations

import ast
import re
from pathlib import Path

GUARD_DIR = Path(__file__).resolve().parents[2] / "paddock_cli" / "guard"

NETWORK_MODULES = {"pkg/net.py", "urlcheck/fetch.py", "receipt.py"}
BANNED_NET = {"socket", "ssl", "http.client", "http.server", "urllib.request", "ftplib", "smtplib", "socketserver",
              "telnetlib", "imaplib", "poplib", "nntplib", "xmlrpc.client", "asyncio"}
PROCESS_MODULES = {"gitutil.py"}
HOSTS = {
    "pkg/net.py": {"registry.npmjs.org", "api.npmjs.org", "pypi.org", "api.osv.dev"},
    "urlcheck/fetch.py": set(),          # the single user-named URL host, never a literal
    "receipt.py": {"api.github.com"},     # or the GITHUB_SERVER_URL host from the environment
}
_HOST_LIKE = re.compile(r"^(?:https?://)?([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)(?::\d+)?(?:/.*)?$")


def _rel(p: Path) -> str:
    return p.relative_to(GUARD_DIR).as_posix()


def _py():
    return sorted(p for p in GUARD_DIR.rglob("*.py") if "__pycache__" not in p.parts)


def imported_modules(tree: ast.AST) -> set[str]:
    """Every absolute module name an import could pull in, including ``from pkg import submodule``."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out.add(a.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.add(node.module)
            for a in node.names:
                out.add(node.module + "." + a.name)
    return out


def _banned_hits(mods: set[str], banned: set[str]) -> set[str]:
    return {m for m in mods if any(m == b or m.startswith(b + ".") for b in banned)}


def test_only_network_modules_import_network_libraries():
    bad = []
    for p in _py():
        if _rel(p) in NETWORK_MODULES:
            continue
        hits = _banned_hits(imported_modules(ast.parse(p.read_text(encoding="utf-8"))), BANNED_NET)
        if hits:
            bad.append("%s imports %s" % (_rel(p), sorted(hits)))
    assert bad == []


def test_only_gitutil_imports_subprocess():
    bad = []
    for p in _py():
        if p.name in PROCESS_MODULES and p.parent == GUARD_DIR:
            continue
        hits = _banned_hits(imported_modules(ast.parse(p.read_text(encoding="utf-8"))), {"subprocess", "multiprocessing", "pty"})
        if hits:
            bad.append("%s imports %s" % (_rel(p), sorted(hits)))
    assert bad == []


def test_the_detector_sees_every_import_spelling():
    for src in ("import socket", "import ssl", "import http.client", "from http import client", "from urllib import request",
                "from urllib.request import urlopen", "import urllib.request as r", "from socket import socket"):
        assert _banned_hits(imported_modules(ast.parse(src)), BANNED_NET), src
    assert not _banned_hits(imported_modules(ast.parse("import urllib.parse\nfrom urllib.parse import quote\nimport http")), BANNED_NET)
    assert _banned_hits(imported_modules(ast.parse("from os import system\nimport subprocess")), {"subprocess"})


def test_network_modules_contact_only_their_pinned_hosts():
    for rel, allowed in HOSTS.items():
        p = GUARD_DIR / rel
        if not p.is_file():
            continue  # package not built yet
        tree = ast.parse(p.read_text(encoding="utf-8"))
        seen = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                m = _HOST_LIKE.match(node.value.strip())
                if m and ("://" in node.value or re.search(r"\.(com|org|dev|io|net)$", m.group(1))):
                    seen.add(m.group(1))
        assert seen <= allowed, "%s names hosts outside its pin: %s" % (rel, sorted(seen - allowed))


def test_no_module_hard_codes_a_url_outside_the_pinned_network_modules():
    bad = []
    for p in _py():
        if _rel(p) in NETWORK_MODULES:
            continue
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.search(r"https?://", node.value):
                bad.append("%s: %s" % (_rel(p), node.value[:60]))
    # SARIF's schema URI is a format constant, not a destination
    bad = [b for b in bad if "json.schemastore.org/sarif-2.1.0.json" not in b]
    assert bad == [], bad


def test_the_write_surface_and_process_surface_do_not_overlap_with_the_network():
    """Belt and braces: the module that starts git never imports a network library."""
    tree = ast.parse((GUARD_DIR / "gitutil.py").read_text(encoding="utf-8"))
    assert not _banned_hits(imported_modules(tree), BANNED_NET)
