"""Rust-ecosystem parser: Cargo.lock (TOML). Emits ``crates.io``.

Cargo.lock has ``[[package]]`` arrays with name/version/dependencies. The
root crate(s) are those never referenced as a dependency. Untrusted DATA.
"""
from __future__ import annotations

from typing import Any

from ._util import dedupe, resolve_graph

ECOSYSTEM = "crates.io"

try:  # Python 3.11+
    import tomllib as _toml
except Exception:  # pragma: no cover
    _toml = None  # type: ignore


def parse_cargo_lock(content: str) -> list[dict[str, Any]]:
    if _toml is None:
        return []
    try:
        data = _toml.loads(content)
    except Exception:
        return []
    pkgs = data.get("package")
    if not isinstance(pkgs, list):
        return []
    versions: dict[str, str] = {}
    edges: dict[str, list[str]] = {}
    for p in pkgs:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "")
        version = str(p.get("version") or "")
        if not name or not version:
            continue
        node = name  # Cargo.lock names are unique within a resolution graph
        versions[node] = version
        deps = p.get("dependencies")
        children: list[str] = []
        if isinstance(deps, list):
            for d in deps:
                # dependency entries can be "name" or "name version" or
                # "name version (registry+...)"
                dn = str(d).split(" ", 1)[0]
                if dn:
                    children.append(dn)
        edges[node] = children
    if not versions:
        return []
    return dedupe(resolve_graph(ECOSYSTEM, versions, edges, roots=None))
