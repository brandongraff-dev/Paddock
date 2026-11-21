"""Python-ecosystem lockfile parsers: requirements.txt, poetry.lock,
Pipfile.lock. Emits ecosystem ``PyPI``.

Input is untrusted DATA (text / toml / json) -- parsed, never executed.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ._util import component, dedupe

ECOSYSTEM = "PyPI"

try:  # Python 3.11+
    import tomllib as _toml
except Exception:  # pragma: no cover
    _toml = None  # type: ignore


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------
_REQ_PIN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(==|===)\s*([^;\s#]+)")
_REQ_RANGE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(~=|>=|<=|>|<|!=|\^)")


def parse_requirements(content: str) -> list[dict[str, Any]]:
    if not isinstance(content, str):
        return []
    out: list[dict[str, Any]] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # drop inline env markers / comments
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line or line.lower().startswith(("http:", "https:", "git+", "file:")):
            continue
        m = _REQ_PIN.match(line)
        if m:
            name, version = m.group(1), m.group(4).strip()
            out.append(component(ECOSYSTEM, name, version, direct=True, depth=0))
            continue
        rng = _REQ_RANGE.match(line)
        if rng:
            # unpinned range: record name with no resolved version; the pinning
            # risk detector reads metadata.spec to flag it.
            c = component(ECOSYSTEM, rng.group(1), "", direct=True, depth=0)
            c["metadata"] = {"spec": line, "unpinned": True}
            out.append(c)
    return dedupe([c for c in out if c.get("version")]) + [
        c for c in out if not c.get("version")
    ]


# ---------------------------------------------------------------------------
# poetry.lock  (TOML: [[package]] arrays with name/version/category)
# ---------------------------------------------------------------------------
def parse_poetry_lock(content: str) -> list[dict[str, Any]]:
    if _toml is None:
        return []
    try:
        data = _toml.loads(content)
    except Exception:
        return []
    pkgs = data.get("package")
    if not isinstance(pkgs, list):
        return []
    # Build reverse graph to infer transitive depth.
    versions: dict[str, str] = {}
    edges: dict[str, list[str]] = {}
    for p in pkgs:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "")
        version = str(p.get("version") or "")
        if not name or not version:
            continue
        versions[name] = version
        deps = p.get("dependencies")
        children: list[str] = []
        if isinstance(deps, dict):
            children = [str(k) for k in deps.keys()]
        edges[name] = children
    if not versions:
        return []
    from ._util import resolve_graph
    return dedupe(resolve_graph(ECOSYSTEM, versions, edges, roots=None))


# ---------------------------------------------------------------------------
# Pipfile.lock  (JSON: default / develop maps of name -> {version: "==x"})
# ---------------------------------------------------------------------------
def parse_pipfile_lock(content: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[dict[str, Any]] = []
    for section, direct in (("default", True), ("develop", True)):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version") or "").lstrip("=").strip()
            if not version:
                continue
            out.append(component(ECOSYSTEM, name, version, direct=direct, depth=0))
    return dedupe(out)
