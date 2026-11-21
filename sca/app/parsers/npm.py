"""npm-ecosystem lockfile parsers: package-lock.json (v1 + v2/v3), yarn.lock,
pnpm-lock.yaml.

All three emit records with ecosystem ``npm``. Input is treated as untrusted
DATA: we json/yaml-load it, never execute it, and skip anything malformed.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ._util import component, dedupe, resolve_graph

ECOSYSTEM = "npm"


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------
def parse_package_lock(content: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    # v2/v3 carry a flat ``packages`` map keyed by install path.
    if isinstance(data.get("packages"), dict):
        return _parse_lock_v2(data)
    if isinstance(data.get("dependencies"), dict):
        return _parse_lock_v1(data["dependencies"])
    return []


def _parse_lock_v2(data: dict[str, Any]) -> list[dict[str, Any]]:
    packages = data["packages"]
    root = packages.get("", {}) if isinstance(packages.get(""), dict) else {}
    direct_names = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = root.get(key)
        if isinstance(block, dict):
            direct_names.update(block.keys())

    out: list[dict[str, Any]] = []
    for path, meta in packages.items():
        if path == "" or not isinstance(meta, dict):
            continue
        name = _name_from_path(path)
        if not name:
            continue
        version = meta.get("version") or ""
        if not version:
            continue
        # depth = how many node_modules segments deep it is installed.
        depth = max(0, path.count("node_modules/") - 1)
        is_direct = depth == 0 and name in direct_names
        out.append(component(
            ECOSYSTEM, name, version,
            direct=is_direct, depth=depth if not is_direct else 0,
            paths=[_parent_from_path(path)] if _parent_from_path(path) else [],
        ))
    return dedupe(out)


def _name_from_path(path: str) -> str:
    # "node_modules/foo" -> "foo"; "node_modules/@scope/bar" -> "@scope/bar";
    # "node_modules/a/node_modules/b" -> "b"
    if "node_modules/" not in path:
        return path
    tail = path.rsplit("node_modules/", 1)[1]
    return tail


def _parent_from_path(path: str) -> str:
    parts = path.split("node_modules/")
    # parts like ["", "a/", "b"] for nested; parent name is parts[-2] trimmed
    if len(parts) >= 3:
        return parts[-2].strip("/")
    return ""


def _parse_lock_v1(deps: dict[str, Any], depth: int = 0, parent: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(deps, dict):
        return out
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version") or ""
        if version:
            out.append(component(
                ECOSYSTEM, name, version,
                direct=(depth == 0), depth=depth,
                paths=[parent] if parent else [],
            ))
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            out.extend(_parse_lock_v1(nested, depth + 1, name))
    return dedupe(out)


# ---------------------------------------------------------------------------
# yarn.lock (v1 classic format)
# ---------------------------------------------------------------------------
_YARN_ENTRY_HEADER = re.compile(r'^(?!\s)(.*?):\s*$')


def parse_yarn_lock(content: str) -> list[dict[str, Any]]:
    if not isinstance(content, str):
        return []
    versions: dict[str, str] = {}
    edges: dict[str, list[str]] = {}
    descriptor_to_node: dict[str, str] = {}

    blocks = _split_yarn_blocks(content)
    parsed_blocks: list[tuple[list[str], str, list[str]]] = []
    for header_descriptors, body in blocks:
        version = _yarn_field(body, "version")
        if not version:
            continue
        names = {_descriptor_name(d) for d in header_descriptors if _descriptor_name(d)}
        if not names:
            continue
        name = sorted(names)[0]
        node = f"{name}@{version}"
        versions[node] = version
        for d in header_descriptors:
            descriptor_to_node[d] = node
        dep_descriptors = _yarn_dependencies(body)
        parsed_blocks.append((header_descriptors, node, dep_descriptors))

    for _hdr, node, dep_descriptors in parsed_blocks:
        children: list[str] = []
        for dd in dep_descriptors:
            child = descriptor_to_node.get(dd)
            if child:
                children.append(child)
        edges[node] = children

    if not versions:
        return []
    return dedupe(resolve_graph(ECOSYSTEM, versions, edges, roots=None))


def _split_yarn_blocks(content: str) -> list[tuple[list[str], str]]:
    blocks: list[tuple[list[str], str]] = []
    lines = content.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            descriptors = _parse_yarn_header(header)
            body_lines: list[str] = []
            i += 1
            while i < n and (not lines[i].strip() or lines[i].startswith((" ", "\t"))):
                body_lines.append(lines[i])
                i += 1
            blocks.append((descriptors, "\n".join(body_lines)))
        else:
            i += 1
    return blocks


def _parse_yarn_header(header: str) -> list[str]:
    out: list[str] = []
    for part in header.split(","):
        d = part.strip().strip('"').strip()
        if d:
            out.append(d)
    return out


def _descriptor_name(descriptor: str) -> str:
    # "left-pad@^1.0.0" -> "left-pad"; "@scope/pkg@^1" -> "@scope/pkg"
    d = descriptor.strip().strip('"')
    if d.startswith("@"):
        at = d.find("@", 1)
        return d[:at] if at != -1 else d
    at = d.find("@")
    return d[:at] if at != -1 else d


def _yarn_field(body: str, field: str) -> str:
    for line in body.splitlines():
        s = line.strip()
        if s.startswith(field + " ") or s.startswith(field + ":"):
            val = s.split(None, 1)[1] if " " in s else s.split(":", 1)[1]
            return val.strip().strip('"')
    return ""


def _yarn_dependencies(body: str) -> list[str]:
    out: list[str] = []
    lines = body.splitlines()
    in_deps = False
    deps_indent = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip())
        if stripped in ("dependencies:", "optionalDependencies:"):
            in_deps = True
            deps_indent = indent
            continue
        if in_deps:
            if indent <= (deps_indent or 0):
                in_deps = False
                continue
            # "left-pad "^1.0.0""
            m = re.match(r'^"?([^"\s]+)"?\s+"?([^"]+)"?$', stripped)
            if m:
                out.append(f"{m.group(1)}@{m.group(2)}")
    return out


# ---------------------------------------------------------------------------
# pnpm-lock.yaml
# ---------------------------------------------------------------------------
def parse_pnpm_lock(content: str) -> list[dict[str, Any]]:
    try:
        import yaml  # type: ignore
    except Exception:  # pragma: no cover - pyyaml is a declared dep
        return []
    try:
        data = yaml.safe_load(content)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []

    versions: dict[str, str] = {}
    edges: dict[str, list[str]] = {}

    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            name, version = _pnpm_split_key(key, meta if isinstance(meta, dict) else {})
            if not name or not version:
                continue
            node = f"{name}@{version}"
            versions[node] = version
            children: list[str] = []
            if isinstance(meta, dict):
                for block_key in ("dependencies", "optionalDependencies"):
                    block = meta.get(block_key)
                    if isinstance(block, dict):
                        for dn, dv in block.items():
                            cn, cvv = _pnpm_split_dep(dn, dv)
                            if cn and cvv:
                                children.append(f"{cn}@{cvv}")
            edges[node] = children

    roots = _pnpm_roots(data, versions)
    if not versions:
        return []
    return dedupe(resolve_graph(ECOSYSTEM, versions, edges, roots=roots or None))


def _pnpm_roots(data: dict[str, Any], versions: dict[str, str]) -> list[str]:
    roots: list[str] = []
    importers = data.get("importers")
    sources: list[dict[str, Any]] = []
    if isinstance(importers, dict):
        sources = [v for v in importers.values() if isinstance(v, dict)]
    else:
        sources = [data]
    for src in sources:
        for block_key in ("dependencies", "devDependencies", "optionalDependencies"):
            block = src.get(block_key)
            if isinstance(block, dict):
                for dn, dv in block.items():
                    cn, cvv = _pnpm_split_dep(dn, dv)
                    node = f"{cn}@{cvv}"
                    if node in versions:
                        roots.append(node)
                    elif cn:
                        # match by name if version form differs
                        for vnode in versions:
                            if vnode.rsplit("@", 1)[0] == cn:
                                roots.append(vnode)
                                break
    return roots


def _pnpm_split_dep(name: str, val: Any) -> tuple[str, str]:
    if isinstance(val, dict):
        val = val.get("version", "")
    val = str(val or "")
    # strip peer-suffix like "1.2.3(react@18)"
    val = val.split("(", 1)[0]
    return name, val


def _pnpm_split_key(key: str, meta: dict[str, Any]) -> tuple[str, str]:
    # Formats: "/left-pad/1.0.0", "/left-pad@1.0.0", "left-pad@1.0.0(peer)"
    if isinstance(meta, dict) and meta.get("name") and meta.get("version"):
        return str(meta["name"]), str(meta["version"]).split("(", 1)[0]
    k = key
    if k.startswith("/"):
        k = k[1:]
    k = k.split("(", 1)[0]
    if "@" in k.lstrip("@"):
        # handle scoped "@scope/name@ver" and "name@ver"
        if k.startswith("@"):
            at = k.find("@", 1)
            if at != -1:
                return k[:at], k[at + 1:]
        else:
            name, _, ver = k.rpartition("@")
            if name:
                return name, ver
    if "/" in k:
        # "/left-pad/1.0.0"
        parts = k.rsplit("/", 1)
        return parts[0], parts[1]
    return k, ""
