"""Shared helpers for lockfile parsers.

Everything here operates on already-parsed, in-memory DATA. No parser in this
package ever executes, imports, or evaluates the file it reads.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Iterable


def component(
    ecosystem: str,
    name: str,
    version: str,
    *,
    direct: bool = True,
    depth: int = 0,
    paths: list[Any] | None = None,
) -> dict[str, Any]:
    """Normalised component record emitted by every parser."""
    return {
        "ecosystem": ecosystem,
        "name": (name or "").strip(),
        "version": (version or "").strip(),
        "direct": bool(direct),
        "depth": int(depth),
        "paths": paths or [],
    }


def resolve_graph(
    ecosystem: str,
    versions: dict[str, str],
    edges: dict[str, Iterable[str]],
    roots: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Turn a dependency adjacency into component records.

    ``versions``  maps node-key -> version.
    ``edges``     maps parent node-key -> iterable of child node-keys.
    ``roots``     direct dependencies; if ``None`` we fall back to the set of
                  nodes that are never referenced as anyone's child.

    Depth is the shortest hop-count from a root (roots are depth 0). ``paths``
    lists the immediate parents (who pulls the component in), capped so a
    pathological graph cannot blow up memory.
    """
    nodes = set(versions)
    # normalise edges to only reference known nodes
    adj: dict[str, set[str]] = {n: set() for n in nodes}
    parents: dict[str, set[str]] = {n: set() for n in nodes}
    for parent, children in edges.items():
        if parent not in nodes:
            continue
        for child in children or []:
            if child in nodes and child != parent:
                adj[parent].add(child)
                parents[child].add(parent)

    if roots is None:
        root_set = {n for n in nodes if not parents[n]}
    else:
        root_set = {r for r in roots if r in nodes}
    if not root_set:
        # Fully cyclic / no clear roots: treat everything as a root so we still
        # emit every component rather than dropping the graph.
        root_set = set(nodes)

    depth: dict[str, int] = {}
    queue: deque[str] = deque()
    for r in sorted(root_set):
        depth[r] = 0
        queue.append(r)
    while queue:
        cur = queue.popleft()
        for child in sorted(adj[cur]):
            nd = depth[cur] + 1
            if child not in depth or nd < depth[child]:
                depth[child] = nd
                queue.append(child)
    # Any node unreachable from roots (e.g. isolated in a cycle) gets depth 1.
    out: list[dict[str, Any]] = []
    for node in sorted(nodes):
        d = depth.get(node, 1)
        paths = sorted(parents[node])[:16]
        out.append(
            component(
                ecosystem,
                _name_of(node),
                versions[node],
                direct=(node in root_set),
                depth=d,
                paths=paths,
            )
        )
    return out


def _name_of(node_key: str) -> str:
    """A node key may be ``name`` or ``name@version``; return the name part."""
    if "@" in node_key and not node_key.startswith("@"):
        return node_key.rsplit("@", 1)[0]
    if node_key.startswith("@") and node_key.count("@") >= 2:
        # scoped: @scope/name@version
        return node_key.rsplit("@", 1)[0]
    return node_key


def dedupe(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicate (ecosystem,name,version); keep the shallowest/direct."""
    best: dict[tuple[str, str, str], dict[str, Any]] = {}
    for c in components:
        if not c.get("name") or not c.get("version"):
            continue
        key = (c["ecosystem"], c["name"], c["version"])
        cur = best.get(key)
        if cur is None:
            best[key] = c
            continue
        cur["direct"] = cur["direct"] or c["direct"]
        cur["depth"] = min(cur["depth"], c["depth"])
        merged = {tuple(p) if isinstance(p, list) else p for p in cur["paths"]}
        for p in c["paths"]:
            merged.add(tuple(p) if isinstance(p, list) else p)
        cur["paths"] = [list(p) if isinstance(p, tuple) else p for p in merged][:16]
    return list(best.values())
