"""Parser dispatch by lockfile name.

Given a path (or bare filename) and its content, pick the right ecosystem
parser and return normalised component records. go.mod is consumed alongside
go.sum when both are present in the same scan.
"""
from __future__ import annotations

import os
from typing import Any, Callable

from . import cargo, go, maven, npm, python, ruby

# filename (lowercased basename) -> parser callable(content) -> list[component]
_DISPATCH: dict[str, Callable[[str], list[dict[str, Any]]]] = {
    "package-lock.json": npm.parse_package_lock,
    "npm-shrinkwrap.json": npm.parse_package_lock,
    "yarn.lock": npm.parse_yarn_lock,
    "pnpm-lock.yaml": npm.parse_pnpm_lock,
    "requirements.txt": python.parse_requirements,
    "poetry.lock": python.parse_poetry_lock,
    "pipfile.lock": python.parse_pipfile_lock,
    "cargo.lock": cargo.parse_cargo_lock,
    "pom.xml": maven.parse_pom,
    "gemfile.lock": ruby.parse_gemfile_lock,
}

# Everything we know how to read (for directory scanning / UI hints).
SUPPORTED_FILENAMES = tuple(_DISPATCH.keys()) + ("go.sum", "go.mod")


def basename(path: str) -> str:
    return os.path.basename((path or "").strip()).lower()


def is_supported(path: str) -> bool:
    name = basename(path)
    return name in _DISPATCH or name in ("go.sum", "go.mod")


def parse_one(path: str, content: str) -> list[dict[str, Any]]:
    """Parse a single lockfile. go.sum is parsed without its go.mod here;
    use :func:`parse_files` to pair them."""
    name = basename(path)
    if name == "go.sum":
        return go.parse_go(content)
    if name == "go.mod":
        return []  # go.mod alone carries ranges, not a resolved lock
    fn = _DISPATCH.get(name)
    if fn is None:
        return []
    try:
        return fn(content)
    except Exception:
        # Robust-to-malformed: never let one bad file crash a scan.
        return []


def parse_files(files: dict[str, str]) -> list[dict[str, Any]]:
    """Parse a {path: content} map, pairing go.sum with a sibling go.mod.

    Returns the concatenated component list across every recognised file.
    """
    if not isinstance(files, dict):
        return []
    # index go.mod contents by directory so a go.sum can find its directs
    gomods: dict[str, str] = {}
    for path, content in files.items():
        if basename(path) == "go.mod" and isinstance(content, str):
            gomods[os.path.dirname((path or "").strip())] = content

    out: list[dict[str, Any]] = []
    for path, content in files.items():
        if not isinstance(content, str):
            continue
        name = basename(path)
        try:
            if name == "go.sum":
                go_mod = gomods.get(os.path.dirname((path or "").strip()))
                out.extend(go.parse_go(content, go_mod))
            elif name == "go.mod":
                continue
            else:
                out.extend(parse_one(path, content))
        except Exception:
            continue
    return out
