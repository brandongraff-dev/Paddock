"""Safe YAML -> validated ``Invariant`` + a canonical, content-addressed digest."""
from __future__ import annotations

import hashlib
import json
from typing import Any

import yaml
from pydantic import ValidationError

from .model import Invariant

MAX_BYTES = 64 * 1024
MAX_DEPTH = 12


class ParseError(ValueError):
    """The document is not a valid invariant. ``problems`` lists each issue with its path."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


def _depth(node: Any, d: int = 0) -> int:
    if isinstance(node, dict):
        return max([d] + [_depth(v, d + 1) for v in node.values()])
    if isinstance(node, list):
        return max([d] + [_depth(v, d + 1) for v in node])
    return d


def load_document(text: str) -> Any:
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise ParseError([f"document larger than {MAX_BYTES} bytes"])
    try:
        # Anchors/aliases are how YAML bombs are made; invariants never need them.
        if any(isinstance(e, yaml.AliasEvent) for e in yaml.parse(text, Loader=yaml.SafeLoader)):
            raise ParseError(["YAML aliases are not allowed"])
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ParseError([f"invalid YAML: {str(exc).splitlines()[0] if str(exc) else 'error'}"]) \
            from exc
    if not isinstance(doc, dict):
        raise ParseError(["document must be a mapping"])
    if _depth(doc) > MAX_DEPTH:
        raise ParseError([f"document nested deeper than {MAX_DEPTH} levels"])
    return doc


def parse_invariant(text: str) -> Invariant:
    doc = load_document(text)
    try:
        return Invariant.model_validate(doc)
    except ValidationError as exc:
        problems = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "(document)"
            problems.append(f"{loc}: {err['msg']}")
        raise ParseError(problems) from exc


def canonical_json(inv: Invariant) -> str:
    """Defaults included and set-like lists sorted, so equal meaning gives equal bytes."""
    data = inv.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(inv: Invariant) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(inv).encode("ascii")).hexdigest()
