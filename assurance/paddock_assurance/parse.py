"""Safe YAML -> validated ``Invariant`` + a canonical, content-addressed digest."""
from __future__ import annotations

import hashlib
import json
from typing import Any

import yaml
from pydantic import ValidationError

from . import hostexpr as X
from .model import ASSERT_PROBLEMS, PLACEHOLDER_REFUSED, Invariant

MAX_BYTES = 64 * 1024
MAX_DEPTH = 14      # a host-config assert nests two document levels per all/any/not (6 levels allowed)
# A flow collection (``[`` / ``{``) nests without indentation, so a tiny document can be thousands
# of levels deep, and PyYAML's cost on that is superlinear (about 2 ms per level before it finally
# raises RecursionError). The post-parse ``_depth`` check can never help, so the depth is bounded
# by a linear character scan *before* the parser sees the text. The cap is a little above
# MAX_DEPTH because a bracket inside a quoted string is counted too (the scan is deliberately
# dumb, so unbalanced brackets in free text can at worst make a pathological document fail).
MAX_FLOW_DEPTH = MAX_DEPTH + 4


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


def _check_flow_nesting(text: str) -> None:
    depth = 0
    for ch in text:
        if ch == "[" or ch == "{":
            depth += 1
            if depth > MAX_FLOW_DEPTH:
                raise ParseError([f"document nested deeper than {MAX_DEPTH} levels"])
        elif (ch == "]" or ch == "}") and depth:
            depth -= 1


def load_document(text: str) -> Any:
    if not isinstance(text, str):
        raise ParseError(["document must be text"])
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise ParseError([f"document larger than {MAX_BYTES} bytes"])
    _check_flow_nesting(text)
    try:
        # Anchors/aliases are how YAML bombs are made; invariants never need them.
        if any(isinstance(e, yaml.AliasEvent) for e in yaml.parse(text, Loader=yaml.SafeLoader)):
            raise ParseError(["YAML aliases are not allowed"])
        doc = yaml.safe_load(text)
    except ParseError:
        raise
    except yaml.YAMLError as exc:
        raise ParseError([f"invalid YAML: {str(exc).splitlines()[0] if str(exc) else 'error'}"]) \
            from exc
    except RecursionError as exc:      # block nesting the scan above cannot see (``- - - -``)
        raise ParseError([f"document nested deeper than {MAX_DEPTH} levels"]) from exc
    except Exception as exc:           # a parser must never leak anything but ParseError
        raise ParseError([f"invalid YAML: {type(exc).__name__}"]) from exc
    if not isinstance(doc, dict):
        raise ParseError(["document must be a mapping"])
    try:
        too_deep = _depth(doc) > MAX_DEPTH
    except RecursionError:
        too_deep = True
    if too_deep:
        raise ParseError([f"document nested deeper than {MAX_DEPTH} levels"])
    return doc


def _assert_message(message: str) -> str:
    """A collected assert problem as the author reads it. Most messages already start ``assert`` (``assert: position
    8: ...``, ``assert.all[0]: ...``): those are kept, anything else gets the ``assert: `` label."""
    return message if message.startswith("assert") else f"assert: {message}"


def parse_invariant(text: str) -> Invariant:
    """Parse and validate. EVERY problem is reported in one ``ParseError`` (P2.1 D36): a bad ``assert:`` is collected
    and listed first, then the field errors, instead of hiding them. Valid documents are unaffected (same model, same
    digest); a document with a bad assert never yields an ``Invariant``."""
    doc = load_document(text)
    context: dict[str, list] = {ASSERT_PROBLEMS: []}
    try:
        inv = Invariant.model_validate(doc, context=context)
    except ValidationError as exc:
        problems = [_assert_message(m) for _, m in context[ASSERT_PROBLEMS]]
        for err in exc.errors():
            if not err["loc"] and err["msg"] == f"Value error, {PLACEHOLDER_REFUSED}":
                continue          # our own refusal of the placeholder (exact match: never an author's text)
            loc = ".".join(str(p) for p in err["loc"]) or "(document)"
            problems.append(f"{loc}: {err['msg']}")
        raise ParseError(problems) from exc
    if context[ASSERT_PROBLEMS]:       # unreachable while _shape refuses the placeholder; never hand it back anyway
        raise ParseError([_assert_message(m) for _, m in context[ASSERT_PROBLEMS]])
    return inv


def canonical_json(inv: Invariant) -> str:
    """Defaults included and set-like lists sorted, so equal meaning gives equal bytes."""
    data = inv.model_dump(mode="json", by_alias=True, exclude_none=True)
    if inv.expr is not None:
        # host-config: the digest covers the structured canonical tree (sorted children, collapsed
        # singletons, normalised literals), never the author's text, spacing or ordering.
        data["assert"] = X.to_json(inv.expr)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(inv: Invariant) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(inv).encode("ascii")).hexdigest()
