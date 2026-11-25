"""The host-config predicate language: tokenizer, parser, type-checker and canonical form.

``assert:`` of a host-config invariant is a predicate string or a mapping ``{all|any|not: ...}``::

    pred   := path OP literal | path 'in' list | path 'subset_of' list | 'count(' path ')' CMP INT
    path   := ident ( '.' ident | '(' INT ')' )*          e.g. host.listener(22).exists
    OP     := == != < <= > >=
    literal:= "string" | 'string' | INT | true | false

Hand-written on purpose: no ``eval``, no regular expressions (so no backtracking), every input
bounded (<= 200 characters per predicate, depth <= 6, <= 64 leaves, lists <= 64 items). Anything
that is not exactly in the grammar is an ``ExprError``; nothing is guessed.

The parser returns the **canonical tree**: children of ``all`` / ``any`` sorted by their canonical
JSON, single-child ``all`` / ``any`` collapsed, set literals sorted and de-duplicated, case-folded
strings lower-cased. Whitespace, quoting style and sibling order therefore never reach the digest,
while every field, parameter, operator, literal and ``not`` does. The evaluator walks this very
tree, so a witness ``clause`` index names the same position the digest covers.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Optional, Union

from . import hostfields as HF

MAX_PRED_CHARS = 200
MAX_DEPTH = 6              # combinator levels (all / any / not) between the root and any leaf
MAX_LEAVES = 64
MAX_LIST = 64
MAX_TOKENS = 120
MAX_INT = 10 ** 9
MAX_STR = 128
MAX_DIGITS = 10

_LOWER = "abcdefghijklmnopqrstuvwxyz_"
_DIGITS = "0123456789"
_IDENT_REST = _LOWER + _DIGITS
_SPACE = " \t\r\n"

SCALAR_OPS = {
    "bool": ("==", "!="),
    "int": ("==", "!=", "<", "<=", ">", ">=", "in"),
    "str": ("==", "!=", "in"),
    "set<str>": ("==", "!=", "subset_of"),
    "set<cidr>": ("==", "!=", "subset_of"),
}
COUNT_OPS = ("==", "!=", "<", "<=", ">", ">=")


class ExprError(ValueError):
    """A predicate is not valid. The message names the position and what was expected."""


# --------------------------------------------------------------------------------------------
# AST (the canonical tree)

@dataclass(frozen=True)
class Leaf:
    field: str                       # registry name, without parameters
    params: tuple[int, ...]
    op: str                          # == != < <= > >= in subset_of
    value: Any                       # bool | int | str | tuple (sorted, de-duplicated)
    count: bool = False              # True: ``count(field) op value``


@dataclass(frozen=True)
class Group:
    kind: str                        # "all" | "any"
    children: tuple["Node", ...]


@dataclass(frozen=True)
class Not:
    child: "Node"


Node = Union[Leaf, Group, Not]


# --------------------------------------------------------------------------------------------
# tokenizer

@dataclass(frozen=True)
class Tok:
    kind: str       # ident | int | str | op | ( ) [ ] , . | end
    value: Any
    pos: int


def tokenize(text: str) -> list[Tok]:
    if not isinstance(text, str):
        raise ExprError("a predicate must be text")
    if len(text) > MAX_PRED_CHARS:
        raise ExprError(f"predicate longer than {MAX_PRED_CHARS} characters")
    out: list[Tok] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in _SPACE:
            i += 1
            continue
        if len(out) >= MAX_TOKENS:
            raise ExprError(f"predicate has more than {MAX_TOKENS} tokens")
        if c in _LOWER:
            j = i + 1
            while j < n and text[j] in _IDENT_REST:
                j += 1
            out.append(Tok("ident", text[i:j], i))
            i = j
        elif c in _DIGITS or (c == "-" and i + 1 < n and text[i + 1] in _DIGITS):
            j = i + 1
            while j < n and text[j] in _DIGITS:
                j += 1
            digits = text[i:j].lstrip("-")
            if len(digits) > MAX_DIGITS:
                raise ExprError(f"position {i}: number too long")
            if j < n and text[j] in _IDENT_REST + ".":
                raise ExprError(f"position {j}: unexpected {text[j]!r} after a number "
                                "(floats and suffixes are not supported)")
            out.append(Tok("int", int(text[i:j]), i))
            i = j
        elif c == '"' or c == "'":
            j = i + 1
            buf: list[str] = []
            while True:
                if j >= n:
                    raise ExprError(f"position {i}: unterminated string")
                d = text[j]
                if d == c:
                    break
                if d == "\\":
                    if j + 1 >= n or text[j + 1] not in ("\\", '"', "'"):
                        raise ExprError(f"position {j}: only \\\\, \\\" and \\' are valid escapes")
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if not (" " <= d <= "~"):
                    raise ExprError(f"position {j}: strings are printable ASCII only")
                buf.append(d)
                j += 1
                if len(buf) > MAX_STR:
                    raise ExprError(f"position {i}: string longer than {MAX_STR} characters")
            out.append(Tok("str", "".join(buf), i))
            i = j + 1
        elif c in "=!<>":
            two = text[i:i + 2]
            if two in ("==", "!=", "<=", ">="):
                out.append(Tok("op", two, i))
                i += 2
            elif c in "<>":
                out.append(Tok("op", c, i))
                i += 1
            else:
                raise ExprError(f"position {i}: {c!r} is not an operator (use == or !=)")
        elif c in "()[],.":
            out.append(Tok(c, c, i))
            i += 1
        else:
            raise ExprError(f"position {i}: unexpected character {c!r}")
    out.append(Tok("end", None, n))
    return out


# --------------------------------------------------------------------------------------------
# parser (one predicate)

class _P:
    def __init__(self, text: str) -> None:
        self.toks = tokenize(text)
        self.i = 0

    @property
    def cur(self) -> Tok:
        return self.toks[self.i]

    def take(self, kind: str, what: str) -> Tok:
        t = self.cur
        if t.kind != kind:
            raise ExprError(f"position {t.pos}: expected {what}, found {_show(t)}")
        self.i += 1
        return t

    def accept(self, kind: str, value: Any = None) -> Optional[Tok]:
        t = self.cur
        if t.kind == kind and (value is None or t.value == value):
            self.i += 1
            return t
        return None

    # path := ident ( '.' ident | '(' INT ')' )*
    def path(self) -> tuple[list[str], tuple[int, ...], int, int]:
        """``(segments, params, param_after, start)``; ``param_after`` is -1 without parameters."""
        start = self.cur.pos
        segs = [str(self.take("ident", "a field name").value)]
        params: tuple[int, ...] = ()
        after = -1
        while True:
            if self.accept("."):
                segs.append(str(self.take("ident", "a name after '.'").value))
            elif self.cur.kind == "(":
                if params:
                    raise ExprError(f"position {self.cur.pos}: a field takes at most one parameter list")
                self.i += 1
                vals = [int(self.take("int", "a number").value)]
                while self.accept(","):
                    vals.append(int(self.take("int", "a number").value))
                self.take(")", "')'")
                params = tuple(vals)
                after = len(segs) - 1
            else:
                return segs, params, after, start

    def literal(self) -> Any:
        t = self.cur
        if t.kind == "int" or t.kind == "str":
            self.i += 1
            return t.value
        if t.kind == "ident" and t.value in ("true", "false"):
            self.i += 1
            return t.value == "true"
        if t.kind == "[":
            self.i += 1
            items: list[Any] = []
            if self.accept("]"):
                return items
            while True:
                it = self.cur
                if it.kind not in ("int", "str"):
                    raise ExprError(f"position {it.pos}: lists hold strings or numbers, found {_show(it)}")
                self.i += 1
                items.append(it.value)
                if len(items) > MAX_LIST:
                    raise ExprError(f"list longer than {MAX_LIST} items")
                if self.accept(","):
                    continue
                self.take("]", "',' or ']'")
                return items
        raise ExprError(f"position {t.pos}: expected a value (string, number, true, false or a list), "
                        f"found {_show(t)}")

    def predicate(self) -> Leaf:
        if self.cur.kind == "ident" and self.cur.value == "count" and self.toks[self.i + 1].kind == "(":
            self.i += 2
            segs, params, after, start = self.path()
            self.take(")", "')' closing count(")
            op_t = self.take("op", "a comparison operator")
            lit_t = self.take("int", "a whole number after the comparison")
            self.take("end", "end of the predicate")
            return _typed_count(segs, params, after, start, str(op_t.value), int(lit_t.value), op_t.pos)
        segs, params, after, start = self.path()
        t = self.cur
        if t.kind == "op":
            op = str(t.value)
            self.i += 1
        elif t.kind == "ident" and t.value in ("in", "subset_of"):
            op = str(t.value)
            self.i += 1
        else:
            raise ExprError(f"position {t.pos}: expected an operator (== != < <= > >= in subset_of), "
                            f"found {_show(t)}")
        lit_pos = self.cur.pos
        value = self.literal()
        self.take("end", "end of the predicate")
        return _typed_leaf(segs, params, after, start, op, value, lit_pos)


def _show(t: Tok) -> str:
    if t.kind == "end":
        return "the end of the predicate"
    return repr(t.value)


# --------------------------------------------------------------------------------------------
# type-checking against the registry

def _lookup(segs: list[str], params: tuple[int, ...], after: int, start: int) -> HF.FieldSpec:
    name = ".".join(segs)
    spec = HF.REGISTRY.get(name)
    if spec is None:
        near = sorted(k for k in HF.REGISTRY if k.rsplit(".", 1)[0] == name.rsplit(".", 1)[0])[:4]
        hint = f" (did you mean {', '.join(near)}?)" if near else ""
        raise ExprError(f"position {start}: unknown field {name!r}{hint}")
    if spec.param is None:
        if params:
            raise ExprError(f"position {start}: {name} takes no parameter")
        return spec
    if not params:
        raise ExprError(f"position {start}: {name} needs a parameter, e.g. {_example(spec)}")
    if len(params) != 1:
        raise ExprError(f"position {start}: {name} takes exactly one parameter")
    if after != spec.param_after:
        raise ExprError(f"position {start}: the parameter of {name} goes right after "
                        f"{'.'.join(segs[:spec.param_after + 1])!r}")
    p = params[0]
    if not (spec.param.lo <= p <= spec.param.hi):
        raise ExprError(f"position {start}: {spec.param.name} must be between {spec.param.lo} "
                        f"and {spec.param.hi}")
    return spec


def _example(spec: HF.FieldSpec) -> str:
    return spec.display((spec.param.lo,) if spec.param else ())


def _norm_str(spec: HF.FieldSpec, v: Any, pos: int) -> str:
    if not isinstance(v, str) or not v:
        raise ExprError(f"position {pos}: expected a non-empty string")
    s = v.lower()
    if spec.choices is not None:
        s = spec.aliases.get(s, s)
        if s not in spec.choices:
            raise ExprError(f"position {pos}: {v!r} is not a value of {spec.name} "
                            f"(one of {', '.join(sorted(spec.choices))})")
    return s


def _norm_cidr(v: Any, pos: int) -> str:
    if not isinstance(v, str):
        raise ExprError(f"position {pos}: expected a CIDR string such as \"10.0.0.0/8\"")
    try:
        return str(ipaddress.ip_network(v, strict=True))
    except ValueError:
        raise ExprError(f"position {pos}: {v!r} is not a valid CIDR (host bits must be zero)") from None


def _norm_name(v: Any, pos: int) -> str:
    if not isinstance(v, str) or not v or len(v) > MAX_STR:
        raise ExprError(f"position {pos}: expected a non-empty name")
    return v


def _int(v: Any, pos: int) -> int:
    if type(v) is not int:
        raise ExprError(f"position {pos}: expected a whole number")
    if abs(v) > MAX_INT:
        raise ExprError(f"position {pos}: number out of range")
    return v


def _typed_leaf(segs: list[str], params: tuple[int, ...], after: int, start: int, op: str,
                value: Any, pos: int) -> Leaf:
    spec = _lookup(segs, params, after, start)
    typ = spec.type
    if op not in SCALAR_OPS[typ]:
        raise ExprError(f"position {start}: {spec.name} is a {typ}; operator {op!r} is not allowed "
                        f"(use {', '.join(SCALAR_OPS[typ])})")
    if typ == "bool":
        if type(value) is not bool:
            raise ExprError(f"position {pos}: {spec.name} is a bool; compare with true or false")
        v: Any = value
    elif typ == "int":
        if op == "in":
            if not isinstance(value, list) or not value:
                raise ExprError(f"position {pos}: 'in' needs a non-empty list")
            v = tuple(sorted({_int(x, pos) for x in value}))
        else:
            v = _int(value, pos)
    elif typ == "str":
        if op == "in":
            if not isinstance(value, list) or not value:
                raise ExprError(f"position {pos}: 'in' needs a non-empty list")
            v = tuple(sorted({_norm_str(spec, x, pos) for x in value}))
        else:
            if isinstance(value, list):
                raise ExprError(f"position {pos}: {op} compares with one value; use 'in' for a list")
            v = _norm_str(spec, value, pos)
    else:   # set<str> / set<cidr>
        if not isinstance(value, list):
            raise ExprError(f"position {pos}: {op} on a set needs a list, e.g. [\"a\", \"b\"]")
        if typ == "set<cidr>":
            v = tuple(sorted({_norm_cidr(x, pos) for x in value}))
        else:
            v = tuple(sorted({_norm_name(x, pos) for x in value}))
    return Leaf(spec.name, params, op, v)


def _typed_count(segs: list[str], params: tuple[int, ...], after: int, start: int, op: str,
                 value: int, pos: int) -> Leaf:
    spec = _lookup(segs, params, after, start)
    if not spec.type.startswith("set<"):
        raise ExprError(f"position {start}: count() needs a set field, {spec.name} is a {spec.type}")
    if op not in COUNT_OPS:
        raise ExprError(f"position {pos}: count() compares with == != < <= > >=")
    if value < 0 or value > MAX_INT:
        raise ExprError(f"position {pos}: count() compares with a whole number >= 0")
    return Leaf(spec.name, params, op, value, True)


def parse_predicate(text: str) -> Leaf:
    """One predicate string to its (type-checked, normalised) leaf."""
    return _P(text).predicate()


# --------------------------------------------------------------------------------------------
# the document level: strings, all / any / not

def _jsonable_leaf(n: Leaf) -> dict[str, Any]:
    d: dict[str, Any] = {"f": n.field, "op": n.op, "v": list(n.value) if isinstance(n.value, tuple)
                         else n.value}
    if n.params:
        d["p"] = list(n.params)
    if n.count:
        d["fn"] = "count"
    return d


def to_json(n: Node) -> Any:
    """The structured canonical form (what the digest covers)."""
    if isinstance(n, Leaf):
        return _jsonable_leaf(n)
    if isinstance(n, Not):
        return {"not": to_json(n.child)}
    return {n.kind: [to_json(c) for c in n.children]}


def _key(n: Node) -> str:
    return json.dumps(to_json(n), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _fmt_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=True)
    return "[" + ", ".join(_fmt_value(x) for x in v) + "]"


def leaf_text(n: Leaf) -> str:
    """The canonical spelling of a predicate, e.g. ``host.listener(22).exists == true``."""
    spec = HF.REGISTRY[n.field]
    path = spec.display(n.params)
    if n.count:
        return f"count({path}) {n.op} {n.value}"
    return f"{path} {n.op} {_fmt_value(n.value)}"


def to_text(n: Node) -> str:
    if isinstance(n, Leaf):
        return leaf_text(n)
    if isinstance(n, Not):
        return f"not({to_text(n.child)})"
    return f"{n.kind}(" + "; ".join(to_text(c) for c in n.children) + ")"


def leaves(n: Node) -> list[Leaf]:
    """Every leaf, left to right."""
    if isinstance(n, Leaf):
        return [n]
    if isinstance(n, Not):
        return leaves(n.child)
    out: list[Leaf] = []
    for c in n.children:
        out.extend(leaves(c))
    return out


def depth(n: Node) -> int:
    if isinstance(n, Leaf):
        return 0
    if isinstance(n, Not):
        return 1 + depth(n.child)
    return 1 + max(depth(c) for c in n.children)


class _Counter:
    def __init__(self) -> None:
        self.leaves = 0


def _node(raw: Any, path: str, level: int, ctr: _Counter) -> Node:
    if level > MAX_DEPTH:
        raise ExprError(f"{path}: nested deeper than {MAX_DEPTH} levels")
    if isinstance(raw, str):
        ctr.leaves += 1
        if ctr.leaves > MAX_LEAVES:
            raise ExprError(f"more than {MAX_LEAVES} predicates")
        try:
            return parse_predicate(raw)
        except ExprError as exc:
            raise ExprError(f"{path}: {exc}") from None
    if isinstance(raw, dict):
        if len(raw) != 1:
            raise ExprError(f"{path}: a mapping must have exactly one key (all, any or not)")
        (key, val), = raw.items()
        if key == "not":
            if isinstance(val, list):
                raise ExprError(f"{path}.not: takes one predicate or mapping, not a list "
                                "(use not: {any: [...]})")
            return Not(_node(val, f"{path}.not", level + 1, ctr))
        if key in ("all", "any"):
            if not isinstance(val, list) or not val:
                raise ExprError(f"{path}.{key}: needs a non-empty list")
            if len(val) > MAX_LEAVES:
                raise ExprError(f"{path}.{key}: more than {MAX_LEAVES} items")
            kids = tuple(_node(c, f"{path}.{key}[{i}]", level + 1, ctr) for i, c in enumerate(val))
            return _group(str(key), kids)
        raise ExprError(f"{path}: unknown key {key!r} (use all, any or not, or write a predicate string)")
    raise ExprError(f"{path}: expected a predicate string or a mapping with all, any or not")


def _group(kind: str, kids: tuple[Node, ...]) -> Node:
    if len(kids) == 1:
        return kids[0]
    return Group(kind, tuple(sorted(kids, key=_key)))


def _canon(n: Node) -> Node:
    """Re-sort children bottom-up (children of a child may have been collapsed after sorting)."""
    if isinstance(n, Leaf):
        return n
    if isinstance(n, Not):
        return Not(_canon(n.child))
    return _group(n.kind, tuple(_canon(c) for c in n.children))


def parse_assertion(raw: Any) -> Node:
    """The value of ``assert:`` (a predicate string, or ``{all|any|not: ...}``) to the canonical tree."""
    ctr = _Counter()
    tree = _canon(_node(raw, "assert", 0, ctr))
    if depth(tree) > MAX_DEPTH:      # defensive: _node already bounds the raw nesting
        raise ExprError(f"assert: nested deeper than {MAX_DEPTH} levels")
    return tree


__all__ = ["ExprError", "Group", "Leaf", "Node", "Not", "depth", "leaf_text", "leaves",
           "parse_assertion", "parse_predicate", "to_json", "to_text", "tokenize"]
