"""SCIM filter expressions (RFC 7644 section 3.4.2.2) compiled to parameterised SQL.

Supported: ``eq ne co sw ew gt ge lt le pr``, ``and`` / ``or`` / ``not (...)``,
parentheses, and value-path filters (``emails[type eq "work"]``,
``groups[value eq "..."]``, ``members[value eq "..."]``). Attribute names and
operators are case-insensitive; string comparison is case-insensitive unless
the attribute is ``caseExact`` (``id``, ``externalId``).

Nothing from the filter is ever interpolated into SQL: attribute names are
looked up in a closed per-resource ``Spec`` and values travel as bind
parameters. The parser is bounded (length, depth, term count) so a hostile
filter cannot blow the stack or build a huge query.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

MAX_LEN = 1024
MAX_DEPTH = 8
MAX_TERMS = 20

_OPS = {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}
_TOKEN = re.compile(r'\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<lb>\[)|(?P<rb>\])|(?P<str>"(?:[^"\\]|\\.)*")|(?P<word>[^\s()\[\]"]+))')
_UNSTORABLE = re.compile(r"[\x00\ud800-\udfff]")
_URNS = (
    "urn:ietf:params:scim:schemas:core:2.0:user:",
    "urn:ietf:params:scim:schemas:core:2.0:group:",
)


class FilterError(ValueError):
    """Maps to SCIM ``invalidFilter`` (400)."""


@dataclass(frozen=True)
class Col:
    sql: str                  # trusted SQL expression for the attribute
    kind: str = "string"      # string | bool | datetime
    ci: bool = True           # case-insensitive comparison (strings)


@dataclass(frozen=True)
class Exists:
    """A multi-valued reference: ``sql`` contains ``{p}`` for the bound value
    (e.g. group membership); only ``eq`` / ``ne`` / ``pr`` apply."""

    sql: str
    any_sql: str  # the same without the value condition (for ``pr``)


Spec = dict[str, "Col | Exists"]


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

def _tokens(expr: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    expr = expr.rstrip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise FilterError("cannot tokenise filter")
        kind = m.lastgroup or ""
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, expr: str) -> None:
        if len(expr) > MAX_LEN:
            raise FilterError("filter too long")
        self.t = _tokens(expr)
        self.i = 0
        self.terms = 0

    def peek(self) -> tuple[str, str] | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise FilterError("unexpected end of filter")
        self.i += 1
        return tok

    def word(self, *want: str) -> bool:
        tok = self.peek()
        return tok is not None and tok[0] == "word" and tok[1].lower() in want

    def parse(self) -> Any:
        node = self.or_expr(0)
        if self.peek() is not None:
            raise FilterError("unexpected trailing input")
        return node

    def or_expr(self, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise FilterError("filter too deeply nested")
        node = self.and_expr(depth)
        while self.word("or"):
            self.take()
            node = ("or", node, self.and_expr(depth))
        return node

    def and_expr(self, depth: int) -> Any:
        node = self.unary(depth)
        while self.word("and"):
            self.take()
            node = ("and", node, self.unary(depth))
        return node

    def unary(self, depth: int) -> Any:
        if self.word("not"):
            self.take()
            if (self.peek() or ("", ""))[0] != "lp":
                raise FilterError("'not' needs parentheses")
            return ("not", self.group(depth))
        if (self.peek() or ("", ""))[0] == "lp":
            return self.group(depth)
        return self.atom()

    def group(self, depth: int) -> Any:
        self.take()  # (
        node = self.or_expr(depth + 1)
        if self.take()[0] != "rp":
            raise FilterError("missing ')'")
        return node

    def atom(self) -> Any:
        kind, attr = self.take()
        if kind != "word":
            raise FilterError("expected an attribute name")
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise FilterError("filter has too many terms")
        if (self.peek() or ("", ""))[0] == "lb":  # attr[ valFilter ] (.sub)?
            self.take()
            sub = self.or_expr(1)
            if self.take()[0] != "rb":
                raise FilterError("missing ']'")
            tail = None
            nxt = self.peek()
            if nxt and nxt[0] == "word" and nxt[1].startswith("."):
                tail = self.take()[1][1:]
            return ("valpath", attr, sub, tail)
        nxt = self.peek()
        if nxt is None or nxt[0] != "word":
            raise FilterError("expected an operator")
        op = self.take()[1].lower()
        if op == "pr":
            return ("pr", attr)
        if op not in _OPS:
            raise FilterError(f"unsupported operator {op!r}")
        vk, vv = self.take()
        if vk == "str":
            try:
                value: Any = json.loads(vv)
            except ValueError as exc:
                raise FilterError("bad string literal") from exc
            if isinstance(value, str) and _UNSTORABLE.search(value):
                # NUL and lone surrogates cannot be sent to Postgres (they would be a 500)
                raise FilterError("string literal contains an unsupported character")
        elif vk == "word" and vv.lower() in ("true", "false"):
            value = vv.lower() == "true"
        elif vk == "word" and vv.lower() == "null":
            value = None
        elif vk == "word" and re.fullmatch(r"-?\d+(\.\d+)?", vv):
            value = vv
        else:
            raise FilterError("expected a value")
        return ("cmp", attr, op, value)


def parse(expr: str) -> Any:
    return _Parser(expr).parse()


# --------------------------------------------------------------------------- #
# Compiler
# --------------------------------------------------------------------------- #

def _norm_attr(attr: str) -> str:
    low = attr.strip().lower()
    for urn in _URNS:
        if low.startswith(urn):
            return low[len(urn):]
    return low


class _Compiler:
    def __init__(self, spec: Spec, args: list[Any]) -> None:
        self.spec, self.args = spec, args

    def param(self, v: Any) -> str:
        self.args.append(v)
        return f"${len(self.args)}"

    def lookup(self, attr: str, prefix: str = "") -> "Col | Exists":
        name = _norm_attr(attr)
        key = f"{prefix}.{name}" if prefix else name
        hit = self.spec.get(key)
        if hit is None:
            raise FilterError(f"filtering on {attr!r} is not supported")
        return hit

    def node(self, n: Any, prefix: str = "") -> str:
        t = n[0]
        if t == "and":
            return f"({self.node(n[1], prefix)} AND {self.node(n[2], prefix)})"
        if t == "or":
            return f"({self.node(n[1], prefix)} OR {self.node(n[2], prefix)})"
        if t == "not":
            return f"(NOT {self.node(n[1], prefix)})"
        if t == "pr":
            return self.present(self.lookup(n[1], prefix))
        if t == "cmp":
            return self.compare(self.lookup(n[1], prefix), n[2], n[3], n[1])
        if t == "valpath":
            return self.valpath(n)
        raise FilterError("bad filter")  # pragma: no cover

    def valpath(self, n: Any) -> str:
        _, attr, sub, tail = n
        base = _norm_attr(attr)
        if tail:  # emails[type eq "work"].value pr  -> not meaningful as a filter
            raise FilterError("a sub-attribute after a value filter is not supported")
        target = self.spec.get(f"{base}.value")
        if isinstance(target, Exists):
            # set-valued reference: only a single `value <op> x` condition
            if sub[0] != "cmp" or _norm_attr(sub[1]) != "value":
                raise FilterError(f"{attr}[...] supports only a single `value` comparison")
            return self.compare(target, sub[2], sub[3], f"{attr}.value")
        return self.node(sub, prefix=base)

    # -- leaves ------------------------------------------------------------- #
    def present(self, col: "Col | Exists") -> str:
        if isinstance(col, Exists):
            return col.any_sql
        if col.kind == "string":
            return f"({col.sql} IS NOT NULL AND {col.sql} <> '')"
        return f"({col.sql} IS NOT NULL)"

    def compare(self, col: "Col | Exists", op: str, value: Any, shown: str) -> str:
        if isinstance(col, Exists):
            if op not in ("eq", "ne") or not isinstance(value, str):
                raise FilterError(f"{shown} supports only eq / ne with a string")
            sql = col.sql.format(p=self.param(value.lower()))
            return sql if op == "eq" else f"(NOT {sql})"
        if value is None:
            if op == "eq":
                return f"({col.sql} IS NULL)"
            if op == "ne":
                return f"({col.sql} IS NOT NULL)"
            raise FilterError("null can only be compared with eq / ne")
        if col.kind == "bool":
            if isinstance(value, str) and value.lower() in ("true", "false"):
                value = value.lower() == "true"
            if not isinstance(value, bool) or op not in ("eq", "ne"):
                raise FilterError(f"{shown} is boolean: use eq / ne with true or false")
            p = self.param(value)
            return f"({col.sql} = {p}::boolean)" if op == "eq" else f"({col.sql} IS DISTINCT FROM {p}::boolean)"
        if col.kind == "datetime":
            if op in ("co", "sw", "ew"):
                raise FilterError(f"{shown} is a date: co / sw / ew do not apply")
            p = self.param(_parse_dt(value))
            sym = {"eq": "=", "ne": "<>", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[op]
            return f"({col.sql} {sym} {p}::timestamptz)"
        if not isinstance(value, str):
            raise FilterError(f"{shown} is a string: the value must be quoted")
        p = self.param(value)
        lhs, rhs = (f"lower({col.sql})", f"lower({p}::text)") if col.ci else (col.sql, f"{p}::text")
        if op == "eq":
            return f"({lhs} = {rhs})"
        if op == "ne":
            return f"({col.sql} IS NULL OR {lhs} <> {rhs})"
        if op == "co":
            return f"(strpos({lhs}, {rhs}) > 0)"
        if op == "sw":
            return f"(starts_with({lhs}, {rhs}))"
        if op == "ew":
            return f"(right({lhs}, length({p}::text)) = {rhs})"
        sym = {"gt": ">", "ge": ">=", "lt": "<", "le": "<="}[op]
        return f"({lhs} {sym} {rhs})"


def _parse_dt(value: Any) -> datetime:
    if not isinstance(value, str):
        raise FilterError("a date value must be a quoted ISO 8601 string")
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError as exc:
        raise FilterError(f"not an ISO 8601 date: {value[:40]!r}") from exc
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    try:
        dt.astimezone(timezone.utc)  # year 0001 / 9999 with an offset overflows on normalisation
    except (OverflowError, ValueError) as exc:
        raise FilterError(f"date out of range: {value[:40]!r}") from exc
    if not (1900 <= dt.year <= 2200):
        raise FilterError(f"date out of range: {value[:40]!r}")
    return dt


def compile_filter(expr: str | None, spec: Spec, args: list[Any]) -> str | None:
    """SQL boolean expression for ``expr`` (bind values appended to ``args``),
    or ``None`` for an empty filter. Raises ``FilterError`` (-> invalidFilter)."""
    if not expr or not expr.strip():
        return None
    return _Compiler(spec, args).node(parse(expr))
