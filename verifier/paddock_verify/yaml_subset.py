# SPDX-License-Identifier: Apache-2.0
"""PPY: a strict YAML subset for acceptance policies, no external library (spec/08-acceptance-policy.md section 2).

Accepted: comments, blank lines, LF endings, ASCII only, two-space indentation, block mappings and sequences,
sequence items that are scalars, flow mappings, flow sequences or block mappings, double-quoted strings with the
escapes ``\\"`` and ``\\\\``, integers, decimals (kept as ``Decimal``), lowercase ``true`` and ``false`` and bare
strings of ``[A-Za-z0-9_.:/%+-]``. Everything else is an error with the offending line number (``YamlError``,
code ``config.policy_invalid``): anchors, aliases, tags, block scalars, multiple documents, merge keys,
``yes/no/on/off/~/null``, duplicate keys, depth over 6, files over 64 KiB, tabs, carriage returns, single quotes,
nested flow collections, a null value.

The parser is iterative over lines and never recurses more than the depth limit (6).
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple, Union

from . import limits

CODE = "config.policy_invalid"


class YamlError(ValueError):
    """The text is outside the subset; ``line`` is 1-based."""

    code = CODE

    def __init__(self, line: int, message: str) -> None:
        super().__init__("line %d: %s" % (line, message))
        self.line = line
        self.detail = message


_BARE = re.compile(r"[A-Za-z0-9_.:/%+-]+\Z")
_KEY = re.compile(r"[A-Za-z0-9_.+/%-]+\Z")
_INT = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_DEC = re.compile(r"[0-9]+\.[0-9]+\Z")
_NUMERICISH = re.compile(r"[0-9.+-]+\Z")
_RESERVED = frozenset(["yes", "no", "on", "off", "null", "~", "true", "false"])


class _Line(object):
    __slots__ = ("no", "indent", "text")

    def __init__(self, no: int, indent: int, text: str) -> None:
        self.no, self.indent, self.text = no, indent, text


def loads(source: Union[str, bytes]) -> Dict[str, Any]:
    """Parse a policy document into plain values (``dict``, ``list``, ``str``, ``int``, ``bool``, ``Decimal``)."""
    if isinstance(source, (bytes, bytearray)):
        text = bytes(source).decode("latin-1")
        size = len(source)
    elif isinstance(source, str):
        text = source
        size = len(source.encode("utf-8", "surrogatepass"))
    else:
        raise TypeError("text or bytes required")
    if size > limits.MAX_POLICY_YAML_BYTES:
        raise YamlError(1, "file over %d bytes" % limits.MAX_POLICY_YAML_BYTES)
    lines = _prepare(text)
    if not lines:
        return {}
    first = lines[0]
    if first.indent != 0:
        raise YamlError(first.no, "the document starts indented")
    parser = _Parser(lines)
    value = parser.block(0, 1)
    if parser.pos != len(lines):
        raise YamlError(lines[parser.pos].no, "unexpected content")
    if not isinstance(value, dict):
        raise YamlError(first.no, "the document is a mapping")
    return value


def _prepare(text: str) -> List[_Line]:
    out = []  # type: List[_Line]
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    for no, raw in enumerate(raw_lines, 1):
        for ch in raw:
            o = ord(ch)
            if ch == "\r":
                raise YamlError(no, "carriage return (LF line endings only)")
            if ch == "\t":
                raise YamlError(no, "tab")
            if o > 0x7E or o < 0x20:
                raise YamlError(no, "only printable ASCII is allowed")
        if raw.startswith("---") or raw.startswith("..."):
            if raw.rstrip() in ("---", "...") or raw.startswith("--- ") or raw.startswith("... "):
                raise YamlError(no, "multi-document markers are not supported")
        body = _strip_comment(raw, no)
        stripped = body.lstrip(" ")
        if stripped == "":
            continue
        indent = len(body) - len(stripped)
        if indent % 2:
            raise YamlError(no, "indentation is two spaces per level")
        out.append(_Line(no, indent, stripped.rstrip(" ")))
    return out


def _strip_comment(raw: str, no: int) -> str:
    """Remove a ``#`` comment (at the start of the line or after a space) that is outside double quotes."""
    in_q = False
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if in_q:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_q = False
        elif c == '"':
            in_q = True
        elif c == "#" and (i == 0 or raw[i - 1] == " "):
            return raw[:i]
        i += 1
    return raw


class _Parser(object):
    def __init__(self, lines: List[_Line]) -> None:
        self.lines = lines
        self.pos = 0

    # ------------------------------------------------------------------------------------- blocks
    def block(self, indent: int, depth: int) -> Any:
        line = self.lines[self.pos]
        if depth > limits.MAX_POLICY_YAML_DEPTH:
            raise YamlError(line.no, "nesting deeper than %d" % limits.MAX_POLICY_YAML_DEPTH)
        if line.indent != indent:
            raise YamlError(line.no, "unexpected indentation")
        if line.text == "-" or line.text.startswith("- "):
            return self.sequence(indent, depth)
        return self.mapping(indent, depth)

    def mapping(self, indent: int, depth: int) -> Dict[str, Any]:
        out = {}  # type: Dict[str, Any]
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.indent < indent:
                break
            if line.indent > indent:
                raise YamlError(line.no, "unexpected indentation")
            if line.text == "-" or line.text.startswith("- "):
                raise YamlError(line.no, "a sequence item inside a mapping")
            key, rest = self._split_key(line)
            if key in out:
                raise YamlError(line.no, "duplicate key")
            self.pos += 1
            if rest == "":
                out[key] = self._child(line, indent, depth)
            else:
                out[key] = self._inline_value(rest, line.no, allow_flow_map=False)
        return out

    def _child(self, owner: _Line, indent: int, depth: int) -> Any:
        if self.pos >= len(self.lines) or self.lines[self.pos].indent <= indent:
            raise YamlError(owner.no, "a key needs a value (null is not supported)")
        nxt = self.lines[self.pos]
        if nxt.indent != indent + 2:
            raise YamlError(nxt.no, "indentation is two spaces per level")
        return self.block(indent + 2, depth + 1)

    def sequence(self, indent: int, depth: int) -> List[Any]:
        out = []  # type: List[Any]
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.indent < indent:
                break
            if line.indent > indent:
                raise YamlError(line.no, "unexpected indentation")
            if not (line.text == "-" or line.text.startswith("- ")):
                raise YamlError(line.no, "a mapping key inside a sequence")
            rest = line.text[1:].lstrip(" ")
            if rest == "":
                self.pos += 1
                out.append(self._child(line, indent, depth))
            elif rest.startswith("- ") or rest == "-":
                raise YamlError(line.no, "a sequence directly inside a sequence item")
            elif rest[0] == "{" or rest[0] == "[" or rest[0] == '"' or self._is_scalar_item(rest):
                self.pos += 1
                out.append(self._inline_value(rest, line.no, allow_flow_map=True))
            else:
                # "- key: value": the rest of the line starts a block mapping aligned two columns in
                col = len(line.text) - len(rest) + indent
                if col != indent + 2:
                    raise YamlError(line.no, "one space after '-'")
                if depth + 1 > limits.MAX_POLICY_YAML_DEPTH:
                    raise YamlError(line.no, "nesting deeper than %d" % limits.MAX_POLICY_YAML_DEPTH)
                self.lines[self.pos] = _Line(line.no, indent + 2, rest)
                out.append(self.mapping(indent + 2, depth + 1))
        return out

    @staticmethod
    def _is_scalar_item(rest: str) -> bool:
        """True when the item is a plain scalar (no ``key:`` form)."""
        return not _has_key_colon(rest)

    def _split_key(self, line: _Line) -> Tuple[str, str]:
        text = line.text
        idx = _key_colon(text)
        if idx < 0:
            raise YamlError(line.no, "expected 'key: value'")
        key, rest = text[:idx], text[idx + 1:]
        if rest != "" and not rest.startswith(" "):
            raise YamlError(line.no, "expected 'key: value'")
        if not _KEY.match(key) or key == "<<":
            raise YamlError(line.no, "a key is a bare word")
        return key, rest.lstrip(" ")

    # ------------------------------------------------------------------------------------- values
    def _inline_value(self, text: str, no: int, allow_flow_map: bool) -> Any:
        if text.startswith("{"):
            if not allow_flow_map:
                raise YamlError(no, "a flow mapping is only allowed as a sequence item")
            return self._flow_map(text, no)
        if text.startswith("["):
            return self._flow_seq(text, no)
        return _scalar(text, no)

    def _flow_seq(self, text: str, no: int) -> List[Any]:
        if not text.endswith("]"):
            raise YamlError(no, "unclosed flow sequence")
        inner = text[1:-1]
        if inner.strip(" ") == "":
            return []
        out = []
        for part in _split_flow(inner, no):
            if part.startswith("[") or part.startswith("{"):
                raise YamlError(no, "nested flow collections are not supported")
            out.append(_scalar(part, no))
        return out

    def _flow_map(self, text: str, no: int) -> Dict[str, Any]:
        if not text.endswith("}"):
            raise YamlError(no, "unclosed flow mapping")
        inner = text[1:-1]
        out = {}  # type: Dict[str, Any]
        if inner.strip(" ") == "":
            return out
        for part in _split_flow(inner, no):
            idx = _key_colon(part)
            if idx < 0 or part[idx + 1:idx + 2] != " ":
                raise YamlError(no, "expected 'key: value' inside the flow mapping")
            key, value = part[:idx], part[idx + 1:].strip(" ")
            if not _KEY.match(key) or key == "<<":
                raise YamlError(no, "a key is a bare word")
            if key in out:
                raise YamlError(no, "duplicate key")
            if value.startswith("[") or value.startswith("{"):
                raise YamlError(no, "nested flow collections are not supported")
            out[key] = _scalar(value, no)
        return out


def _key_colon(text: str) -> int:
    """Index of the first ``:`` that ends a key (followed by a space or the end), outside double quotes; -1 if none."""
    in_q = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_q:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_q = False
        elif c == '"':
            in_q = True
        elif c == ":" and (i + 1 == n or text[i + 1] == " "):
            return i
        i += 1
    return -1


def _has_key_colon(text: str) -> bool:
    return _key_colon(text) >= 0


def _split_flow(inner: str, no: int) -> List[str]:
    parts = []  # type: List[str]
    cur = []    # type: List[str]
    in_q = False
    i = 0
    while i < len(inner):
        c = inner[i]
        if in_q:
            cur.append(c)
            if c == "\\" and i + 1 < len(inner):
                cur.append(inner[i + 1])
                i += 2
                continue
            if c == '"':
                in_q = False
        elif c == '"':
            in_q = True
            cur.append(c)
        elif c == ",":
            parts.append("".join(cur).strip(" "))
            cur = []
        else:
            cur.append(c)
        i += 1
    if in_q:
        raise YamlError(no, "unterminated string")
    parts.append("".join(cur).strip(" "))
    if any(p == "" for p in parts):
        raise YamlError(no, "empty item in a flow collection")
    return parts


def _scalar(text: str, no: int) -> Any:
    if text == "":
        raise YamlError(no, "empty value")
    if text[0] == '"':
        return _quoted(text, no)
    if text == "true":
        return True
    if text == "false":
        return False
    if text.lower() in _RESERVED:
        raise YamlError(no, "%r is not a supported scalar (quote it to mean the string)" % text)
    if _INT.match(text):
        return int(text)
    if _DEC.match(text):
        return Decimal(text)
    if not _BARE.match(text):
        raise YamlError(no, "not a supported scalar")
    if _NUMERICISH.match(text):
        raise YamlError(no, "an ambiguous number (use digits or a decimal with digits on both sides of the point)")
    return text


def _quoted(text: str, no: int) -> str:
    out = []  # type: List[str]
    i = 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            if i + 1 >= n or text[i + 1] not in '"\\':
                raise YamlError(no, "only the escapes \\\" and \\\\ are supported")
            out.append(text[i + 1])
            i += 2
            continue
        if c == '"':
            if i != n - 1:
                raise YamlError(no, "content after the closing quote")
            return "".join(out)
        out.append(c)
        i += 1
    raise YamlError(no, "unterminated string")
