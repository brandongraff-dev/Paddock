# SPDX-License-Identifier: AGPL-3.0-or-later
"""A small line-oriented YAML reader for workflows, compose files and pre-commit configs.

Guard has no YAML dependency (D5), so this reads the subset those files use: block mappings and
sequences, plain and quoted single-line scalars, ``|`` and ``>`` block scalars, comments, and
single-line flat flow collections. Anything else (anchors, aliases, merge keys, tags, nested or
multi-line flow, complex keys, tabs for indentation, several documents, multi-line quoted
scalars) raises ``YamlUnsupported`` so the caller can record ``skipped`` plus a note instead of
guessing. Every node carries the 1-based line it starts on.
"""
from __future__ import annotations

import re
from typing import Any

MAX_LINES = 20000
MAX_LINE = 4000
MAX_DEPTH = 64


class YamlUnsupported(Exception):
    """The text uses YAML that this reader does not support (reason in the message)."""


class YNode:
    __slots__ = ("line",)

    def __init__(self, line: int):
        self.line = line


class YScalar(YNode):
    __slots__ = ("value", "style", "body_line")

    def __init__(self, value: str | None, line: int, style: str = "plain", body_line: int | None = None):
        super().__init__(line)
        self.value = value
        self.style = style  # plain | single | double | block
        self.body_line = body_line if body_line is not None else line

    def typed(self) -> Any:
        """bool, None, int or str per the YAML core schema (quoted scalars stay strings)."""
        v = self.value
        if self.style != "plain":
            return v
        if v is None or v == "" or v in ("~", "null", "Null", "NULL"):
            return None
        if v in ("true", "True", "TRUE"):
            return True
        if v in ("false", "False", "FALSE"):
            return False
        if re.fullmatch(r"[-+]?\d{1,18}", v):
            return int(v)
        return v

    def __repr__(self) -> str:
        return "YScalar(%r)" % (self.value,)


class YMap(YNode):
    __slots__ = ("items", "duplicates")

    def __init__(self, line: int):
        super().__init__(line)
        self.items: list[tuple[str, YNode, int]] = []
        self.duplicates: list[str] = []

    def keys(self) -> list[str]:
        out: list[str] = []
        for k, _, _ in self.items:
            if k not in out:
                out.append(k)
        return out

    def get(self, key: str) -> Any:
        found = None
        for k, v, _ in self.items:
            if k == key:
                found = v
        return found

    def key_line(self, key: str) -> int | None:
        for k, _, ln in reversed(self.items):
            if k == key:
                return ln
        return None


class YSeq(YNode):
    __slots__ = ("items",)

    def __init__(self, line: int):
        super().__init__(line)
        self.items: list[YNode] = []


def to_python(node: Any) -> Any:
    if isinstance(node, YScalar):
        return "" if node.value is None else node.value
    if isinstance(node, YSeq):
        return [to_python(i) for i in node.items]
    if isinstance(node, YMap):
        return {k: to_python(v) for k, v, _ in node.items}
    return node


_KEY_BAD_START = set("-?:,[]{}#&*!|>'\"%@`")


class _Line:
    __slots__ = ("no", "indent", "text", "raw")

    def __init__(self, no: int, indent: int, text: str, raw: str):
        self.no, self.indent, self.text, self.raw = no, indent, text, raw


def _strip_comment(s: str) -> str:
    """Remove a trailing ``# comment`` (a ``#`` at the start or after whitespace, outside quotes)."""
    quote = ""
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                if quote == "'" and s[i + 1:i + 2] == "'":
                    continue
                quote = ""
            elif ch == "\\" and quote == '"':
                continue
        elif ch in "'\"" and (i == 0 or s[i - 1] in " \t:[{,-" or not quote):
            if i == 0 or s[i - 1] in " \t:[{,-":
                quote = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


class _Parser:
    def __init__(self, text: str):
        raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if len(raw_lines) > MAX_LINES:
            raise YamlUnsupported("more than %d lines" % MAX_LINES)
        self.raw = raw_lines
        self.pos = 0
        self.depth = 0
        self.docs = 0

    # -- helpers ---------------------------------------------------------------------------
    def _skip_blank(self) -> None:
        while self.pos < len(self.raw):
            s = self.raw[self.pos].strip()
            if s == "" or s.startswith("#"):
                self.pos += 1
            else:
                break

    def _peek(self) -> _Line | None:
        self._skip_blank()
        if self.pos >= len(self.raw):
            return None
        raw = self.raw[self.pos]
        if len(raw) > MAX_LINE:
            raise YamlUnsupported("line longer than %d characters" % MAX_LINE)
        stripped = raw.lstrip(" ")
        if stripped.startswith("\t") or (raw[: len(raw) - len(stripped)] != " " * (len(raw) - len(stripped))):
            raise YamlUnsupported("tab indentation")
        indent = len(raw) - len(stripped)
        return _Line(self.pos + 1, indent, _strip_comment(stripped), raw)

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise YamlUnsupported("nesting deeper than %d" % MAX_DEPTH)

    def _leave(self) -> None:
        self.depth -= 1

    # -- document ----------------------------------------------------------------------------
    def document(self) -> YNode:
        ln = self._peek()
        if ln is not None and ln.text == "---":
            self.pos += 1
        elif ln is not None and ln.text.startswith("--- "):
            raise YamlUnsupported("content on the document start line")
        ln = self._peek()
        if ln is None:
            return YScalar(None, 1)
        node = self._block(ln.indent)
        rest = self._peek()
        if rest is not None:
            if rest.text == "---" or rest.text == "...":
                raise YamlUnsupported("more than one document")
            raise YamlUnsupported("unexpected content at line %d" % rest.no)
        return node

    def _block(self, indent: int) -> YNode:
        ln = self._peek()
        if ln is None:
            return YScalar(None, self.pos + 1)
        if ln.text == "-" or ln.text.startswith("- "):
            return self._seq(ln.indent)
        key = self._split_key(ln.text)
        if key is not None:
            return self._map(ln.indent)
        self.pos += 1
        return self._scalar(ln.text, ln.no)

    # -- scalars -------------------------------------------------------------------------------
    def _scalar(self, text: str, no: int) -> YNode:
        t = text.strip()
        if t.startswith(("&", "*")):
            raise YamlUnsupported("anchors and aliases are not supported (line %d)" % no)
        if t.startswith("!"):
            raise YamlUnsupported("tags are not supported (line %d)" % no)
        if t.startswith("? "):
            raise YamlUnsupported("complex keys are not supported (line %d)" % no)
        if t.startswith("[") or t.startswith("{"):
            return self._flow(t, no)
        if t.startswith('"'):
            end = self._closing_quote(t, '"')
            if end is None or t[end + 1:].strip():
                raise YamlUnsupported("multi-line or malformed quoted scalar (line %d)" % no)
            return YScalar(self._unescape(t[1:end]), no, "double")
        if t.startswith("'"):
            end = self._closing_quote(t, "'")
            if end is None or t[end + 1:].strip():
                raise YamlUnsupported("multi-line or malformed quoted scalar (line %d)" % no)
            return YScalar(t[1:end].replace("''", "'"), no, "single")
        if t in ("|", ">") or re.match(r"^[|>][+-]?\d?$", t):
            raise YamlUnsupported("block scalar in an unsupported position (line %d)" % no)
        return YScalar(t, no, "plain")

    @staticmethod
    def _closing_quote(t: str, q: str) -> int | None:
        i = 1
        while i < len(t):
            c = t[i]
            if q == '"' and c == "\\":
                i += 2
                continue
            if c == q:
                if q == "'" and t[i + 1:i + 2] == "'":
                    i += 2
                    continue
                return i
            i += 1
        return None

    @staticmethod
    def _unescape(s: str) -> str:
        table = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0", " ": " "}
        out: list[str] = []
        i = 0
        while i < len(s):
            c = s[i]
            if c == "\\" and i + 1 < len(s):
                n = s[i + 1]
                if n == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", s[i + 2:i + 6]):
                    out.append(chr(int(s[i + 2:i + 6], 16)))
                    i += 6
                    continue
                out.append(table.get(n, n))
                i += 2
                continue
            out.append(c)
            i += 1
        return "".join(out)

    def _flow(self, t: str, no: int) -> YNode:
        if t[0] == "[":
            if not t.endswith("]") or t.count("[") != 1 or "{" in t:
                raise YamlUnsupported("nested or multi-line flow collection (line %d)" % no)
            inner = t[1:-1].strip()
            node = YSeq(no)
            for part in self._flow_split(inner, no):
                node.items.append(self._scalar(part, no))
            return node
        if not t.endswith("}") or t.count("{") != 1 or "[" in t:
            raise YamlUnsupported("nested or multi-line flow collection (line %d)" % no)
        m = YMap(no)
        inner = t[1:-1].strip()
        for part in self._flow_split(inner, no):
            kv = self._split_key(part)
            if kv is None:
                raise YamlUnsupported("flow mapping entry without a key (line %d)" % no)
            key, rest = kv
            m.items.append((key, self._scalar(rest, no) if rest else YScalar(None, no), no))
        return m

    @staticmethod
    def _flow_split(inner: str, no: int) -> list[str]:
        if not inner:
            return []
        parts: list[str] = []
        cur: list[str] = []
        quote = ""
        for ch in inner:
            if quote:
                cur.append(ch)
                if ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
                cur.append(ch)
            elif ch == ",":
                parts.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        if quote:
            raise YamlUnsupported("unterminated quote in flow collection (line %d)" % no)
        parts.append("".join(cur).strip())
        if parts and parts[-1] == "":
            parts.pop()
        if any(p == "" for p in parts):
            raise YamlUnsupported("empty entry in flow collection (line %d)" % no)
        return parts

    # -- keys ----------------------------------------------------------------------------------
    def _split_key(self, text: str) -> tuple[str, str] | None:
        """(key, rest) when ``text`` is ``key:`` or ``key: value``; None otherwise."""
        if not text:
            return None
        c0 = text[0]
        if c0 in "\"'":
            end = self._closing_quote(text, c0)
            if end is None:
                return None
            after = text[end + 1:].lstrip()
            if not after.startswith(":"):
                return None
            rest = after[1:]
            if rest and not rest.startswith((" ", "\t")):
                return None
            key = self._unescape(text[1:end]) if c0 == '"' else text[1:end].replace("''", "'")
            return key, rest.strip()
        if c0 in _KEY_BAD_START:
            if c0 == "?" and text[1:2] == " ":
                raise YamlUnsupported("complex keys are not supported")
            return None
        i = 0
        n = len(text)
        while i < n:
            if text[i] == ":" and (i + 1 == n or text[i + 1] in " \t"):
                key = text[:i].rstrip()
                if key == "<<":
                    raise YamlUnsupported("merge keys are not supported")
                if not key:
                    return None
                return key, text[i + 1:].strip()
            i += 1
        return None

    # -- mappings ------------------------------------------------------------------------------
    def _map(self, indent: int) -> YMap:
        self._enter()
        first = self._peek()
        node = YMap(first.no if first else self.pos + 1)
        seen: set[str] = set()
        while True:
            ln = self._peek()
            if ln is None or ln.indent < indent or (ln.indent == 0 and ln.text in ("---", "...")):
                break
            if ln.indent > indent:
                raise YamlUnsupported("unexpected indentation at line %d" % ln.no)
            if ln.text == "-" or ln.text.startswith("- "):
                break
            kv = self._split_key(ln.text)
            if kv is None:
                raise YamlUnsupported("expected a mapping key at line %d" % ln.no)
            key, rest = kv
            self.pos += 1
            if key in seen:
                node.duplicates.append(key)
            seen.add(key)
            node.items.append((key, self._value(rest, ln, indent), ln.no))
        self._leave()
        return node

    def _value(self, rest: str, ln: _Line, indent: int) -> YNode:
        if rest == "":
            nxt = self._peek()
            if nxt is None:
                return YScalar(None, ln.no)
            if nxt.indent > indent:
                return self._block(nxt.indent)
            if nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                return self._seq(indent)
            return YScalar(None, ln.no)
        if re.match(r"^[|>][+-]?\d?$", rest):
            return self._block_scalar(rest, ln, indent)
        node = self._scalar(rest, ln.no)
        nxt = self._peek()
        if (nxt is not None and nxt.indent > indent and isinstance(node, YScalar) and node.style == "plain"):
            raise YamlUnsupported("multi-line plain scalar at line %d" % ln.no)
        return node

    def _block_scalar(self, header: str, ln: _Line, parent_indent: int) -> YScalar:
        folded = header.startswith(">")
        chomp = "-" if "-" in header else "+" if "+" in header else ""
        body: list[str] = []
        block_indent: int | None = None
        start = self.pos + 1
        first_body = None
        while self.pos < len(self.raw):
            raw = self.raw[self.pos]
            if len(raw) > MAX_LINE:
                raise YamlUnsupported("line longer than %d characters" % MAX_LINE)
            if raw.strip() == "":
                body.append("")
                self.pos += 1
                continue
            ind = len(raw) - len(raw.lstrip(" "))
            if raw.lstrip(" ").startswith("\t") and ind <= parent_indent:
                break
            if ind <= parent_indent:
                break
            if block_indent is None:
                block_indent = ind
                first_body = self.pos + 1
            if ind < block_indent:
                raise YamlUnsupported("inconsistent block scalar indentation at line %d" % (self.pos + 1))
            body.append(raw[block_indent:])
            self.pos += 1
        while body and body[-1] == "":
            body.pop()
        if folded:
            text = " ".join(x for x in body if x != "")
        else:
            text = "\n".join(body)
        if chomp != "-" and body:
            text += "\n" if not folded else ""
        return YScalar(text, ln.no, "block", first_body if first_body else start)

    # -- sequences -----------------------------------------------------------------------------
    def _seq(self, indent: int) -> YSeq:
        self._enter()
        first = self._peek()
        node = YSeq(first.no if first else self.pos + 1)
        while True:
            ln = self._peek()
            if ln is None or ln.indent < indent or (ln.indent == 0 and ln.text in ("---", "...")):
                break
            if ln.indent > indent:
                raise YamlUnsupported("unexpected indentation at line %d" % ln.no)
            if not (ln.text == "-" or ln.text.startswith("- ")):
                break
            rest = ln.text[1:].lstrip(" ")
            offset = len(ln.text) - len(rest) if rest else 0
            if rest == "":
                self.pos += 1
                nxt = self._peek()
                if nxt is not None and nxt.indent > indent:
                    node.items.append(self._block(nxt.indent))
                else:
                    node.items.append(YScalar(None, ln.no))
                continue
            if rest.startswith("- ") or rest == "-":
                raise YamlUnsupported("nested sequence on one line (line %d)" % ln.no)
            if self._split_key(rest) is not None and not rest.startswith(("[", "{")):
                # a mapping that starts on the "- " line: rewrite the line as the first map line
                col = indent + offset
                self.raw[self.pos] = " " * col + self.raw[self.pos].lstrip(" ")[offset:]
                node.items.append(self._map(col))
                continue
            self.pos += 1
            if re.match(r"^[|>][+-]?\d?$", rest):
                node.items.append(self._block_scalar(rest, ln, indent))
            else:
                node.items.append(self._scalar(rest, ln.no))
        self._leave()
        return node


def parse(text: str) -> YNode:
    """Parse ``text``; raises ``YamlUnsupported`` for anything outside the supported subset."""
    if not isinstance(text, str):
        raise YamlUnsupported("not text")
    try:
        return _Parser(text).document()
    except RecursionError:
        raise YamlUnsupported("nesting too deep") from None
    except (ValueError, OverflowError, MemoryError, IndexError):
        raise YamlUnsupported("could not read this YAML") from None
