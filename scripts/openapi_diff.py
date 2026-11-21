#!/usr/bin/env python3
"""A small, dependency-free OpenAPI breaking-change detector for Paddock's /v1.

    python scripts/openapi_diff.py BASE.json HEAD.json [--allow-breaking] [--markdown]

Reports, per operation, the changes that can break an existing client:

* a path, or an HTTP method on a path, was removed
* a parameter was removed, changed location/type, or became required
* a NEW required parameter / required request-body field was added
* a request body became required
* an enum value accepted in a request was removed
* a 2xx response status was removed
* a field disappeared from (or changed type in) a 2xx response body,
  including nested objects and array items; a field that was required in a
  response became optional

Additions that cannot break a client (new paths, optional params, new response
fields) are listed as informational. Exit code: 1 when breaking changes exist
(unless ``--allow-breaking``), else 0. Only paths under ``--prefix`` (default
``/v1``) are held to the stability promise; see docs/API.md.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any

METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
MAX_DEPTH = 8


@dataclass(frozen=True)
class Change:
    breaking: bool
    where: str
    message: str


class Spec:
    def __init__(self, doc: dict[str, Any]) -> None:
        self.doc = doc

    def resolve(self, schema: Any, _seen: tuple[str, ...] = ()) -> dict[str, Any]:
        if not isinstance(schema, dict):
            return {}
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            if ref in _seen:
                return {}
            node: Any = self.doc
            for part in ref[2:].split("/"):
                node = node.get(part, {}) if isinstance(node, dict) else {}
            return self.resolve(node, (*_seen, ref))
        return schema

    def flatten(self, schema: Any) -> dict[str, Any]:
        """Resolve $ref and merge allOf; collapse `anyOf: [X, null]` to X (nullable)."""
        s = dict(self.resolve(schema))
        if "allOf" in s:
            merged: dict[str, Any] = {"properties": {}, "required": []}
            for sub in s.pop("allOf"):
                f = self.flatten(sub)
                merged["properties"].update(f.get("properties", {}))
                merged["required"].extend(f.get("required", []))
                for k, v in f.items():
                    if k not in ("properties", "required"):
                        merged.setdefault(k, v)
            merged.update({k: v for k, v in s.items() if k not in merged})
            s = merged
        for key in ("anyOf", "oneOf"):
            if key in s:
                opts = [o for o in s[key] if self.resolve(o).get("type") != "null"]
                if len(opts) == 1:
                    inner = self.flatten(opts[0])
                    s = {**inner, **{k: v for k, v in s.items() if k != key}, "nullable": True}
        return s


def type_sig(spec: Spec, schema: Any) -> str:
    s = spec.flatten(schema)
    for key in ("anyOf", "oneOf"):
        if key in s:
            return key + "(" + ",".join(sorted(type_sig(spec, o) for o in s[key])) + ")"
    t = s.get("type")
    if t is None and "properties" in s:
        t = "object"
    if t == "array":
        return "array<" + type_sig(spec, s.get("items", {})) + ">"
    if t == "integer":
        return "number"  # integer -> number widening is not breaking for JSON clients
    return str(t or "any")


def _params(spec: Spec, op: dict[str, Any], path_item: dict[str, Any]) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for p in [*path_item.get("parameters", []), *op.get("parameters", [])]:
        p = spec.resolve(p)
        if "name" in p:
            out[(p["name"], p.get("in", "query"))] = p
    return out


def _json_schema(spec: Spec, container: dict[str, Any] | None) -> Any:
    if not container:
        return None
    content = spec.resolve(container).get("content", {})
    for ctype in ("application/json", *content.keys()):
        if ctype in content:
            return content[ctype].get("schema")
    return None


def _compare_request_schema(base: Spec, head: Spec, bs: Any, hs: Any, where: str, out: list[Change], depth: int = 0) -> None:
    if depth > MAX_DEPTH or bs is None or hs is None:
        return
    b, h = base.flatten(bs), head.flatten(hs)
    b_enum, h_enum = b.get("enum"), h.get("enum")
    if b_enum and h_enum:
        for v in b_enum:
            if v not in h_enum:
                out.append(Change(True, where, f"request no longer accepts enum value {v!r}"))
    bt, ht = type_sig(base, b), type_sig(head, h)
    if bt != ht and "any" not in (bt, ht):
        out.append(Change(True, where, f"request type changed {bt} -> {ht}"))
        return
    b_props, h_props = b.get("properties", {}), h.get("properties", {})
    b_req, h_req = set(b.get("required", [])), set(h.get("required", []))
    for name in sorted(h_req - b_req):
        if name in b_props:
            out.append(Change(True, f"{where}.{name}", "request field became required"))
        else:
            out.append(Change(True, f"{where}.{name}", "new REQUIRED request field"))
    for name in sorted(set(h_props) - set(b_props) - h_req):
        out.append(Change(False, f"{where}.{name}", "new optional request field"))
    if b_props and h.get("additionalProperties") is False:
        for name in sorted(set(b_props) - set(h_props)):
            out.append(Change(True, f"{where}.{name}", "request field removed (and extra fields are rejected)"))
    for name in sorted(set(b_props) & set(h_props)):
        _compare_request_schema(base, head, b_props[name], h_props[name], f"{where}.{name}", out, depth + 1)
    if b.get("type") == "array" and h.get("type") == "array":
        _compare_request_schema(base, head, b.get("items"), h.get("items"), f"{where}[]", out, depth + 1)


def _compare_response_schema(base: Spec, head: Spec, bs: Any, hs: Any, where: str, out: list[Change], depth: int = 0) -> None:
    if depth > MAX_DEPTH or bs is None:
        return
    if hs is None:
        out.append(Change(True, where, "response body schema removed"))
        return
    b, h = base.flatten(bs), head.flatten(hs)
    bt, ht = type_sig(base, b), type_sig(head, h)
    if bt != ht and "any" not in (bt, ht):
        out.append(Change(True, where, f"response type changed {bt} -> {ht}"))
        return
    if b.get("nullable") is not True and h.get("nullable") is True and depth > 0:
        out.append(Change(True, where, "response field became nullable"))
    b_enum, h_enum = b.get("enum"), h.get("enum")
    if b_enum and h_enum:
        for v in h_enum:
            if v not in b_enum:
                out.append(Change(False, where, f"response may now return new enum value {v!r}"))
    b_props, h_props = b.get("properties", {}), h.get("properties", {})
    b_req, h_req = set(b.get("required", [])), set(h.get("required", []))
    for name in sorted(set(b_props) - set(h_props)):
        out.append(Change(True, f"{where}.{name}", "response field removed"))
    for name in sorted(set(h_props) - set(b_props)):
        out.append(Change(False, f"{where}.{name}", "new response field"))
    for name in sorted((b_req & set(h_props)) - h_req):
        out.append(Change(True, f"{where}.{name}", "response field no longer guaranteed (was required)"))
    for name in sorted(set(b_props) & set(h_props)):
        _compare_response_schema(base, head, b_props[name], h_props[name], f"{where}.{name}", out, depth + 1)
    if b.get("type") == "array":
        _compare_response_schema(base, head, b.get("items"), h.get("items"), f"{where}[]", out, depth + 1)


def diff(base_doc: dict[str, Any], head_doc: dict[str, Any], prefix: str = "/v1") -> list[Change]:
    base, head = Spec(base_doc), Spec(head_doc)
    out: list[Change] = []
    bpaths, hpaths = base_doc.get("paths", {}), head_doc.get("paths", {})

    for path in sorted(set(hpaths) - set(bpaths)):
        if path.startswith(prefix):
            out.append(Change(False, path, "new path"))

    for path in sorted(bpaths):
        if not path.startswith(prefix):
            continue
        b_item = bpaths[path]
        h_item = hpaths.get(path)
        if h_item is None:
            out.append(Change(True, path, "path removed"))
            continue
        for m in METHODS:
            if m not in b_item:
                if m in h_item:
                    out.append(Change(False, f"{m.upper()} {path}", "new operation"))
                continue
            where = f"{m.upper()} {path}"
            if m not in h_item:
                note = " (was deprecated)" if b_item[m].get("deprecated") else ""
                out.append(Change(True, where, f"operation removed{note}"))
                continue
            bop, hop = b_item[m], h_item[m]
            if hop.get("deprecated") and not bop.get("deprecated"):
                out.append(Change(False, where, "operation deprecated"))

            # parameters
            bp, hp = _params(base, bop, b_item), _params(head, hop, h_item)
            for key in sorted(set(bp) - set(hp)):
                name, loc = key
                moved = [k for k in hp if k[0] == name]
                msg = f"parameter moved {loc} -> {moved[0][1]}" if moved else "parameter removed"
                out.append(Change(True, f"{where} {loc}:{name}", msg))
            for key in sorted(set(hp) - set(bp)):
                name, loc = key
                if any(k[0] == name for k in bp):
                    continue
                if hp[key].get("required"):
                    out.append(Change(True, f"{where} {loc}:{name}", "new REQUIRED parameter"))
                else:
                    out.append(Change(False, f"{where} {loc}:{name}", "new optional parameter"))
            for key in sorted(set(bp) & set(hp)):
                name, loc = key
                if hp[key].get("required") and not bp[key].get("required"):
                    out.append(Change(True, f"{where} {loc}:{name}", "parameter became required"))
                _compare_request_schema(
                    base, head, bp[key].get("schema"), hp[key].get("schema"), f"{where} {loc}:{name}", out
                )

            # request body
            brb, hrb = bop.get("requestBody"), hop.get("requestBody")
            if hrb and not brb and head.resolve(hrb).get("required"):
                out.append(Change(True, where, "new REQUIRED request body"))
            elif brb and hrb:
                if head.resolve(hrb).get("required") and not base.resolve(brb).get("required"):
                    out.append(Change(True, where, "request body became required"))
                _compare_request_schema(
                    base, head, _json_schema(base, brb), _json_schema(head, hrb), f"{where} body", out
                )

            # responses (2xx only: errors are allowed to evolve)
            bresp, hresp = bop.get("responses", {}), hop.get("responses", {})
            for code in sorted(c for c in bresp if str(c).startswith("2")):
                if code not in hresp:
                    out.append(Change(True, where, f"response {code} removed"))
                    continue
                _compare_response_schema(
                    base, head, _json_schema(base, bresp[code]), _json_schema(head, hresp[code]),
                    f"{where} -> {code}", out,
                )
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base")
    ap.add_argument("head")
    ap.add_argument("--prefix", default="/v1")
    ap.add_argument("--allow-breaking", action="store_true")
    ap.add_argument("--markdown", action="store_true", help="emit a markdown report (for $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--quiet-info", action="store_true", help="omit non-breaking changes")
    a = ap.parse_args(argv)

    with open(a.base, encoding="utf-8") as fh:
        base_doc = json.load(fh)
    with open(a.head, encoding="utf-8") as fh:
        head_doc = json.load(fh)

    changes = diff(base_doc, head_doc, a.prefix)
    breaking = [c for c in changes if c.breaking]
    info = [] if a.quiet_info else [c for c in changes if not c.breaking]

    if a.markdown:
        print(f"### API contract: {len(breaking)} breaking, {len([c for c in changes if not c.breaking])} additive\n")
        for c in breaking:
            print(f"- :x: `{c.where}` — {c.message}")
        for c in info:
            print(f"- `{c.where}` — {c.message}")
    else:
        for c in breaking:
            print(f"BREAKING  {c.where}: {c.message}")
        for c in info:
            print(f"info      {c.where}: {c.message}")
        print(f"\n{len(breaking)} breaking change(s), {len(changes) - len(breaking)} non-breaking.")

    if breaking and not a.allow_breaking:
        print(
            "\nBreaking /v1 change(s) detected. Follow docs/API.md (deprecate first, Sunset >= 6 months),\n"
            "or, if this is intentional and approved, add the `api-breaking` label to the PR.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
