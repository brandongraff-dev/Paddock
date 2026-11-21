#!/usr/bin/env python3
"""Generate ``paddock_sdk/_generated.py`` from docs/api/openapi.json.

    python sdk/python/codegen.py            # regenerate
    python sdk/python/codegen.py --check    # exit 1 if the generated file is stale

A deliberately small, dependency-free generator: every components.schema
becomes a ``TypedDict`` (functional syntax, so any JSON field name works), and
every operation becomes a typed method on ``GeneratedOperations`` that calls
``self._request(...)`` on the hand-written core (``paddock_sdk/_core.py``).
Output is deterministic (sorted), so CI can diff it.
"""
from __future__ import annotations

import argparse
import json
import keyword
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = ROOT / "docs" / "api" / "openapi.json"
OUT = HERE / "paddock_sdk" / "_generated.py"
METHODS = ("get", "post", "put", "patch", "delete")


def ident(name: str) -> str:
    s = re.sub(r"\W+", "_", name).strip("_") or "x"
    if s[0].isdigit():
        s = "_" + s
    if keyword.iskeyword(s):
        s += "_"
    return s


def type_name(ref: str) -> str:
    return ident(ref.rsplit("/", 1)[-1])


def py_type(schema: dict) -> str:
    """Python annotation for a JSON schema (unquoted; callers quote where needed)."""
    if not schema:
        return "Any"
    if "$ref" in schema:
        return type_name(schema["$ref"])
    if "const" in schema:
        return f"Literal[{schema['const']!r}]"
    if "enum" in schema:
        return "Literal[" + ", ".join(repr(v) for v in schema["enum"]) + "]"
    for key in ("anyOf", "oneOf"):
        if key in schema:
            parts: list[str] = []
            for sub in schema[key]:
                t = py_type(sub)
                if t not in parts:
                    parts.append(t)
            return " | ".join(parts)
    if "allOf" in schema and len(schema["allOf"]) == 1:
        return py_type(schema["allOf"][0])
    t = schema.get("type")
    simple = {"string": "str", "integer": "int", "number": "float", "boolean": "bool", "null": "None"}
    if t in simple:
        return simple[t]
    if t == "array":
        return f"list[{py_type(schema.get('items', {}))}]"
    if t == "object" or "properties" in schema or "additionalProperties" in schema:
        ap = schema.get("additionalProperties")
        if isinstance(ap, dict) and ap:
            return f"dict[str, {py_type(ap)}]"
        return "dict[str, Any]"
    return "Any"


def strip_operation_suffix(op_id: str, path: str, method: str) -> str:
    """FastAPI operationIds are ``<function>_<path>_<method>``; keep the function name."""
    suffix = re.sub(r"\W", "_", path) + "_" + method
    if op_id.endswith(suffix) and len(op_id) > len(suffix):
        return op_id[: -len(suffix)].rstrip("_") or op_id
    return op_id


def json_schema(container: dict | None) -> dict | None:
    if not container:
        return None
    content = container.get("content", {})
    if "application/json" in content:
        return content["application/json"].get("schema", {})
    return None


def collect_operations(spec: dict) -> list[dict]:
    ops: list[dict] = []
    used: set[str] = set()
    for path in sorted(spec.get("paths", {})):
        item = spec["paths"][path]
        for method in METHODS:
            if method not in item:
                continue
            op = item[method]
            base = ident(strip_operation_suffix(op.get("operationId", f"{method}_{path}"), path, method))
            name = base
            if name in used:
                name = f"{base}_{ident((op.get('tags') or ['x'])[0])}"
                i = 2
                while name in used:
                    name = f"{base}_{i}"
                    i += 1
            used.add(name)
            params = [*item.get("parameters", []), *op.get("parameters", [])]
            ok = sorted(c for c in op.get("responses", {}) if str(c).startswith("2"))
            no_content = bool(ok and ok[0] == "204")
            resp_schema = json_schema(op["responses"][ok[0]]) if ok and not no_content else None
            body = op.get("requestBody")
            ops.append({
                "name": name,
                "method": method.upper(),
                "path": path,
                "summary": op.get("summary", ""),
                "description": (op.get("description") or "").strip(),
                "deprecated": bool(op.get("deprecated")),
                "tag": (op.get("tags") or [""])[0],
                "path_params": [p for p in params if p.get("in") == "path"],
                "query_params": [p for p in params if p.get("in") == "query"],
                "body": json_schema(body) if body else None,
                "body_required": bool(body and body.get("required")),
                "has_body": body is not None and json_schema(body) is not None,
                "returns": resp_schema,
                "no_content": no_content,
                "paginated": {"limit", "offset"} <= {p["name"] for p in params if p.get("in") == "query"},
            })
    return ops


def _doc(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"""', "'''")


def gen_models(spec: dict) -> list[str]:
    out: list[str] = []
    schemas = spec.get("components", {}).get("schemas", {})
    for name in sorted(schemas):
        s = schemas[name]
        cls = ident(name)
        if s.get("type") == "object" or "properties" in s:
            req = set(s.get("required", []))
            out.append(f"{cls} = TypedDict(")
            out.append(f"    {cls!r},")
            out.append("    {")
            for pname, pschema in s.get("properties", {}).items():
                wrap = "Required" if pname in req else "NotRequired"
                out.append(f"        {pname!r}: {wrap}[{py_type(pschema)!r}],")
            out.append("    },")
            out.append("    total=False,")
            out.append(")")
            doc = (s.get("description") or "").strip().splitlines()
            if doc:
                out.append(f'"""{_doc(doc[0])}"""')
            out.append("")
        else:
            out.append(f"{cls} = {py_type(s)}")
            out.append("")
    return out


def gen_operations(ops: list[dict]) -> list[str]:
    out = ["class GeneratedOperations:", '    """One typed method per API operation (generated)."""', ""]
    for op in ops:
        args = ["self"]
        doc_args = []
        for p in op["path_params"]:
            args.append(f"{ident(p['name'])}: {py_type(p.get('schema', {}))}")
        if op["has_body"]:
            bt = py_type(op["body"])
            if op["body_required"]:
                args.append(f"body: {bt} | dict[str, Any]")
            else:
                args.append(f"body: {bt} | dict[str, Any] | None = None")
        if op["query_params"]:
            args.append("*")
            for p in op["query_params"]:
                t = py_type(p.get("schema", {}))
                pn = ident(p["name"])
                if p.get("required"):
                    args.append(f"{pn}: {t}")
                else:
                    opt = t if t.endswith("| None") or t == "None" else f"{t} | None"
                    args.append(f"{pn}: {opt} = None")
                if p.get("description"):
                    doc_args.append(f"{pn}: {p['description'].strip().splitlines()[0]}")
        if op["no_content"]:
            ret = "None"
        else:
            ret = py_type(op["returns"]) if op["returns"] is not None else "Any"
        out.append(f'    def {op["name"]}({", ".join(args)}) -> {ret}:')
        doc = [f'{op["method"]} {op["path"]}' + (f' -- {op["summary"]}' if op["summary"] else "")]
        if op["deprecated"]:
            doc += ["", "DEPRECATED: see the Sunset/Link response headers for the successor."]
        if op["description"]:
            doc += ["", *op["description"].splitlines()[:12]]
        if doc_args:
            doc += ["", "Args:", *(f"    {d}" for d in doc_args)]
        out.append('        """' + _doc(doc[0]))
        for line in doc[1:]:
            out.append(("        " + _doc(line)).rstrip())
        out.append('        """')
        call = [repr(op["method"]), repr(op["path"])]
        if op["path_params"]:
            call.append("path_params={" + ", ".join(f"{p['name']!r}: {ident(p['name'])}" for p in op["path_params"]) + "}")
        if op["query_params"]:
            call.append("query={" + ", ".join(f"{p['name']!r}: {ident(p['name'])}" for p in op["query_params"]) + "}")
        if op["has_body"]:
            call.append("body=body")
        out.append(f"        return self._request({', '.join(call)})")
        out.append("")
    out.append("    def _request(self, method: str, path: str, **kwargs: Any) -> Any:  # pragma: no cover")
    out.append("        raise NotImplementedError")
    out.append("")
    return out


def gen_index(ops: list[dict]) -> list[str]:
    out = ["# name -> (method, path, paginated)", "OPERATIONS: dict[str, tuple[str, str, bool]] = {"]
    for op in ops:
        out.append(f'    {op["name"]!r}: ({op["method"]!r}, {op["path"]!r}, {op["paginated"]!r}),')
    out += ["}", "", ""]
    return out


def generate(spec: dict) -> str:
    ops = collect_operations(spec)
    info = spec.get("info", {})
    head = [
        "# ruff: noqa",
        "# fmt: off",
        "# GENERATED by sdk/python/codegen.py from docs/api/openapi.json -- DO NOT EDIT.",
        '"""Typed models and operations for the Paddock /v1 API (generated)."""',
        "from __future__ import annotations",
        "",
        "from typing import Any, Literal, NotRequired, Required, TypedDict",
        "",
        f"API_TITLE = {info.get('title', '')!r}",
        f"API_VERSION = {info.get('version', '')!r}",
        "",
    ]
    return "\n".join([*head, *gen_models(spec), *gen_index(ops), *gen_operations(ops)]).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default=str(SPEC))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    spec = json.loads(Path(a.spec).read_text(encoding="utf-8"))
    text = generate(spec)
    out = Path(a.out)
    if a.check:
        if out.exists() and out.read_text(encoding="utf-8") == text:
            print("OK: python SDK is up to date")
            return 0
        print("ERROR: sdk/python/paddock_sdk/_generated.py is stale; run `make api-regen`", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} ({len(collect_operations(spec))} operations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
