"""A small, strict validator for the JSON-schema subset connectors use.

Supported keywords: ``type`` (object, string, integer, number, boolean,
array), ``properties``, ``required``, ``additionalProperties`` (bool or
schema), ``items``, ``enum``, ``default``, ``minimum``/``maximum``,
``minLength``/``maxLength``, ``minItems``/``maxItems``, ``pattern`` and
``format`` (``uri``, ``email``, ``hostname``). Anything else is ignored, so a
connector may carry UI-only hints (``title``, ``description``, ``x-*``).

``validate_config`` returns a NEW dict with defaults filled in, or raises
``ConfigError`` listing every problem (path + message).
"""
from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlsplit


class ConfigError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


_EMAIL_RE = re.compile(r"^[^@\s<>\"',;]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _type_ok(value: Any, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "null":
        return value is None
    return True


def _check_format(value: str, fmt: str) -> str | None:
    if fmt == "uri":
        p = urlsplit(value)
        if p.scheme not in ("http", "https") or not p.netloc:
            return "must be an http(s) URL"
    elif fmt == "email":
        if not _EMAIL_RE.match(value):
            return "must be an email address"
    elif fmt == "hostname":
        if not _HOST_RE.match(value):
            return "must be a hostname"
    return None


def _validate(value: Any, schema: Mapping[str, Any], path: str, errors: list[str]) -> Any:
    t = schema.get("type")
    types = t if isinstance(t, list) else ([t] if t else [])
    if types and not any(_type_ok(value, x) for x in types):
        errors.append(f"{path}: expected {' or '.join(types)}")
        return value

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {', '.join(map(str, schema['enum']))}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: must be at least {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: must be at most {schema['maxLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match the required pattern")
        if "format" in schema and value != "":
            msg = _check_format(value, schema["format"])
            if msg:
                errors.append(f"{path}: {msg}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: must be <= {schema['maximum']}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: needs at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: allows at most {schema['maxItems']} item(s)")
        items = schema.get("items")
        if isinstance(items, Mapping):
            value = [_validate(v, items, f"{path}[{i}]", errors) for i, v in enumerate(value)]

    if isinstance(value, dict):
        props: Mapping[str, Any] = schema.get("properties") or {}
        out: dict[str, Any] = {}
        for req in schema.get("required") or ():
            if req not in value or value[req] in (None, ""):
                errors.append(f"{path}.{req}: is required" if path else f"{req}: is required")
        addl = schema.get("additionalProperties", True)
        for k, v in value.items():
            sub = f"{path}.{k}" if path else k
            if k in props:
                if v is None and k not in (schema.get("required") or ()):
                    continue                  # null == unset for optional fields
                out[k] = _validate(v, props[k], sub, errors)
            elif addl is False:
                errors.append(f"{sub}: unknown field")
            elif isinstance(addl, Mapping):
                out[k] = _validate(v, addl, sub, errors)
            else:
                out[k] = v
        for k, p in props.items():
            if k not in out and isinstance(p, Mapping) and "default" in p:
                out[k] = p["default"]
        return out
    return value


def validate_config(config: Mapping[str, Any] | None, schema: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    cfg = dict(config or {})
    root = dict(schema or {"type": "object"})
    root.setdefault("type", "object")
    out = _validate(cfg, root, "", errors)
    if errors:
        raise ConfigError(errors)
    return out
