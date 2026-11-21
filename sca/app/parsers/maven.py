"""Maven-ecosystem parser: pom.xml. Emits ``Maven`` (name ``group:artifact``).

We read declared ``<dependency>`` elements (all treated as direct -- a pom is a
manifest, not a full resolution lock). XML is untrusted DATA: we parse it with
the stdlib pull-parser configured to ignore external entities, and never
execute it.
"""
from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from ._util import component, dedupe

ECOSYSTEM = "Maven"

_NS = re.compile(r"\{[^}]*\}")


def _local(tag: str) -> str:
    return _NS.sub("", tag)


def parse_pom(content: str) -> list[dict[str, Any]]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        # ElementTree does not resolve external entities, which keeps XXE out;
        # we additionally reject DOCTYPE to avoid entity-expansion payloads.
        if "<!DOCTYPE" in content:
            content = re.sub(r"<!DOCTYPE[^>]*>", "", content)
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    except Exception:
        return []

    properties = _collect_properties(root)
    out: list[dict[str, Any]] = []
    for deps in root.iter():
        if _local(deps.tag) != "dependencies":
            continue
        for dep in list(deps):
            if _local(dep.tag) != "dependency":
                continue
            fields: dict[str, str] = {}
            for child in list(dep):
                fields[_local(child.tag)] = (child.text or "").strip()
            group = _resolve(fields.get("groupId", ""), properties)
            artifact = _resolve(fields.get("artifactId", ""), properties)
            version = _resolve(fields.get("version", ""), properties)
            if not group or not artifact:
                continue
            name = f"{group}:{artifact}"
            c = component(ECOSYSTEM, name, version, direct=True, depth=0)
            if not version or version.startswith("${"):
                c["version"] = version or ""
                c.setdefault("metadata", {})["unresolved_version"] = True
            out.append(c)
    # keep components even without a version so confusion/typosquat can inspect,
    # but dedupe needs a version; split like python requirements.
    versioned = dedupe([c for c in out if c.get("version")])
    unversioned = [c for c in out if not c.get("version")]
    return versioned + unversioned


def _collect_properties(root: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for el in root.iter():
        if _local(el.tag) == "properties":
            for child in list(el):
                props[_local(child.tag)] = (child.text or "").strip()
    return props


def _resolve(value: str, props: dict[str, str]) -> str:
    if value and value.startswith("${") and value.endswith("}"):
        key = value[2:-1]
        return props.get(key, value)
    return value
