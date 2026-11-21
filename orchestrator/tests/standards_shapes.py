"""Structural validators for the interoperability formats.

The official JSON schemas (SARIF 2.1.0, CycloneDX 1.5, SPDX 2.3, OpenVEX
0.2.0) are not vendored in this repo, so these encode the REQUIRED fields,
enums and cross-references from those schemas that a consumer (GitHub code
scanning, Dependency-Track, the SPDX tools) actually rejects on. If
``jsonschema`` and a schema file under ``tests/fixtures/schemas/`` are both
present, ``validate_with_schema`` additionally runs the official schema.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SCHEMAS = Path(__file__).parent / "fixtures" / "schemas"

_SARIF_LEVELS = {"none", "note", "warning", "error"}
_CDX_COMPONENT_TYPES = {"application", "framework", "library", "container", "platform",
                        "operating-system", "device", "device-driver", "firmware", "file",
                        "machine-learning-model", "data"}
_CDX_STATES = {"resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive",
               "not_affected"}
_CDX_JUSTIFICATIONS = {"code_not_present", "code_not_reachable", "requires_configuration",
                       "requires_dependency", "requires_environment", "protected_by_compiler",
                       "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control"}
_CDX_SEVERITIES = {"critical", "high", "medium", "low", "info", "none", "unknown"}
_SPDX_ID = re.compile(r"^SPDXRef-[A-Za-z0-9.\-]+$")
_SPDX_RELS = {"DESCRIBES", "DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS", "CONTAINED_BY"}
_OPENVEX_STATUS = {"not_affected", "affected", "fixed", "under_investigation"}
_OPENVEX_JUST = {"component_not_present", "vulnerable_code_not_present",
                 "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
                 "inline_mitigations_already_exist"}


def validate_with_schema(doc: dict, schema_file: str) -> bool:
    """Run the official schema if available. Returns True if it ran."""
    path = SCHEMAS / schema_file
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return False
    if not path.exists():
        return False
    schema = json.loads(path.read_text())
    try:  # resolve sibling $refs (CycloneDX -> spdx.schema.json / jsf-0.82.schema.json)
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7

        resources = []
        for p in SCHEMAS.glob("*.json"):
            contents = json.loads(p.read_text())
            res = Resource.from_contents(contents, default_specification=DRAFT7)
            resources.append((p.name, res))
            if isinstance(contents, dict) and contents.get("$id"):
                resources.append((contents["$id"], res))
        cls = jsonschema.validators.validator_for(schema)
        cls(schema, registry=Registry().with_resources(resources)).validate(doc)
    except ImportError:
        jsonschema.validate(doc, schema)
    return True


def assert_sarif(doc: dict) -> None:
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(doc["runs"], list) and doc["runs"]
    for run in doc["runs"]:
        driver = run["tool"]["driver"]
        assert driver["name"]
        rules = driver.get("rules", [])
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids)), "rule ids must be unique"
        for r in rules:
            assert r["shortDescription"]["text"]
            ss = r["properties"]["security-severity"]
            assert 0.0 <= float(ss) <= 10.0
            assert r["defaultConfiguration"]["level"] in _SARIF_LEVELS
        taxa_ids = [t["id"] for tx in run.get("taxonomies", []) for t in tx["taxa"]]
        for res in run["results"]:
            assert res["message"]["text"]
            assert res["level"] in _SARIF_LEVELS
            assert res["ruleId"] in ids
            assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
            assert res["locations"], "GitHub requires at least one location"
            for loc in res["locations"]:
                pl = loc["physicalLocation"]
                assert pl["artifactLocation"]["uri"]
                if "region" in pl:
                    assert pl["region"]["startLine"] >= 1
                    assert pl["region"].get("endLine", pl["region"]["startLine"]) >= pl["region"]["startLine"]
            for t in res.get("taxa", []):
                assert t["id"] in taxa_ids and t["toolComponent"]["name"] == "CWE"
            for flow in res.get("codeFlows", []):
                assert flow["threadFlows"][0]["locations"]
    validate_with_schema(doc, "sarif-schema-2.1.0.json")


def assert_cyclonedx(doc: dict) -> None:
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert re.match(r"^urn:uuid:[0-9a-f-]{36}$", doc["serialNumber"])
    assert doc["version"] >= 1
    refs = {doc["metadata"]["component"]["bom-ref"]}
    for c in doc.get("components", []):
        assert c["type"] in _CDX_COMPONENT_TYPES and c["name"]
        assert c["bom-ref"] not in refs, "bom-refs must be unique"
        refs.add(c["bom-ref"])
        if "purl" in c:
            assert c["purl"].startswith("pkg:")
    for d in doc.get("dependencies", []):
        assert d["ref"] in refs
        for x in d.get("dependsOn", []):
            assert x in refs
    for v in doc.get("vulnerabilities", []):
        assert v["id"] and v["bom-ref"]
        for r in v.get("ratings", []):
            assert r["severity"] in _CDX_SEVERITIES
        a = v.get("analysis")
        if a:
            assert a["state"] in _CDX_STATES
            if "justification" in a:
                assert a["justification"] in _CDX_JUSTIFICATIONS
        for af in v["affects"]:
            assert af["ref"] in refs
            for ver in af.get("versions", []):
                assert ver["status"] in {"affected", "unaffected", "unknown"}
    validate_with_schema(doc, "bom-1.5.schema.json")


def assert_spdx(doc: dict) -> None:
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT" and doc["name"]
    assert doc["documentNamespace"].startswith("https://") and "#" not in doc["documentNamespace"]
    ci = doc["creationInfo"]
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ci["created"])
    assert ci["creators"] and all(re.match(r"^(Tool|Organization|Person): ", c) for c in ci["creators"])
    ids = {"SPDXRef-DOCUMENT"}
    for p in doc["packages"]:
        assert _SPDX_ID.match(p["SPDXID"]), p["SPDXID"]
        assert p["SPDXID"] not in ids
        ids.add(p["SPDXID"])
        assert p["name"] and p["downloadLocation"]
        for er in p.get("externalRefs", []):
            assert er["referenceCategory"] == "PACKAGE-MANAGER" and er["referenceType"] == "purl"
            assert er["referenceLocator"].startswith("pkg:")
    assert any(r["relationshipType"] == "DESCRIBES" and r["spdxElementId"] == "SPDXRef-DOCUMENT"
               for r in doc["relationships"])
    for r in doc["relationships"]:
        assert r["relationshipType"] in _SPDX_RELS
        assert r["spdxElementId"] in ids and r["relatedSpdxElement"] in ids
    validate_with_schema(doc, "spdx-schema.json")


def assert_openvex(doc: dict) -> None:
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["@id"] and doc["author"] and doc["timestamp"] and doc["version"] >= 1
    for s in doc["statements"]:
        assert s["vulnerability"]["name"]
        assert s["products"] and all(p["@id"] for p in s["products"])
        assert s["status"] in _OPENVEX_STATUS
        if s["status"] == "not_affected":
            assert s.get("justification") in _OPENVEX_JUST or s.get("impact_statement")
        if s["status"] == "affected":
            assert s["action_statement"]
    validate_with_schema(doc, "openvex_json_schema.json")
