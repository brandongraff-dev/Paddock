"""Tests for the API-contract tooling (export determinism + breaking-change detector).

Run from the repo root:  pytest -q scripts/tests
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs" / "api" / "openapi.json"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


oad = _load("openapi_diff")


@pytest.fixture(scope="module")
def spec() -> dict:
    return json.loads(SPEC.read_text())


def _breaking(base, head):
    return [(c.where, c.message) for c in oad.diff(base, head) if c.breaking]


def test_identical_spec_has_no_changes(spec):
    assert oad.diff(spec, copy.deepcopy(spec)) == []


def test_removed_path_and_method(spec):
    head = copy.deepcopy(spec)
    del head["paths"]["/v1/timeline"]
    del head["paths"]["/v1/scope"]["post"]
    got = _breaking(spec, head)
    assert ("/v1/timeline", "path removed") in got
    assert ("POST /v1/scope", "operation removed") in got


def test_new_required_param_and_param_changes(spec):
    head = copy.deepcopy(spec)
    params = head["paths"]["/v1/findings"]["get"]["parameters"]
    params.append({"name": "tenant", "in": "query", "required": True, "schema": {"type": "string"}})
    params.append({"name": "opt", "in": "query", "required": False, "schema": {"type": "string"}})
    for p in params:
        if p["name"] == "q":
            p["required"] = True
    head["paths"]["/v1/findings"]["get"]["parameters"] = [p for p in params if p["name"] != "kev"]
    got = _breaking(spec, head)
    assert ("GET /v1/findings query:tenant", "new REQUIRED parameter") in got
    assert ("GET /v1/findings query:q", "parameter became required") in got
    assert ("GET /v1/findings query:kev", "parameter removed") in got
    assert not any("opt" in w for w, _ in got)


def _findings_schemas(spec):
    """(page schema name, item schema name) behind GET /v1/findings -> 200.

    Resolved from the spec instead of hard-coded, so renaming a response
    model (e.g. FindingPage -> FindingLifecyclePage) can't break these tests.
    """
    ref = spec["paths"]["/v1/findings"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    page = ref.rsplit("/", 1)[1]
    items = spec["components"]["schemas"][page]["properties"]["items"]["items"]["$ref"].rsplit("/", 1)[1]
    return page, items


def test_response_field_removed_via_ref(spec):
    head = copy.deepcopy(spec)
    _, item = _findings_schemas(spec)
    head["components"]["schemas"][item]["properties"].pop("title")
    got = _breaking(spec, head)
    # the item schema is reached through a $ref'd page -> items[] -> item
    assert any(w.startswith("GET /v1/findings -> 200") and w.endswith(".title") for w, _ in got), got


def test_response_type_change_and_new_field_is_additive(spec):
    head = copy.deepcopy(spec)
    page, _ = _findings_schemas(spec)
    props = head["components"]["schemas"][page]["properties"]
    props["total"] = {"type": "string", "title": "Total"}
    props["cursor"] = {"type": "string"}
    changes = oad.diff(spec, head)
    assert any(c.breaking and "type changed" in c.message and c.where.endswith(".total") for c in changes)
    assert any((not c.breaking) and c.where.endswith(".cursor") for c in changes)


def test_new_required_request_field_and_enum_removal(spec):
    head = copy.deepcopy(spec)
    sch = head["components"]["schemas"]["ScopeEntryIn"]
    sch["properties"]["tenant"] = {"type": "string"}
    sch["required"] = [*sch.get("required", []), "tenant"]
    sch["properties"]["kind"]["enum"] = [v for v in sch["properties"]["kind"]["enum"] if v != "asn"]
    got = _breaking(spec, head)
    assert ("POST /v1/scope body.tenant", "new REQUIRED request field") in got
    assert any("enum value 'asn'" in m for _, m in got)


def test_non_v1_paths_are_not_held_to_the_promise(spec):
    head = copy.deepcopy(spec)
    del head["paths"]["/healthz"]
    assert _breaking(spec, head) == []


def test_cli_exit_codes(spec, tmp_path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(spec))
    h = copy.deepcopy(spec)
    del h["paths"]["/v1/timeline"]
    head.write_text(json.dumps(h))
    assert oad.main([str(base), str(base)]) == 0
    assert oad.main([str(base), str(head)]) == 1
    assert oad.main([str(base), str(head), "--allow-breaking", "--markdown"]) == 0


def test_committed_spec_is_current():
    """Same check CI runs: the committed spec matches the code."""
    exp = _load("export_openapi")
    assert exp.render(exp.build_spec()) == SPEC.read_text(), (
        "docs/api/openapi.json is stale: run `make api-regen`"
    )
