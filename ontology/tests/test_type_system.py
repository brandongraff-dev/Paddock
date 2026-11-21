"""Type-system invariants: the object/link catalogue is internally consistent."""
from __future__ import annotations

from app import types as T


def test_required_object_types_present():
    expected = {
        "Host", "Service", "Technology", "Vulnerability", "Repository",
        "Secret", "Package", "Certificate", "Team", "Ticket", "AttackPath",
    }
    assert expected <= set(T.OBJECT_TYPES)


def test_required_link_types_present():
    expected = {
        "RESOLVES_TO", "RUNS", "AFFECTS", "DECLARES", "CONTAINS",
        "ON_PATH", "OWNED_BY", "TRACKS", "SECURES",
    }
    assert expected <= set(T.LINK_TYPES)


def test_link_endpoints_reference_known_object_types():
    for name, spec in T.LINK_TYPES.items():
        assert spec["from_type"] in T.OBJECT_TYPES, name
        assert spec["to_type"] in T.OBJECT_TYPES, name


def test_object_types_have_source_and_schema():
    for name, spec in T.OBJECT_TYPES.items():
        assert spec["source"], name
        assert isinstance(spec["property_schema"], dict), name
        assert spec["color"].startswith("#"), name


def test_asset_kind_map_targets_known_types():
    for kind, otype in T.ASSET_KIND_TO_TYPE.items():
        assert otype in T.OBJECT_TYPES, kind
