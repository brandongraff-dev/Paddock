from __future__ import annotations

from app.parsers import python
from tests.conftest import load_fixture


def _by_name(components):
    return {c["name"]: c for c in components}


def test_requirements_pins_and_ranges():
    comps = python.parse_requirements(load_fixture("requirements.txt"))
    by = _by_name(comps)
    assert by["requests"]["version"] == "2.31.0"
    assert by["Django"]["version"] == "4.2.1"
    # urllib3 is a range -> recorded with unpinned metadata, no resolved version
    assert by["urllib3"]["version"] == ""
    assert by["urllib3"]["metadata"]["unpinned"] is True
    # flask with no operator is not captured as a pin
    assert "flask" not in by or by["flask"]["version"] == ""
    assert all(c["ecosystem"] == "PyPI" for c in comps)


def test_poetry_lock_graph():
    comps = python.parse_poetry_lock(load_fixture("poetry.lock"))
    by = _by_name(comps)
    assert by["requests"]["version"] == "2.31.0"
    assert by["requests"]["direct"] is True
    # urllib3 + certifi are pulled by requests -> transitive
    assert by["urllib3"]["direct"] is False
    assert "requests" in by["urllib3"]["paths"]


def test_pipfile_lock():
    comps = python.parse_pipfile_lock(load_fixture("Pipfile.lock"))
    by = _by_name(comps)
    assert by["requests"]["version"] == "2.31.0"
    assert by["pytest"]["version"] == "7.4.0"


def test_python_malformed():
    assert python.parse_poetry_lock("not toml =====") == []
    assert python.parse_pipfile_lock("{bad") == []
    assert python.parse_requirements("") == []
