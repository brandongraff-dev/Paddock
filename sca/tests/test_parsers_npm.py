from __future__ import annotations

from app.parsers import npm
from tests.conftest import load_fixture


def _by_name(components):
    return {c["name"]: c for c in components}


def test_package_lock_v1():
    comps = npm.parse_package_lock(load_fixture("package-lock-v1.json"))
    by = _by_name(comps)
    assert by["express"]["version"] == "4.17.1"
    assert by["express"]["direct"] is True
    assert by["express"]["depth"] == 0
    # body-parser is nested -> transitive
    assert by["body-parser"]["direct"] is False
    assert by["body-parser"]["depth"] == 1
    assert by["left-pad"]["version"] == "1.3.0"


def test_package_lock_v3_packages():
    comps = npm.parse_package_lock(load_fixture("package-lock-v3.json"))
    by = _by_name(comps)
    assert by["express"]["direct"] is True
    assert by["@scope/internal-utils"]["version"] == "1.0.0"
    # nested install path -> transitive, depth 1
    assert by["body-parser"]["direct"] is False
    assert by["body-parser"]["depth"] == 1


def test_yarn_lock():
    comps = npm.parse_yarn_lock(load_fixture("yarn.lock"))
    by = _by_name(comps)
    assert by["left-pad"]["version"] == "1.3.0"
    assert by["express"]["version"] == "4.17.1"
    # body-parser is pulled by express -> not a root
    assert by["body-parser"]["direct"] is False
    assert "express@4.17.1" in by["body-parser"]["paths"]


def test_pnpm_lock():
    comps = npm.parse_pnpm_lock(load_fixture("pnpm-lock.yaml"))
    by = _by_name(comps)
    assert by["express"]["version"] == "4.17.1"
    assert by["express"]["direct"] is True
    assert by["body-parser"]["version"] == "1.19.0"
    assert by["body-parser"]["direct"] is False


def test_npm_malformed_is_skipped():
    assert npm.parse_package_lock("{not json") == []
    assert npm.parse_package_lock("[]") == []
    assert npm.parse_yarn_lock("") == []
    assert npm.parse_pnpm_lock(": : :") == []
