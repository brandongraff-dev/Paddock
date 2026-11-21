from __future__ import annotations

from app import parsers
from app.parsers import registry
from tests.conftest import load_fixture


def test_is_supported_by_basename():
    assert registry.is_supported("path/to/package-lock.json")
    assert registry.is_supported("go.sum")
    assert registry.is_supported("POM.XML")  # case-insensitive
    assert not registry.is_supported("random.txt")
    assert not registry.is_supported("README.md")


def test_parse_one_dispatch():
    comps = registry.parse_one("a/b/requirements.txt", load_fixture("requirements.txt"))
    assert any(c["name"] == "requests" for c in comps)
    assert registry.parse_one("unknown.file", "x") == []
    # go.mod alone yields nothing (ranges, not a resolved lock)
    assert registry.parse_one("go.mod", load_fixture("go.mod")) == []


def test_parse_files_pairs_go_mod_and_sum():
    files = {
        "go.mod": load_fixture("go.mod"),
        "go.sum": load_fixture("go.sum"),
        "requirements.txt": load_fixture("requirements.txt"),
    }
    comps = parsers.parse_files(files)
    gos = {c["name"]: c for c in comps if c["ecosystem"] == "Go"}
    assert gos["github.com/sirupsen/logrus"]["direct"] is True
    assert any(c["ecosystem"] == "PyPI" for c in comps)


def test_parse_files_robust_to_bad_entries():
    files = {
        "package-lock.json": "{not json",
        "pom.xml": "<broken",
        "Cargo.lock": load_fixture("Cargo.lock"),
        "ignored.bin": 12345,  # non-str content skipped
    }
    comps = parsers.parse_files(files)
    # only the valid Cargo.lock contributes
    assert any(c["ecosystem"] == "crates.io" for c in comps)
    assert all(c["ecosystem"] == "crates.io" for c in comps)
