from __future__ import annotations

from app.parsers import cargo, go, maven, ruby
from tests.conftest import load_fixture


def _by_name(components):
    return {c["name"]: c for c in components}


# ---- Go ----
def test_go_sum_with_gomod_directs():
    comps = go.parse_go(load_fixture("go.sum"), load_fixture("go.mod"))
    by = _by_name(comps)
    assert by["github.com/sirupsen/logrus"]["version"] == "v1.9.0"
    assert by["github.com/sirupsen/logrus"]["direct"] is True
    assert by["github.com/gin-gonic/gin"]["direct"] is True
    # indirect dep in go.mod -> transitive
    assert by["github.com/bytedance/sonic"]["direct"] is False
    assert by["github.com/sirupsen/logrus"]["ecosystem"] == "Go"


def test_go_sum_without_gomod_all_indirect():
    comps = go.parse_go(load_fixture("go.sum"))
    assert all(c["direct"] is False for c in comps)
    assert len(comps) == 3  # deduped across zip + /go.mod lines


def test_go_malformed():
    assert go.parse_go("garbage\nlines\n") == []


# ---- Cargo ----
def test_cargo_lock_graph():
    comps = cargo.parse_cargo_lock(load_fixture("Cargo.lock"))
    by = _by_name(comps)
    assert by["serde"]["version"] == "1.0.164"
    assert by["demo"]["direct"] is True        # root crate
    assert by["tokio"]["direct"] is False      # pulled by reqwest
    assert "reqwest" in by["tokio"]["paths"]
    assert by["serde"]["ecosystem"] == "crates.io"


def test_cargo_malformed():
    assert cargo.parse_cargo_lock("::: not toml") == []


# ---- Maven ----
def test_pom_xml_properties_resolved():
    comps = maven.parse_pom(load_fixture("pom.xml"))
    by = _by_name(comps)
    assert "com.google.guava:guava" in by
    assert by["com.google.guava:guava"]["version"] == "31.1-jre"
    # ${jackson.version} resolved from <properties>
    assert by["com.fasterxml.jackson.core:jackson-databind"]["version"] == "2.13.0"
    assert all(c["ecosystem"] == "Maven" for c in comps)


def test_pom_malformed():
    assert maven.parse_pom("<project><broken>") == []
    assert maven.parse_pom("") == []


# ---- Ruby ----
def test_gemfile_lock_graph():
    comps = ruby.parse_gemfile_lock(load_fixture("Gemfile.lock"))
    by = _by_name(comps)
    assert by["sinatra"]["version"] == "3.0.6"
    assert by["sinatra"]["direct"] is True      # listed in DEPENDENCIES
    assert by["rack"]["direct"] is False         # pulled by sinatra
    assert "sinatra" in by["rack"]["paths"]
    assert by["sinatra"]["ecosystem"] == "RubyGems"


def test_gemfile_malformed():
    assert ruby.parse_gemfile_lock("") == []
    assert ruby.parse_gemfile_lock("random text") == []
