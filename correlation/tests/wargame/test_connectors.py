"""Tests for the read-only config-source connectors (no network)."""
from __future__ import annotations

import json
import os

import pytest

from app.engine.wargame.connectors import (
    AwsApiConfigSource,
    ConfigSource,
    ConfigSourceError,
    FileConfigSource,
    InMemoryConfigSource,
    collect,
    collect_map,
)
from app.engine.wargame.parsers import WarningLevel, parse

FIX = os.path.join(os.path.dirname(__file__), "parsers", "fixtures")
ASA = os.path.join(FIX, "cisco_asa.conf")
SGS = os.path.join(FIX, "aws_security_groups.json")
NACLS = os.path.join(FIX, "aws_network_acls.json")


def _load(name: str) -> dict:
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


class FakeEc2:
    """Stub EC2 client: only the two Describe calls, records what was called."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def describe_security_groups(self) -> dict:
        self.calls.append("describe_security_groups")
        return _load("aws_security_groups.json")

    def describe_network_acls(self) -> dict:
        self.calls.append("describe_network_acls")
        return _load("aws_network_acls.json")


def test_in_memory_fetch_and_parse():
    with open(ASA, encoding="utf-8") as fh:
        text = fh.read()
    src = InMemoryConfigSource("cisco_asa", text)
    assert isinstance(src, ConfigSource)
    assert src.fetch() == text
    assert parse(src.vendor, src.fetch()).rulesets


def test_file_source_text_and_json():
    asa = FileConfigSource("cisco_asa", ASA)
    assert isinstance(asa.fetch(), str)
    assert parse("cisco_asa", asa.fetch()).rulesets
    aws = FileConfigSource("aws", SGS)
    assert isinstance(aws.fetch(), dict)
    assert parse("aws", aws.fetch()).rulesets


def test_file_source_missing_raises_with_path(tmp_path):
    missing = str(tmp_path / "nope.conf")
    with pytest.raises(ConfigSourceError) as ei:
        FileConfigSource("cisco_asa", missing).fetch()
    assert missing in str(ei.value)


def test_file_source_bad_json_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigSourceError):
        FileConfigSource("aws", str(bad)).fetch()


def test_aws_api_source_with_fake_client():
    client = FakeEc2()
    src = AwsApiConfigSource(client=client)
    raw = src.fetch()
    assert set(raw) == {"SecurityGroups", "NetworkAcls"}
    assert raw["SecurityGroups"] and raw["NetworkAcls"]
    assert sorted(client.calls) == ["describe_network_acls", "describe_security_groups"]
    assert src.fetch() == raw  # idempotent
    ids = set(parse("aws", raw).rulesets)
    assert any(i.startswith("sg-") for i in ids)
    assert any(i.startswith("acl-") for i in ids)


def test_aws_api_source_without_client_raises():
    with pytest.raises(ConfigSourceError, match="no AWS client supplied"):
        AwsApiConfigSource(client=None).fetch()


def test_aws_api_source_client_failure_is_source_error():
    class Boom:
        def describe_security_groups(self):
            raise RuntimeError("AccessDenied")

        def describe_network_acls(self):  # pragma: no cover
            return {}

    with pytest.raises(ConfigSourceError):
        AwsApiConfigSource(client=Boom()).fetch()


def _sources(tmp_path):
    return [
        FileConfigSource("cisco_asa", ASA),
        FileConfigSource("aws", str(tmp_path / "missing.json")),
        AwsApiConfigSource(client=FakeEc2()),
    ]


def test_collect_merges_and_skips_broken(tmp_path):
    res = collect(_sources(tmp_path))
    asa_ids = set(parse("cisco_asa", FileConfigSource("cisco_asa", ASA).fetch()).rulesets)
    aws_ids = set(parse("aws", AwsApiConfigSource(client=FakeEc2()).fetch()).rulesets)
    assert asa_ids and aws_ids
    assert (asa_ids | aws_ids) <= set(res.rulesets)
    assert res.vendor == "multi"
    skipped = [w for w in res.warnings if "source skipped" in w.message]
    assert len(skipped) == 1
    assert skipped[0].level == WarningLevel.UNSUPPORTED
    assert "missing.json" in skipped[0].message
    assert skipped[0].ref == "aws#1"


def test_collect_single_vendor_and_empty():
    one = collect([FileConfigSource("cisco_asa", ASA)])
    assert one.vendor == "cisco_asa"
    assert collect([]).vendor == "multi"


def test_collect_map_keys_and_isolation(tmp_path):
    m = collect_map(_sources(tmp_path))
    assert list(m) == ["cisco_asa#0", "aws#1", "aws#2"]
    assert m["cisco_asa#0"].rulesets
    assert not m["aws#1"].rulesets and m["aws#1"].warnings
    assert m["aws#2"].rulesets


def test_collect_deterministic(tmp_path):
    a = collect(_sources(tmp_path))
    b = collect(_sources(tmp_path))
    assert list(a.rulesets) == list(b.rulesets)
    assert [str(w) for w in a.warnings] == [str(w) for w in b.warnings]
    assert a.bindings == b.bindings
