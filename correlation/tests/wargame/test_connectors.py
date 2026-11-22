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


# -- audit regressions ---------------------------------------------------------

class PagedEc2:
    """Two pages per call; records every method invoked on it."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        self.calls.append(name)

        def call(NextToken=None):
            key = {"describe_security_groups": "SecurityGroups",
                   "describe_network_acls": "NetworkAcls"}[name]
            if NextToken is None:
                return {key: [{"GroupId": "sg-1"}] if key == "SecurityGroups"
                        else [{"NetworkAclId": "acl-1"}], "NextToken": "t"}
            return {key: [{"GroupId": "sg-2"}] if key == "SecurityGroups"
                    else [{"NetworkAclId": "acl-2"}]}
        return call


def test_aws_api_source_follows_pagination_and_stays_describe_only():
    client = PagedEc2()
    raw = AwsApiConfigSource(client=client).fetch()
    assert [g["GroupId"] for g in raw["SecurityGroups"]] == ["sg-1", "sg-2"]
    assert [n["NetworkAclId"] for n in raw["NetworkAcls"]] == ["acl-1", "acl-2"]
    assert client.calls and all(c.startswith("describe_") for c in client.calls)
    assert set(client.calls) <= set(AwsApiConfigSource.ALLOWED_CALLS)


def test_aws_api_source_refuses_a_non_describe_call():
    src = AwsApiConfigSource(client=FakeEc2())
    with pytest.raises(ConfigSourceError, match="non-read-only"):
        src._describe("authorize_security_group_ingress", "SecurityGroups")
    with pytest.raises(ConfigSourceError, match="non-read-only"):
        src._describe("describe_instances", "Reservations")


def test_aws_api_source_odd_responses_are_source_errors_not_crashes():
    class Odd:
        def describe_security_groups(self):
            return ["not", "a", "dict"]

        def describe_network_acls(self):  # pragma: no cover
            return {}

    with pytest.raises(ConfigSourceError):
        AwsApiConfigSource(client=Odd()).fetch()

    class Loop:
        def describe_security_groups(self, NextToken=None):
            return {"SecurityGroups": [], "NextToken": "again"}

        def describe_network_acls(self):  # pragma: no cover
            return {}

    with pytest.raises(ConfigSourceError, match="terminate"):
        AwsApiConfigSource(client=Loop()).fetch()


def test_collect_isolates_unexpected_exceptions():
    class Explodes:
        vendor = "aws"

        def fetch(self):
            raise ValueError("kaboom")

    class UnknownVendor:
        vendor = "no-such-vendor"

        def fetch(self):
            return {}

    class NoVendor:
        def fetch(self):  # pragma: no cover
            return {}

    ok = AwsApiConfigSource(client=FakeEc2())
    res = collect([Explodes(), UnknownVendor(), NoVendor(), ok])
    assert any(i.startswith("sg-") for i in res.rulesets)
    skipped = [w for w in res.warnings if "source skipped" in w.message]
    assert len(skipped) == 3
    assert "ValueError" in skipped[0].message


def test_collect_keeps_both_rulesets_when_ids_collide():
    a = InMemoryConfigSource("aws", {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]})
    b = InMemoryConfigSource("aws", {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]})
    res = collect([a, b])
    assert len(res.rulesets["sg-1"].rules) == 1
    assert len(res.rulesets["sg-1@aws#1"].rules) == 1          # not overwritten
    assert any(bd.ruleset_id == "sg-1@aws#1" for bd in res.bindings)
