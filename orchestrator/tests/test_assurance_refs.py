import uuid

import pytest

from app.assurance import refs


def test_canonical_refs():
    u = uuid.uuid4()
    assert refs.asset_ref(str(u).upper()) == f"asset:{u}"
    assert refs.ip_ref("2001:DB8:0:0::1") == "ip:2001:db8::1"
    assert refs.ip_ref("[2001:db8::1]") == "ip:2001:db8::1"
    assert refs.cidr_ref("10.0.0.5/24") == "cidr:10.0.0.0/24"
    for r in (refs.INTERNET, refs.asset_ref(u), refs.ip_ref("10.1.2.3"), refs.cidr_ref("10.0.0.0/8")):
        assert refs.is_valid_ref(r)


@pytest.mark.parametrize("bad", ["", "ip:", "ip:999.1.1.1", "ip:10.0.0.1/8", "cidr:nope", "asset:123",
                                 "host:web", "IP:10.0.0.1", "ip:2001:DB8::1", "x" * 200, "internet:1"])
def test_bad_refs_rejected(bad):
    assert not refs.is_valid_ref(bad)


def test_tags():
    assert refs.is_valid_tag("app-tier") and refs.is_valid_tag("zone")
    assert not refs.is_valid_tag("App Tier") and not refs.is_valid_tag("")


def test_agent_refs():
    u = uuid.uuid4()
    assert refs.agent_ref(str(u).upper()) == f"agent:{u}"
    assert refs.parse_ref(f"agent:{u}") == ("agent", str(u))
    assert refs.is_valid_ref(f"agent:{u}")
    assert refs.KINDS.count("host") == 1 and "agent" not in refs.KINDS      # an agent node is kind 'host'
    for bad in ("agent:", "agent:123", f"agent:{str(u).upper()}", f"agent:{u.hex}", f"AGENT:{u}", f"agent:{u} "):
        assert not refs.is_valid_ref(bad), bad
    with pytest.raises(refs.RefError):
        refs.agent_ref("not-a-uuid")


# --------------------------------------------------------------------------- #
# estate: the residual node of a security group whose membership is not proven
# (docs/ASSURANCE_P2_1.md section 5.2, D31)
# --------------------------------------------------------------------------- #

def test_estate_ref_is_canonical_and_parses_back():
    r = refs.estate_ref("123456789012", "us-east-1", "vpc-0abc123")
    assert r == "estate:123456789012:us-east-1:vpc-0abc123"
    assert refs.parse_ref(r) == ("estate", "123456789012:us-east-1:vpc-0abc123")
    assert refs.is_valid_ref(r)
    assert refs.estate_ref("123456789012", "eu-west-2", None) == "estate:123456789012:eu-west-2:none"
    assert refs.estate_ref("123456789012", "eu-west-2", "") == "estate:123456789012:eu-west-2:none"
    assert refs.estate_ref("123456789012", "eu-west-2", "none") == "estate:123456789012:eu-west-2:none"
    assert refs.is_valid_ref("estate:000000000001:us-gov-west-1:none")


@pytest.mark.parametrize("region", ["eusc-de-east-1", "us-gov-west-1", "us-iso-east-1", "us-isob-east-1",
                                    "ap-southeast-4", "il-central-1", "me-central-1"])
def test_estate_ref_accepts_every_aws_partition_region_spelling(region):
    # a region we cannot spell would drop the residual into the world-open fallback (over-report, never under)
    r = refs.estate_ref("123456789012", region, "none")
    assert r == f"estate:123456789012:{region}:none" and refs.is_valid_ref(r)


def test_estate_is_a_node_kind_and_a_ref_prefix_but_not_an_agent_style_kind():
    assert "estate" in refs.KINDS
    assert "estate" in refs._PREFIXES
    assert refs.KINDS.count("estate") == 1


@pytest.mark.parametrize("acct", ["", "12345678901", "1234567890123", "12345678901a", "１２３４５６７８９０１２",
                                  " 123456789012", "123456789012\n", None, 123456789012])
def test_estate_ref_rejects_a_bad_account(acct):
    with pytest.raises(refs.RefError):
        refs.estate_ref(acct, "us-east-1", "none")


@pytest.mark.parametrize("region", ["", "US-EAST-1", "us-east", "useast1", "us-east-1:x", "us_east_1", "x" * 40,
                                    "us-east-1 ", "us--east-1", "-us-east-1", None])
def test_estate_ref_rejects_a_bad_region(region):
    with pytest.raises(refs.RefError):
        refs.estate_ref("123456789012", region, "none")


@pytest.mark.parametrize("vpc", ["vpc-", "VPC-0abc", "vpc-0ABC", "vpc-xyz", "subnet-0abc", "vpc-0abc:1", "vpc-" + "a" * 40,
                                 "vpc-0abc ", "None", "NONE"])
def test_estate_ref_rejects_a_bad_vpc(vpc):
    with pytest.raises(refs.RefError):
        refs.estate_ref("123456789012", "us-east-1", vpc)


@pytest.mark.parametrize("bad", ["estate:", "estate:123456789012", "estate:123456789012:us-east-1",
                                 "estate:123456789012:us-east-1:", "estate:123456789012:us-east-1:vpc-0abc:extra",
                                 "ESTATE:123456789012:us-east-1:none", "estate:123456789012:US-EAST-1:none",
                                 "estate:12345:us-east-1:none", "estate:123456789012:us-east-1:vpc-0ABC",
                                 "estate:123456789012:us-east-1:NONE", "estate:123456789012:us-east-1:vpc-0abc ",
                                 "estate:123456789012:us-east-1:none\n"])
def test_bad_or_non_canonical_estate_refs_are_rejected(bad):
    assert not refs.is_valid_ref(bad)


def test_an_estate_ref_stays_inside_the_ref_length_cap():
    assert len(refs.estate_ref("123456789012", "ap-southeast-4", "vpc-" + "a" * 32)) <= 128
    assert not refs.is_valid_ref("estate:123456789012:us-east-1:vpc-" + "a" * 120)
