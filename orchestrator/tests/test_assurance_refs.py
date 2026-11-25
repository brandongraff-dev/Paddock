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
