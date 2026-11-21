"""The shared integrations contract (no DB)."""
from __future__ import annotations

import pytest

from app.integrations import EVENT_TYPES, REGISTRY, Capability, Connector, Event, register
from app.integrations import netsafety, secrets


def test_event_validates_type_and_severity():
    e = Event(type="finding.opened", title="t", severity="high")
    assert e.as_dict()["type"] == "finding.opened" and e.id
    with pytest.raises(ValueError):
        Event(type="nope", title="t")
    with pytest.raises(ValueError):
        Event(type="finding.opened", title="t", severity="urgent")
    assert "integration.test" in EVENT_TYPES


def test_register_and_describe():
    @register
    class _Demo(Connector):
        kind = "_demo_contract"
        display_name = "Demo"
        capabilities = frozenset({Capability.NOTIFY})
        secret_fields = ("token",)

    d = REGISTRY["_demo_contract"].describe()
    assert d["capabilities"] == ["notify"] and d["secret_fields"] == ["token"]
    REGISTRY.pop("_demo_contract")


def test_secrets_roundtrip_and_rotation(monkeypatch):
    import base64
    import os

    k1 = base64.urlsafe_b64encode(os.urandom(32)).decode()
    k2 = base64.urlsafe_b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("PADDOCK_SECRET_KEY", k1)
    blob = secrets.encrypt_secrets({"token": "xoxb-123"})
    assert "xoxb" not in blob
    assert secrets.decrypt_secrets(blob) == {"token": "xoxb-123"}
    monkeypatch.setenv("PADDOCK_SECRET_KEY", k2)
    monkeypatch.setenv("PADDOCK_SECRET_KEY_OLD", k1)
    assert secrets.decrypt_secrets(blob) == {"token": "xoxb-123"}   # rotation
    assert secrets.redact({"token": "x", "empty": ""}) == {"token": "********", "empty": ""}


@pytest.mark.parametrize("url", [
    "http://example.com/hook",                  # plain http
    "https://user:pw@example.com/",             # creds in URL
    "https://169.254.169.254/latest/meta-data", # metadata
    "https://10.0.0.5/hook",                    # private without opt-in
    "https://evil.com#@hooks.slack.com/",       # parser trick -> evil.com (resolves or not: never slack)
    "ftp://example.com/",
])
async def test_outbound_url_rejections(url):
    with pytest.raises(netsafety.UnsafeURL):
        u = await netsafety.validate_outbound_url(url)
        # evil.com may resolve publicly; it must at least not be treated as slack
        assert "slack" not in u.split("#")[0]
        raise netsafety.UnsafeURL("resolved to the real host, not the decoy")


async def test_private_target_allowed_only_with_opt_in():
    assert await netsafety.validate_outbound_url("https://10.0.0.5/jira", allow_private=True)
    with pytest.raises(netsafety.UnsafeURL):
        await netsafety.validate_outbound_url("https://169.254.169.254/", allow_private=True)
