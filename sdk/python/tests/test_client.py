from __future__ import annotations

import importlib
import subprocess
import sys
import typing
import warnings
from pathlib import Path

import httpx
import pytest

import paddock_sdk
from paddock_sdk import (
    NO_RETRY,
    FeatureNotLicensed,
    NotFound,
    PaddockClient,
    PermissionDenied,
    RetryPolicy,
    ServerError,
    TransportError,
    ValidationError,
)
from paddock_sdk import _generated as gen

HERE = Path(__file__).resolve().parent


def test_auth_header_api_key(client, api):
    api.on("GET", "/v1/auth/me", {"actor": "alice", "role": "admin"})
    assert client.me()["actor"] == "alice"
    req = api.calls[0]
    assert req.headers["authorization"] == "Bearer pak_abcd1234_secret"
    assert req.headers["user-agent"].startswith("paddock-sdk-python/")


def test_env_credentials(monkeypatch, api):
    monkeypatch.setenv("PADDOCK_URL", "http://env.test/")
    monkeypatch.setenv("PADDOCK_TOKEN", "eyJ.jwt")
    monkeypatch.delenv("PADDOCK_API_KEY", raising=False)
    api.on("GET", "/v1/auth/me", {"actor": "bob"})
    with PaddockClient(transport=httpx.MockTransport(api)) as c:
        assert c.base_url == "http://env.test"
        c.me()
    assert api.calls[0].headers["authorization"] == "Bearer eyJ.jwt"
    assert str(api.calls[0].url).startswith("http://env.test/v1/auth/me")


def test_login_switches_to_jwt(client, api):
    api.on("POST", "/v1/auth/login", {"access_token": "eyJ.new", "expires_in": 3600, "role": "admin",
                                       "clearance": "restricted"})
    api.on("GET", "/v1/auth/me", {"actor": "admin"})
    client.login_with_password("admin", "pw")
    assert api.body(0) == {"username": "admin", "password": "pw"}
    client.me()
    assert api.calls[-1].headers["authorization"] == "Bearer eyJ.new"


def test_path_and_query_encoding(client, api):
    api.on("GET", "/v1/findings", {"items": [], "total": 0, "limit": 10, "offset": 0})
    client.list_findings_paged(severity="high", kev=True, q=None, limit=10)
    url = api.calls[0].url
    assert url.params["severity"] == "high"
    assert url.params["kev"] == "true"
    assert "q" not in url.params
    api.on("GET", "/v1/scans/a/b", {"id": "x"})  # url.path is the decoded form
    client.get_scan("a/b")
    assert api.calls[-1].url.raw_path == b"/v1/scans/a%2Fb"


def test_body_is_json(client, api):
    api.on("POST", "/v1/scope", httpx.Response(201, json={"id": 7}))
    out = client.add_scope({"kind": "domain", "value": "example.com", "added_by": "me"})
    assert out == {"id": 7}
    assert api.body() == {"kind": "domain", "value": "example.com", "added_by": "me"}


def test_204_returns_none(client, api):
    api.on("DELETE", "/v1/owners/abc", httpx.Response(204))
    assert client.delete_owner("abc") is None


def test_retry_idempotent_on_503(client, api, sleeps):
    api.on("GET", "/v1/scope", [httpx.Response(503), httpx.Response(503), httpx.Response(200, json=[])])
    assert client.list_scope() == []
    assert len(api.calls) == 3 and len(sleeps) == 2


def test_retry_gives_up(client, api, sleeps):
    api.on("GET", "/v1/scope", httpx.Response(502, json={"detail": "bad gateway"}))
    with pytest.raises(ServerError) as ei:
        client.list_scope()
    assert ei.value.status == 502
    assert len(api.calls) == 3


def test_post_not_retried_on_5xx_but_retried_on_429(client, api, sleeps):
    api.on("POST", "/v1/scans", httpx.Response(503))
    with pytest.raises(ServerError):
        client.create_scan({"kind": "passive", "target": "example.com"})
    assert len(api.calls) == 1
    api.calls.clear()
    api.on("POST", "/v1/scans", [httpx.Response(429, headers={"Retry-After": "2"}),
                                 httpx.Response(201, json={"id": "s1"})])
    assert client.create_scan({"kind": "passive", "target": "example.com"})["id"] == "s1"
    assert sleeps[-1] == 2.0


def test_transport_errors_retried_then_raised(api, sleeps):
    def boom(_req):
        raise httpx.ConnectError("refused")

    c = PaddockClient("http://x.test", api_key="k", transport=httpx.MockTransport(boom),
                      retry=RetryPolicy(max_retries=1, sleep=sleeps.append))
    with pytest.raises(TransportError):
        c.list_scope()
    assert len(sleeps) == 1


def test_retry_delay_bounds():
    rp = RetryPolicy(backoff_factor=1, max_backoff=4)
    for attempt in range(6):
        assert 0 <= rp.delay(attempt) <= 4
    assert rp.delay(0, "100") == 4
    assert NO_RETRY.should_retry("GET", 0, 503) is False


@pytest.mark.parametrize("status,exc", [(402, FeatureNotLicensed), (403, PermissionDenied),
                                        (404, NotFound), (422, ValidationError)])
def test_error_mapping(client, api, status, exc):
    api.on("GET", "/v1/license", httpx.Response(status, json={"detail": {"error": "x"}},
                                                headers={"X-Request-ID": "rid-1"}))
    with pytest.raises(exc) as ei:
        client.get_license()
    assert ei.value.status == status
    assert ei.value.request_id == "rid-1"


def test_paginate_page_objects(client, api):
    pages = {0: list(range(3)), 3: list(range(3, 5))}

    def handler(req):
        off = int(req.url.params["offset"])
        return httpx.Response(200, json={"items": pages[off], "total": 5, "limit": 3, "offset": off})

    api.on("GET", "/v1/findings", handler)
    assert list(client.paginate(client.list_findings_paged, page_size=3, severity="high")) == [0, 1, 2, 3, 4]
    assert len(api.calls) == 2
    assert api.calls[0].url.params["severity"] == "high"


def test_paginate_lists_and_max_items(client, api):
    def handler(req):
        off, lim = int(req.url.params["offset"]), int(req.url.params["limit"])
        data = list(range(7))[off: off + lim]
        return httpx.Response(200, json=[{"id": i} for i in data])

    api.on("GET", "/v1/scope", handler)
    assert [r["id"] for r in client.paginate("list_scope", page_size=3)] == list(range(7))
    assert len(list(client.paginate(client.list_scope, page_size=3, max_items=4))) == 4


def test_deprecation_warning_once(client, api):
    api.on("GET", "/v1/findings/list", httpx.Response(
        200, json=[], headers={"Deprecation": "true", "Sunset": "Wed, 30 Jun 2027 00:00:00 GMT"}))
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        client.list_findings_legacy()
        client.list_findings_legacy()
    dep = [x for x in w if issubclass(x.category, DeprecationWarning)]
    assert len(dep) == 1 and "Sunset" not in str(dep[0].message) and "2027" in str(dep[0].message)


def test_optional_endpoints_report_missing_route(client, api):
    with pytest.raises(NotFound, match="does not provide sarif export"):
        client.export_format("sarif")
    api.on("GET", "/v1/integrations", httpx.Response(404, json={"detail": "integration not found"}))
    with pytest.raises(NotFound, match="integration not found"):
        client.integrations_list()


def test_every_operation_is_a_method():
    for name, (method, path, _pag) in gen.OPERATIONS.items():
        fn = getattr(PaddockClient, name)
        assert fn.__doc__.startswith(f"{method} {path}")


def test_models_resolve():
    for name in dir(gen):
        obj = getattr(gen, name)
        if isinstance(obj, type) and typing.is_typeddict(obj):
            typing.get_type_hints(obj)
    hints = typing.get_type_hints(PaddockClient.list_findings_paged)
    assert hints["return"] is gen.FindingPage


def test_generated_code_is_current():
    r = subprocess.run([sys.executable, str(HERE.parent / "codegen.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_public_api():
    importlib.reload(paddock_sdk)
    assert paddock_sdk.__version__
    from paddock_sdk.models import FindingOut, ScopeEntryIn  # noqa: F401
