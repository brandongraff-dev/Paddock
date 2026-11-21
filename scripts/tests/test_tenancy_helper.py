"""The per-service tenant helper: no copy may drift from shared/paddock_tenancy.py,
and the helper's own contract (header trust, event binding, merge) holds.

Run from the repo root:  pytest -q scripts/tests/test_tenancy_helper.py
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import sync_tenancy_helper as sync  # noqa: E402

spec = importlib.util.spec_from_file_location("paddock_tenancy_under_test", ROOT / "shared" / "paddock_tenancy.py")
T = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = T
spec.loader.exec_module(T)

A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def test_every_service_copy_is_identical_to_the_canonical_helper():
    assert sync.main(["--check"]) == 0, "run: python scripts/sync_tenancy_helper.py"
    assert len(sync.target_paths()) == 15


def test_service_dockerfiles_copy_the_app_directory_that_holds_the_helper():
    for p in sync.target_paths():
        svc = p.parents[1]
        df = svc / "Dockerfile"
        if df.exists():
            txt = df.read_text()
            assert "COPY app ./app" in txt or "COPY app/ ./app/" in txt or "COPY app /app/app" in txt, svc


def test_tenant_header_needs_the_service_key(monkeypatch):
    monkeypatch.delenv("TENANCY_STRICT", raising=False)
    monkeypatch.setenv("SERVICE_API_KEY", "k")
    assert T.request_tenant({}) is None
    assert T.request_tenant({"X-Paddock-Tenant": A, "X-API-Key": "k"}) == A
    for bad in ({"X-Paddock-Tenant": A}, {"X-Paddock-Tenant": A, "X-API-Key": "nope"}):
        with pytest.raises(T.TenantError):
            T.request_tenant(bad)
    with pytest.raises(T.TenantError):
        T.request_tenant({"X-Paddock-Tenant": "not-a-uuid", "X-API-Key": "k"})


def test_header_is_not_honoured_without_a_key_in_strict_mode(monkeypatch):
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)
    assert T.request_tenant({"X-Paddock-Tenant": A}) == A  # dev: open network
    monkeypatch.setenv("TENANCY_STRICT", "true")
    with pytest.raises(T.TenantError):
        T.request_tenant({"X-Paddock-Tenant": A})


def test_context_default_strict_and_outbound(monkeypatch):
    monkeypatch.delenv("TENANCY_STRICT", raising=False)
    assert T.current_tenant_id() == T.DEFAULT_TENANT_ID and T.outbound_headers() == {}
    with T.tenant_context(A):
        assert T.outbound_headers() == {"X-Paddock-Tenant": A}
        with T.platform_context():
            assert T.current_tenant_id() == T.DEFAULT_TENANT_ID
        assert T.current_tenant_id() == A
    monkeypatch.setenv("TENANCY_STRICT", "true")
    assert T.current_tenant_id() is None


def test_events_and_jobs_bind_and_stamp(monkeypatch):
    monkeypatch.delenv("TENANCY_STRICT", raising=False)
    with T.bind_job({"tenant_id": A, "scan_id": "s1"}):
        assert T.outbound_headers() == {"X-Paddock-Tenant": A, "X-Paddock-Scan": "s1"}
        assert T.stamp_event({"event": "x"})["tenant_id"] == A
    assert T.stamp_event({"event": "x", "tenant_id": "keep"})["tenant_id"] == "keep"
    assert T.outbound_headers() == {}


def test_merge_counts_sums_and_raises_only_when_everything_failed():
    out = T.merge_counts({"t1": {"n": 2, "ok": True, "x": "s"}, "t2": {"n": 3}, "t3": RuntimeError("boom")})
    assert out == {"tenants": 3, "failed": 1, "n": 5}
    with pytest.raises(RuntimeError):
        T.merge_counts({"t1": RuntimeError("a"), "t2": RuntimeError("b")})
