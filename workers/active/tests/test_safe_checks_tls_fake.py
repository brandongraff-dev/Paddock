"""Decision logic of the TLS weak-cipher check with a scripted handshake
(the local OpenSSL build may not be able to offer 3DES, so a real server
cannot exercise the "still accepted" branch everywhere)."""
from __future__ import annotations

import pytest

from app.modules import safe_checks
from app.modules.safe_checks import CheckEnv, FindingCtx
from app.modules.safe_checks import tls as tls_mod
from app.scope_guard import ScopeGuard

from .conftest import FakeOrchestratorClient

pytestmark = pytest.mark.asyncio


async def test_weak_cipher_decisions_with_a_fake_handshake(politeness, monkeypatch):
    orch = FakeOrchestratorClient()
    scope = ScopeGuard(orch, ttl_sec=60)
    monkeypatch.setattr(tls_mod, "_offerable", lambda fams: ["DES-CBC3-SHA"])
    calls = []

    def make(accept_weak):
        async def hs(host, port, **kw):
            calls.append(kw)
            if kw.get("ciphers"):
                return tls_mod.Handshake(
                    accept_weak, version="TLSv1.2" if accept_weak else None,
                    cipher="DES-CBC3-SHA" if accept_weak else None,
                    error=None if accept_weak else "handshake failure",
                    reason=None if accept_weak else "SSLV3_ALERT_HANDSHAKE_FAILURE")
            return tls_mod.Handshake(True, version="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256")
        return hs

    f = FindingCtx(id="1", rule_id="weak-cipher", rule_source="tls_check",
                   evidence={"port": 443, "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
                   asset_value="example.com:443")
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch, tls_handshake=make(True))
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.evidence["negotiated"] == "DES-CBC3-SHA"
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch, tls_handshake=make(False))
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"
    # the weak-only offer is a handshake with an explicit weak cipher list
    assert any(c.get("ciphers", "").startswith("DES-CBC3-SHA") for c in calls)


async def test_a_network_failure_during_the_weak_probe_is_inconclusive(politeness, monkeypatch):
    orch = FakeOrchestratorClient()
    scope = ScopeGuard(orch, ttl_sec=60)
    monkeypatch.setattr(tls_mod, "_offerable", lambda fams: ["DES-CBC3-SHA"])

    async def hs(host, port, **kw):
        if kw.get("ciphers"):
            return tls_mod.Handshake(False, error="timeout", network=True)
        return tls_mod.Handshake(True, version="TLSv1.2", cipher="X")

    f = FindingCtx(id="1", rule_id="weak-cipher", rule_source="tls_check",
                   evidence={"cipher": "DES-CBC3-SHA"}, asset_value="example.com:443")
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch, tls_handshake=hs)
    assert (await safe_checks.run(f, env)).verdict == "inconclusive"
