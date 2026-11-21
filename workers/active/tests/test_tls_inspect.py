from __future__ import annotations

import json

import pytest

from app.modules import tls_inspect
from tests.conftest import FakeProcess


pytestmark = pytest.mark.asyncio


async def test_expired_cert_flagged(fake_orch, scope, politeness, fake_subprocess):
    row = {
        "host": "example.com",
        "tls_version": ["TLSv1.2"],
        "cipher": "TLS_AES_128_GCM_SHA256",
        "certificate": {
            "subject_cn": "example.com",
            "issuer_cn": "Let's Encrypt R3",
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": "2020-02-01T00:00:00Z",
            "sha256": "deadbeef" * 8,
            "subject_an": ["example.com"],
            "self_signed": False,
        },
    }
    fake_subprocess.register(
        "tlsx", lambda args: FakeProcess(stdout_bytes=(json.dumps(row) + "\n").encode()),
    )
    r = await tls_inspect.inspect(
        "example.com:443", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    rules = {f["rule_id"] for f in r["findings"]}
    assert "expired-certificate" in rules
    assert "missing-tls-1-3" in rules


async def test_weak_cipher_and_legacy_tls(fake_orch, scope, politeness, fake_subprocess):
    row = {
        "host": "example.com",
        "tls_version": ["TLSv1.0", "TLSv1.3"],
        "cipher": "TLS_RSA_WITH_RC4_128_SHA",
        "certificate": {
            "subject_cn": "example.com",
            "issuer_cn": "Example CA",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2030-01-01T00:00:00Z",
            "sha256": "beefdead" * 8,
            "subject_an": ["example.com"],
        },
    }
    fake_subprocess.register("tlsx", lambda args: FakeProcess(stdout_bytes=(json.dumps(row) + "\n").encode()))
    r = await tls_inspect.inspect(
        "example.com:443", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    rules = {f["rule_id"] for f in r["findings"]}
    assert "weak-cipher" in rules
    assert "legacy-tls-version" in rules
