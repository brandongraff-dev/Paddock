"""P3.2: estate bootstrap (docs/ASSURANCE_P3.md 5.1): the random estate id and the sealed ``commit_key``.

``ensure_estate`` is lazy, idempotent and concurrency-safe; without a KEK or platform issuer material it creates
nothing (``not_configured``). It does not create keys or publications (P3.3 and P3.6 build on it).
"""
from __future__ import annotations

import asyncio
import json
import re

import pytest
import pytest_asyncio
from pydantic import SecretStr

from app import tenancy
from app.attest import config as attest_config
from app.attest import crypto, estate

TA = "00000000-0000-0000-0000-0000000000a1"
TB = "00000000-0000-0000-0000-0000000000b1"
DEFAULT = "00000000-0000-0000-0000-000000000001"
KEK_A = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="      # 32 x 0x07
KEK_B = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="      # 32 x 0x08
ESTATE_ID = re.compile(r"^e_[a-z2-7]{26}$")


@pytest.fixture
def configured(monkeypatch, tmp_path):
    for name in ("issuer.key", "issuer.cert", "revoker.key", "revoker.cert"):
        (tmp_path / name).write_text("placeholder material for presence checks\n")
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(KEK_A))
    monkeypatch.setattr(attest_config.settings, "kek_file", None)
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)
    for attr, name in (("issuer_key_file", "issuer.key"), ("issuer_cert_file", "issuer.cert"),
                       ("revoker_key_file", "revoker.key"), ("revoker_cert_file", "revoker.cert")):
        monkeypatch.setattr(attest_config.settings, attr, str(tmp_path / name))
    return tmp_path


@pytest_asyncio.fixture
async def tenants(db_pool):
    for slug, tid in (("est-a", TA), ("est-b", TB)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


async def _counts(pool):
    async with pool.acquire() as con:
        return {t: await con.fetchval(f"SELECT count(*) FROM {t}") for t in
                ("attest_estates", "attest_key_secrets", "attest_keys", "attest_publications")}


# --------------------------------------------------------------------------- #
# not_configured: nothing is created
# --------------------------------------------------------------------------- #

async def test_without_a_kek_nothing_is_created(db_pool, configured, monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", None)
    async with db_pool.acquire() as con:
        with pytest.raises(estate.EstateNotConfigured) as ei:
            await estate.ensure_estate(con)
    assert "kek" in ei.value.missing
    assert all(v == 0 for v in (await _counts(db_pool)).values())


@pytest.mark.parametrize("attr,gap", [
    ("issuer_key_file", "issuer_key"), ("issuer_cert_file", "issuer_cert"),
    ("revoker_key_file", "revoker_key"), ("revoker_cert_file", "revoker_cert"),
])
async def test_without_platform_issuer_material_nothing_is_created(db_pool, configured, monkeypatch, attr, gap):
    monkeypatch.setattr(attest_config.settings, attr, None)
    async with db_pool.acquire() as con:
        with pytest.raises(estate.EstateNotConfigured) as ei:
            await estate.ensure_estate(con)
    assert ei.value.missing == (gap,)
    assert all(v == 0 for v in (await _counts(db_pool)).values())


async def test_a_configured_path_that_does_not_exist_or_is_empty_counts_as_missing(db_pool, configured, monkeypatch):
    monkeypatch.setattr(attest_config.settings, "issuer_key_file", str(configured / "nope"))
    (configured / "empty").write_text("")
    monkeypatch.setattr(attest_config.settings, "revoker_cert_file", str(configured / "empty"))
    assert estate.configuration_gaps() == ["issuer_key", "revoker_cert"]


async def test_a_broken_kek_is_not_configured_not_a_crash(db_pool, configured, monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr("not a key"))
    assert estate.configuration_gaps() == ["kek"]
    async with db_pool.acquire() as con:
        with pytest.raises(estate.EstateNotConfigured):
            await estate.ensure_estate(con)
    assert all(v == 0 for v in (await _counts(db_pool)).values())


async def test_status_reports_not_configured_pending_and_ready(db_pool, configured, monkeypatch):
    async with db_pool.acquire() as con:
        st = await estate.status(con)
        assert (st.state, st.missing, st.estate_id) == ("pending", (), None)
        await estate.ensure_estate(con)
        st = await estate.status(con)
        assert st.state == "ready" and ESTATE_ID.match(st.estate_id)
        monkeypatch.setattr(attest_config.settings, "kek", None)
        st = await estate.status(con)
        assert st.state == "not_configured" and "kek" in st.missing and st.estate_id is not None


async def test_status_never_creates_anything(db_pool, configured):
    async with db_pool.acquire() as con:
        await estate.status(con)
        assert await estate.get_estate(con) is None
    assert all(v == 0 for v in (await _counts(db_pool)).values())


# --------------------------------------------------------------------------- #
# creation
# --------------------------------------------------------------------------- #

async def test_ensure_estate_creates_the_estate_id_and_a_sealed_commit_key(db_pool, configured):
    async with db_pool.acquire() as con:
        info = await estate.ensure_estate(con)
        assert ESTATE_ID.match(info.estate_id)
        assert (info.tenant_id, info.ttl_h, info.issuing_suspended, info.hold_requires_ack) == (DEFAULT, 24, False, False)
        key = await estate.get_commit_key(con)
        row = await con.fetchrow("SELECT kind, kid, sealed FROM attest_key_secrets")
    assert isinstance(key, bytes) and len(key) == 32 and key != b"\x00" * 32
    assert (row["kind"], row["kid"]) == ("commit", "commit")
    assert row["sealed"].startswith("v1:") and key.hex() not in row["sealed"]
    c = await _counts(db_pool)
    assert c == {"attest_estates": 1, "attest_key_secrets": 1, "attest_keys": 0, "attest_publications": 0}


async def test_ensure_estate_is_idempotent(db_pool, configured):
    async with db_pool.acquire() as con:
        a = await estate.ensure_estate(con)
        key = await estate.get_commit_key(con)
        b = await estate.ensure_estate(con)
        assert a == b and await estate.get_commit_key(con) == key
    assert (await _counts(db_pool))["attest_key_secrets"] == 1


async def test_concurrent_ensure_estate_yields_one_estate_and_one_commit_key(db_pool, configured):
    async def one():
        async with db_pool.acquire() as con:
            return await estate.ensure_estate(con)

    got = await asyncio.gather(*[one() for _ in range(4)])
    assert len({g.estate_id for g in got}) == 1
    assert (await _counts(db_pool))["attest_estates"] == 1
    assert (await _counts(db_pool))["attest_key_secrets"] == 1
    async with db_pool.acquire() as con:
        assert len(await estate.get_commit_key(con)) == 32


async def test_the_estate_row_is_locked_while_it_is_filled_in(db_pool, configured):
    """Two callers that both see an unfilled estate row must not each create an estate id: ensure_estate takes the row
    lock (FOR UPDATE) and re-reads after it, so the loser sees the winner's id and writes no second audit row."""
    winner = "e_" + "a" * 26
    async with db_pool.acquire() as holder:
        await holder.execute("INSERT INTO attest_estates (tenant_id) VALUES ($1::uuid)", DEFAULT)
        tx = holder.transaction()
        await tx.start()
        await holder.fetchrow("SELECT estate_id FROM attest_estates WHERE tenant_id = $1::uuid FOR UPDATE", DEFAULT)

        async def caller():
            async with db_pool.acquire() as con:
                return await estate.ensure_estate(con)

        task = asyncio.ensure_future(caller())
        await asyncio.sleep(0.6)
        assert not task.done(), "ensure_estate did not wait for the row lock"
        await holder.execute("UPDATE attest_estates SET estate_id = $2 WHERE tenant_id = $1::uuid", DEFAULT, winner)
        await tx.commit()
        info = await asyncio.wait_for(task, 10)
    assert info.estate_id == winner
    assert await db_pool.fetchval("SELECT count(*) FROM audit_log WHERE action = 'attest.estate.created'") == 0
    assert (await _counts(db_pool))["attest_key_secrets"] == 0


async def test_each_tenant_gets_its_own_estate_and_commit_key(db_pool, app_pool, configured, tenants):
    out = {}
    for tid in (TA, TB):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                info = await estate.ensure_estate(con)
                out[tid] = (info.estate_id, await estate.get_commit_key(con), info.tenant_id)
    assert out[TA][0] != out[TB][0] and out[TA][1] != out[TB][1]
    assert (out[TA][2], out[TB][2]) == (TA, TB)
    # a tenant sees only its own estate and commit key
    with tenancy.tenant_context(TB):
        async with app_pool.acquire() as con:
            assert (await estate.get_estate(con)).estate_id == out[TB][0]
            assert await con.fetchval("SELECT count(*) FROM attest_estates") == 1
    assert (await _counts(db_pool))["attest_key_secrets"] == 2


async def test_estate_ids_are_random_and_not_derived_from_the_tenant(db_pool, configured):
    ids = {estate.new_estate_id() for _ in range(200)}
    assert len(ids) == 200 and all(ESTATE_ID.match(i) for i in ids)
    assert all(DEFAULT.replace("-", "")[:8] not in i for i in ids)


async def test_the_audit_row_names_the_estate_and_never_key_material(db_pool, configured):
    async with db_pool.acquire() as con:
        info = await estate.ensure_estate(con)
        await estate.ensure_estate(con)
        key = await estate.get_commit_key(con)
        sealed = await con.fetchval("SELECT sealed FROM attest_key_secrets")
        rows = await con.fetch("SELECT action, resource_type, resource_id, details FROM audit_log WHERE action LIKE 'attest.%'")
    assert [r["action"] for r in rows] == ["attest.estate.created"]            # once, not on the second call
    r = rows[0]
    assert r["resource_id"] == info.estate_id
    blob = json.dumps(dict(r), default=str)
    import base64
    for bad in (key.hex(), base64.b64encode(key).decode(), base64.urlsafe_b64encode(key).decode(), sealed):
        assert bad not in blob


async def test_creation_is_atomic_a_failed_commit_key_store_leaves_no_estate(db_pool, configured, monkeypatch):
    real = crypto.store_secret

    async def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(crypto, "store_secret", boom)
    async with db_pool.acquire() as con:
        with pytest.raises(RuntimeError):
            await estate.ensure_estate(con)
    assert all(v == 0 for v in (await _counts(db_pool)).values())
    monkeypatch.setattr(crypto, "store_secret", real)
    async with db_pool.acquire() as con:                       # a later call succeeds from scratch
        assert ESTATE_ID.match((await estate.ensure_estate(con)).estate_id)


async def test_a_half_created_estate_row_is_completed_not_duplicated(db_pool, configured):
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO attest_estates (tenant_id) VALUES ($1::uuid)", DEFAULT)      # estate_id ''
        assert await estate.get_estate(con) is None                                              # not an estate yet
        info = await estate.ensure_estate(con)
        assert ESTATE_ID.match(info.estate_id)
        assert len(await estate.get_commit_key(con)) == 32
    assert (await _counts(db_pool))["attest_estates"] == 1


async def test_a_lost_commit_key_is_an_error_never_silently_replaced(db_pool, configured):
    """D29: losing commit_key loses the ability to prove leaves, never root validity. Silently minting a new one would
    change every blinded root without anyone noticing, so ensure_estate leaves it and get_commit_key refuses."""
    async with db_pool.acquire() as con:
        info = await estate.ensure_estate(con)
        await con.execute("DELETE FROM attest_key_secrets")
        again = await estate.ensure_estate(con)
        assert again == info
        with pytest.raises(estate.CommitKeyMissing):
            await estate.get_commit_key(con)
        assert await con.fetchval("SELECT count(*) FROM attest_key_secrets") == 0


async def test_get_commit_key_before_any_estate_raises(db_pool, configured):
    async with db_pool.acquire() as con:
        with pytest.raises(estate.CommitKeyMissing):
            await estate.get_commit_key(con)


async def test_get_commit_key_without_a_kek_is_not_configured(db_pool, configured, monkeypatch):
    async with db_pool.acquire() as con:
        await estate.ensure_estate(con)
        monkeypatch.setattr(attest_config.settings, "kek", None)
        with pytest.raises(estate.EstateNotConfigured):
            await estate.get_commit_key(con)


async def test_a_commit_blob_swapped_between_tenants_does_not_open(db_pool, app_pool, configured, tenants):
    for tid in (TA, TB):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                await estate.ensure_estate(con)
    await db_pool.execute(
        "UPDATE attest_key_secrets SET sealed = (SELECT sealed FROM attest_key_secrets WHERE tenant_id = $1::uuid) "
        "WHERE tenant_id = $2::uuid", TA, TB)
    with tenancy.tenant_context(TB):
        async with app_pool.acquire() as con:
            with pytest.raises(estate.EstateError):
                await estate.get_commit_key(con)
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            assert len(await estate.get_commit_key(con)) == 32


async def test_the_commit_key_survives_a_kek_rotation(db_pool, configured, monkeypatch):
    async with db_pool.acquire() as con:
        await estate.ensure_estate(con)
        before = await estate.get_commit_key(con)
        monkeypatch.setattr(attest_config.settings, "kek", SecretStr(KEK_B))
        monkeypatch.setattr(attest_config.settings, "kek_previous", SecretStr(KEK_A))
        assert await estate.get_commit_key(con) == before
        monkeypatch.setattr(attest_config.settings, "kek_previous", None)
        with pytest.raises(estate.EstateError):
            await estate.get_commit_key(con)


async def test_a_connection_for_another_tenant_than_the_context_is_refused(db_pool, app_pool, configured, tenants):
    """The tenant is part of the AAD: a context that disagrees with the connection must not create an estate."""
    async with db_pool.acquire() as con:                      # superuser, unstamped: tenant = default
        with tenancy.tenant_context(TA):
            with pytest.raises(estate.EstateError, match="tenant"):
                await estate.ensure_estate(con)
    assert all(v == 0 for v in (await _counts(db_pool)).values())


async def test_new_estate_id_matches_the_database_check(db_pool):
    async with db_pool.acquire() as con:
        for _ in range(20):
            assert await con.fetchval("SELECT $1::text ~ '^e_[a-z2-7]{26}$'", estate.new_estate_id()) is True
