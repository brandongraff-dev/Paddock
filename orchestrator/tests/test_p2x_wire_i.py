"""P2 adversarial review, round 2, package I: wire and audit residuals of the server (I-2 .. I-5).

* I-2: a flood of garbage grows the WHOLE audit log by a bounded amount (the per-request outcome row follows the
  handler's decision);
* I-3: the pre-auth limit holds under concurrency (check and hit are one step);
* I-4: replaying one captured, validly signed envelope does not burn the real agent's per-agent budget;
* I-5: the server decodes no /proc/net hex addresses (the agent branches on the byte order).

Fixtures come from ``test_fleet_posture`` (two tenants, real HTTP surface, AUTH_MODE=enforce, RLS role).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app import fleet_posture as fp

from . import p2_support  # noqa: F401  (puts the agent package on sys.path)
from .test_fleet_posture import (  # noqa: F401  (fixtures are shared on purpose)
    _reset_limiters, agent_row, enforce, enroll_host, good_posture, hb, pbytes, post, rejected, rls_app, world)

UTC = dt.timezone.utc


# =========================================================================== #
# I-2: a flood of rejected requests grows the WHOLE audit log by a bounded amount
# =========================================================================== #

def _peer(app, ip: str) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app, client=(ip, 5555)), base_url="http://test")


async def _audit_count(db) -> int:
    async with db.acquire() as con:
        return await con.fetchval("SELECT count(*) FROM audit_log")


@pytest.mark.parametrize("route,n", [("heartbeat", 300), ("posture", 120)])
async def test_i2_three_hundred_garbage_requests_do_not_write_three_hundred_audit_rows(world, rls_app, route, n):
    """Round 1 aggregated the handler's own rows, but the per-request middleware still wrote one 'create' row for
    every status >= 400 on these routes (304 rows for 300 garbage heartbeats). The handler's decision is final."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    before = await _audit_count(world.db)
    codes = Counter()
    async with _peer(rls_app, "203.0.113.9") as bad:
        for _ in range(n):
            codes[(await bad.post(f"/v1/fleet/{host.agent_id}/{route}", content=b"{}", headers=host.h)).status_code] += 1
    assert codes[400] >= 20 and codes[429] >= 1, codes          # processed rejections AND throttled ones
    grown = await _audit_count(world.db) - before
    assert grown <= 40, f"{grown} audit rows for {n} garbage requests {dict(codes)}"
    a = await agent_row(world.db, host.agent_id)
    assert a["rejected_total"] == codes[400], "the rejection counter must stay exact"


async def test_i2_verified_rejections_stay_audited_one_row_each(world, rls_app):
    """The middleware row is skipped only when the HANDLER folded the rejection into an aggregate: a rejection of a
    signed envelope (key-holder evidence) is never aggregated, so it keeps its own ``fleet.evidence.rejected`` row."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    async with _peer(rls_app, "203.0.113.9") as bad:
        for _ in range(60):
            await bad.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=b"{}", headers=host.h)
    before = len(await rejected(world.db, host))
    for i in range(3):
        env = host.env("heartbeat", seq=10 + i, issued=dt.datetime.now(UTC) - dt.timedelta(hours=3))
        r = await post(c, host, "heartbeat", env)
        assert r.status_code == 422 and r.json()["reason"] == "clock_skew"
    assert len(await rejected(world.db, host)) - before == 3


async def test_i2_a_non_rejected_data_plane_request_is_still_not_audited_per_request(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    before = await _audit_count(world.db)
    for _ in range(5):
        assert (await hb(c, host)).status_code == 200
    assert await _audit_count(world.db) == before


# =========================================================================== #
# I-3: the pre-auth limit is atomic
# =========================================================================== #

async def test_i3_two_hundred_concurrent_junk_requests_cannot_exceed_the_preauth_limit(world, rls_app):
    """The pre-auth check was check-then-act: every concurrent request passed the check before any recorded its
    failure (96 of 200 were processed against a limit of 30). A synchronous take makes the limit exact."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    limit = fp.preauth_limiter.limit
    async with _peer(rls_app, "203.0.113.9") as bad:
        rs = await asyncio.gather(*[
            bad.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=b"{}", headers=host.h) for _ in range(200)])
    codes = Counter(r.status_code for r in rs)
    assert codes[400] <= limit, f"{codes[400]} junk requests processed against a limit of {limit}: {dict(codes)}"
    assert codes[400] + codes[429] == 200, codes
    # the real agent, from its own address, is not affected
    assert (await hb(c, host)).status_code == 200


async def test_i3_verified_requests_do_not_consume_the_preauth_budget(world):
    """The slot a request takes up front is given back once its signature verified: an honest agent that sends
    more than the failure limit of VALID requests from one address is never cut off by the failure counter."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    fp.heartbeat_limiter.limit = 1000
    for _ in range(fp.preauth_limiter.limit + 15):
        assert (await hb(c, host)).status_code == 200


def test_i3_the_limiter_take_and_refund_are_exact():
    lim = fp.preauth_limiter.__class__(limit=3, window_s=60)
    toks = [lim.take("k", now=100.0 + i) for i in range(3)]
    assert all(t is not None for t in toks) and lim.take("k", now=104.0) is None
    lim.refund("k", toks[1])
    assert lim.take("k", now=105.0) is not None and lim.take("k", now=106.0) is None
    lim.refund("k", 12345.0)                               # an unknown token is ignored, never raises
    assert lim.take("k", now=107.0) is None


# =========================================================================== #
# I-4: replaying one captured envelope does not burn the real agent's budget
# =========================================================================== #

async def test_i4_replaying_a_captured_signed_envelope_does_not_exhaust_the_agents_budget(world, rls_app):
    """The budget was charged right after the signature verified, before the replay and clock checks, so a holder of
    the bearer and ONE captured envelope could replay it from anywhere (59 idempotent 200s, then 429) and the real
    agent's next heartbeat was refused."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    env = host.env("heartbeat")
    assert (await post(c, host, "heartbeat", env)).status_code == 200
    codes = Counter()
    async with _peer(rls_app, "198.51.100.7") as bad:
        for _ in range(150):
            codes[(await bad.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=json.dumps(env).encode(),
                                  headers=host.h)).status_code] += 1
    assert codes[200] + codes[429] == 150, codes
    r = await hb(c, host)
    assert r.status_code == 200, (dict(codes), r.status_code, r.text)
    assert len(fp.heartbeat_limiter._hits.get(host.agent_id, [])) == 2, "only the two ACCEPTED envelopes are charged"


async def test_i4_replaying_a_stale_or_superseded_envelope_does_not_burn_it_either(world, rls_app):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    old = host.env("heartbeat")
    assert (await post(c, host, "heartbeat", old)).status_code == 200
    assert (await hb(c, host)).status_code == 200                     # seq 2: the first one is now superseded
    stale = host.env("heartbeat", issued=dt.datetime.now(UTC) - dt.timedelta(hours=2))
    codes = Counter()
    async with _peer(rls_app, "198.51.100.7") as bad:
        for _ in range(120):
            for e in (old, stale):
                codes[(await bad.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=json.dumps(e).encode(),
                                      headers=host.h)).status_code] += 1
    assert codes[409] + codes[422] >= 1 and 200 not in codes, codes
    assert (await hb(c, host)).status_code == 200


async def test_i4_new_seqs_are_still_budgeted(world):
    """Not a bypass: every ACCEPTED envelope is charged, so a key holder is still held to its per-agent limit."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    fp.heartbeat_limiter.limit = 5
    codes = [(await hb(c, host)).status_code for _ in range(9)]
    assert codes == [200] * 5 + [429] * 4, codes
    # a refused (over-budget) envelope did not consume its seq: the agent can use it once the window frees up
    assert (await agent_row(world.db, host.agent_id))["rejected_total"] == 0


async def test_i4_the_replay_bucket_bounds_the_rows_a_replay_flood_can_write(world, rls_app):
    """Replays are free for the agent's budget, but they are not free: past a small bucket they are 429s that write
    no evidence row (one aggregate per minute), so the audit chain still cannot be grown at will."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await hb(c, host)).status_code == 200
    stale = host.env("heartbeat", seq=1)                              # seq 1 again, a different body: equivocation
    before = len(await rejected(world.db, host))
    codes = Counter()
    async with _peer(rls_app, "198.51.100.7") as bad:
        for _ in range(200):
            codes[(await bad.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=json.dumps(stale).encode(),
                                  headers=host.h)).status_code] += 1
    assert codes[429] > 0, codes
    assert len(await rejected(world.db, host)) - before <= fp.replay_limiter.limit + 1
    assert (await hb(c, host)).status_code == 200


# =========================================================================== #
# I-5: the server decodes no /proc/net hex addresses
# =========================================================================== #

def test_i5_the_server_never_decodes_proc_net_hex_addresses():
    """coll-8: the agent's collector decodes /proc/net addresses in the host's byte order. The server only ever sees
    the decoded text (``posture_identity`` reads ``ip`` strings and canonicalises them), so there is no byte-order
    assumption on this side to get wrong; this guards against one being added."""
    app = Path(fp.__file__).parent
    for name in ("fleet_posture.py", "routers/fleet.py", "fleet_enroll.py"):
        src = (app / name).read_text()
        assert not re.search(r"fromhex|\[::-1\]|byteorder|/proc/net|inet_ntop", src), name
    ident = fp.posture_identity(json.loads(pbytes(good_posture(ips=["10.1.2.3", "127.0.0.1"]))))
    assert ident["ips"] == ["10.1.2.3"]


def test_i5_the_agent_listener_decoder_honours_the_declared_byte_order(monkeypatch):
    """The agent side (not changed by this package): little- and big-endian spellings of one address decode alike."""
    from paddock_agent.collectors import listeners

    import sys as _sys
    monkeypatch.setattr(_sys, "byteorder", "little")
    assert listeners.decode_addr("0100007F")[0] == "127.0.0.1"
    monkeypatch.setattr(_sys, "byteorder", "big")
    assert listeners.decode_addr("7F000001")[0] == "127.0.0.1"
    assert listeners.decode_addr("0A010203")[0] == "10.1.2.3"
