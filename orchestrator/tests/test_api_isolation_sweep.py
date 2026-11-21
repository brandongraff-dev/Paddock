"""API-level cross-tenant sweep, generated from the live OpenAPI spec.

For every GET / PATCH / PUT / DELETE operation the app exposes, each attacker
(a tenant API key, an MSP user's own session, an MSP switch token into a
customer, the fleet service key naming a tenant) calls it

* once per candidate id of the *victim* tenants (every id of every table the
  victim owns, plus the ids created through the API), and
* once with a random non-existent id (the baseline).

Assertions
----------
1. No response ever contains a victim tenant's marker string.
2. Existence oracle: where either call is an error, the foreign id must be
   answered *exactly* like a random id (same status, same body modulo the id).
3. Nothing the attacker did changed a single victim row (md5 over each
   victim's rows in every tenant table) or any global catalogue.
4. The sweep is not vacuous: the owners of those ids get 200s on the same
   detail routes.
"""
from __future__ import annotations

import re
import uuid

import pytest

from app.config import settings

from . import stress_world as sw
from .test_isolation_sweep import _relations

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
METHODS = ("get", "patch", "put", "delete")

#: Routes skipped, each with the reason. Everything else is swept.
SKIP = {
    "/v1/events": "SSE stream never completes; filtered per tenant, see test_event_stream_isolation.py",
    "/v1/public/trust/{token}": "public by design: the token IS the credential",
    "/v1/public/exposure-report/{report_id}": "public by design (platform-tenant lead report)",
    "/v1/auth/sso/{slug}/callback": "unauthenticated SSO login flow (slug is a global login handle)",
    "/v1/auth/sso/{slug}/metadata": "unauthenticated SSO login flow",
    "/v1/auth/sso/{slug}/sls": "unauthenticated SSO login flow",
    "/v1/auth/sso/{slug}/start": "unauthenticated SSO login flow",
}
SKIP_PREFIX = ("/scim/v2",)  # bearer = SCIM token: covered by test_scim_cross_tenant

BODIES = (
    {},
    {"name": "pwned", "title": "pwned", "status": "closed", "enabled": False, "note": "pwned",
     "reason": "pwned", "label": "pwned", "role": "admin", "severity": "info"},
)


def _ops(app):
    spec = app.openapi()
    out = []
    for path, ops in sorted(spec["paths"].items()):
        if path in SKIP or path.startswith(SKIP_PREFIX):
            continue
        for method in METHODS:
            op = ops.get(method)
            if not op:
                continue
            params = []
            for p in op.get("parameters", []):
                if p["in"] != "path":
                    continue
                sch = p.get("schema", {})
                kind = "uuid" if sch.get("format") == "uuid" else ("int" if sch.get("type") == "integer" else "str")
                params.append((p["name"], kind))
            out.append((method, path, params))
    return out


def _stem(name: str) -> str:
    s = name.removesuffix("_id")
    return s[:-1] if s.endswith("s") else s


def _candidates(victims: list[sw.Tenant], pname: str, kind: str) -> list[str]:
    stem = _stem(pname)
    hinted: list = []
    other: list = []
    for v in victims:
        for table, vals in v.ids.items():
            (hinted if stem in table else other).extend(vals)
        for k, vals in v.api.items():
            if stem in k:
                hinted.extend(x for x in vals if x is not None)
    pool = hinted or other[:40]
    seen, out = set(), []
    for x in pool:
        s = str(x)
        ok = bool(_UUID.match(s)) if kind == "uuid" else (s.lstrip("-").isdigit() if kind == "int" else True)
        if ok and s not in seen:
            seen.add(s)
            out.append(s)
    return out[:8]


def _refine(victims, pname: str, kind: str) -> str:
    """Routes declare many uuid path params as plain strings: if every
    candidate id is a uuid, the random baseline must be one too."""
    if kind == "str":
        c = _candidates(victims, pname, "str")
        if c and all(_UUID.match(x) for x in c):
            return "uuid"
    return kind


def _baseline(kind: str) -> str:
    return str(uuid.uuid4()) if kind == "uuid" else ("987654321" if kind == "int" else "zz-no-such-object")


async def _fingerprint(db_pool, tenant_id: str, tables: list[str]) -> str:
    parts = []
    async with db_pool.acquire() as con:
        for t in tables:
            parts.append(await con.fetchval(
                f'SELECT md5(COALESCE(string_agg(x::text, \'|\' ORDER BY x::text), \'\')) FROM public."{t}" x '
                "WHERE x.tenant_id = $1",
                tenant_id,
            ))
    return "".join(parts)


async def _global_fingerprint(db_pool, tables: list[str]) -> str:
    parts = []
    async with db_pool.acquire() as con:
        for t in tables:
            parts.append(await con.fetchval(
                f'SELECT md5(COALESCE(string_agg(x::text, \'|\' ORDER BY x::text), \'\')) FROM public."{t}" x'
            ))
    return "".join(parts)


async def _call(client, method: str, url: str, headers: dict, body: dict):
    import time

    kw = {} if method == "get" else {"json": body}
    t = time.time()
    r = await client.request(method.upper(), url, headers=headers, **kw)
    if time.time() - t > 1.5:
        print(f"SLOW {time.time() - t:.1f}s {method.upper()} {url}", flush=True)
    return r


@pytest.fixture
def stress_settings(monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    monkeypatch.setattr(settings, "service_api_key", sw.SERVICE_KEY)
    yield


def _norm(text: str, ids: list[str]) -> str:
    for i in ids:
        text = text.replace(i, "<id>")
    return text


async def test_api_cross_tenant_sweep(stress_settings, app, app_pool, db_pool, client):
    w = await sw.build_world(db_pool=db_pool, app_pool=app_pool, app=app, client=client)
    async with db_pool.acquire() as con:
        rels = await _relations(con)
    tenant_tables = [r["relname"] for r in rels if r["relkind"] in ("r", "p") and r["has_tenant"]]
    global_tables = [r["relname"] for r in rels if r["relkind"] in ("r", "p") and not r["has_tenant"]
                     and r["relname"] not in ("tenants", "schema_migrations")]
    ops = _ops(app)
    assert len(ops) > 120

    svc_hdr = {"X-API-Key": sw.SERVICE_KEY, "X-Paddock-Tenant": sw.T_B}
    attackers = [
        # name, headers, own tenant, victims
        ("b-key", w["b"].headers(), "b", ["a", "c1", "m"]),
        ("a-key", w["a"].headers(), "a", ["b", "c1", "m"]),
        ("msp-root", w["m"].headers(), "m", ["a", "b"]),
        ("msp-switched", w["c1"].headers(), "c1", ["a", "b", "m"]),
        ("service-as-b", svc_hdr, "b", ["a", "c1", "m"]),
    ]
    failures: list[str] = []
    n_calls = 0
    import os, time
    t0 = time.time()
    only = os.environ.get('SWEEP_ONLY')
    for aname, hdr, own, victim_names in attackers:
        if only and aname != only:
            continue
        print(f'## attacker {aname} calls so far {n_calls} t={time.time()-t0:.0f}s', flush=True)
        victims = [w[v] for v in victim_names]
        markers = [v.marker for v in victims]
        # Fingerprints of what must not change. A delegated (switched) session
        # legitimately writes the MSP parent's audit chain; skip m's audit_log.
        before = {v.name: await _fingerprint(db_pool, v.id, [t for t in tenant_tables
                  if not (aname == "msp-switched" and v.name == "m" and t == "audit_log")]) for v in victims}
        gbefore = await _global_fingerprint(db_pool, global_tables)

        for method, path, params in ops:
            if not params:
                url = path
                for body in (BODIES if method in ("patch", "put") else BODIES[:1]):
                    r = await _call(client, method, url, hdr, body)
                    n_calls += 1
                    low = r.text.lower()
                    for m in markers:
                        if m in low:
                            failures.append(f"[{aname}] {method.upper()} {url} leaked {m}: {r.text[:200]}")
                continue
            params = [(pn, _refine(victims, pn, k)) for pn, k in params]
            base_vals = [_baseline(k) for _, k in params]
            base_url = path
            for (pn, _), bv in zip(params, base_vals):
                base_url = base_url.replace("{" + pn + "}", bv)
            for body in (BODIES if method in ("patch", "put") else BODIES[:1]):
                rb = await _call(client, method, base_url, hdr, body)
                n_calls += 1
                # one param varies at a time, others stay baseline
                for idx, (pn, kind) in enumerate(params):
                    for cand in _candidates(victims, pn, kind):
                        vals = list(base_vals)
                        vals[idx] = cand
                        url = path
                        for (n2, _), v in zip(params, vals):
                            url = url.replace("{" + n2 + "}", v)
                        r = await _call(client, method, url, hdr, body)
                        n_calls += 1
                        low = r.text.lower()
                        for m in markers:
                            if m in low:
                                failures.append(f"[{aname}] {method.upper()} {url} leaked {m}: {r.text[:200]}")
                        if r.status_code < 400 and rb.status_code < 400:
                            if method != "get" and r.status_code != rb.status_code:
                                failures.append(f"[{aname}] {method.upper()} {url} mutated? {r.status_code} vs {rb.status_code}")
                            continue
                        same = r.status_code == rb.status_code and \
                            _norm(r.text, [cand]) == _norm(rb.text, [base_vals[idx]])
                        if not same:
                            failures.append(
                                f"[{aname}] oracle {method.upper()} {path} {pn}={cand} body={list(body)}: "
                                f"{r.status_code} {r.text[:120]!r} vs random {rb.status_code} {rb.text[:120]!r}")
        for v in victims:
            now = await _fingerprint(db_pool, v.id, [t for t in tenant_tables
                  if not (aname == "msp-switched" and v.name == "m" and t == "audit_log")])
            if now != before[v.name]:
                failures.append(f"[{aname}] victim tenant {v.name} rows CHANGED")
        if await _global_fingerprint(db_pool, global_tables) != gbefore:
            failures.append(f"[{aname}] a global catalogue CHANGED")

    # Control: the owner of the ids is served by the very same routes.
    ok_detail = 0
    for owner in ("a", "b"):
        for method, path, params in ops:
            if method != "get" or len(params) != 1:
                continue
            pn, kind = params[0]
            for cand in _candidates([w[owner]], pn, kind)[:3]:
                r = await client.get(path.replace("{" + pn + "}", cand), headers=w[owner].headers())
                if r.status_code == 200:
                    ok_detail += 1
                    break
    assert ok_detail >= 20, f"sweep looks vacuous: owners only got {ok_detail} detail 200s"
    assert n_calls > 2000, n_calls
    assert not failures, f"{len(failures)} isolation failures:\n" + "\n".join(failures[:60])
