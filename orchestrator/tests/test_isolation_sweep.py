"""Generic tenant-isolation sweep (hardening).

1. ``test_every_table_is_classified`` enumerates EVERY relation in schema
   ``public`` at runtime and fails for any table that is neither tenant-scoped
   (tenant_id + ENABLE/FORCE RLS + a ``tenant_isolation`` policy keyed on
   ``paddock_current_tenant()``) nor an explicitly allow-listed global
   catalogue. A future table therefore cannot ship unisolated.
2. ``test_row_level_isolation_for_every_tenant_table`` inserts a generated row
   into every tenant-scoped table as tenant A and proves, as the non-superuser
   ``paddock_app`` role, that tenant B cannot read, update, delete or
   (re)write it, and cannot insert a row into A.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import uuid

import asyncpg

from app import tenancy

TENANT_A = "00000000-0000-0000-0000-0000000000a1"
TENANT_B = "00000000-0000-0000-0000-0000000000b1"

#: Global catalogues (no tenant_id). Each entry says why it is safe to share.
GLOBAL_ALLOWLIST = {
    "tenants": "the tenant catalogue itself (read-only for the app role)",
    "schema_migrations": "migration ledger",
    "cves": "public NVD/KEV/EPSS feed data",
    "intel_cursors": "public-feed sync cursors",
    "attack_technique_map": "MITRE ATT&CK catalogue",
    "ontology_object_types": "platform ontology catalogue",
    "ontology_link_types": "platform ontology catalogue",
    "ti_feeds": "public threat-intel feed catalogue",
    "ti_indicators": "public threat-intel indicators",
    "sla_policies": "platform-wide SLA policy",
    "billing_customers": "opaque Stripe customer->tenant routing, platform-written (webhook has no tenant)",
    "billing_events": "opaque Stripe webhook event ids (replay protection), platform-written",
}

#: Extra permissive policies on tenant tables, and the only condition each may
#: use (anything else widens access and must be reviewed here).
EXTRA_POLICIES = {
    ("sensors", "sensor_auth_lookup"): "app.auth_lookup",
    ("sensor_enroll_tokens", "sensor_token_auth_lookup"): "app.auth_lookup",
    ("fleet_agents", "fleet_agent_auth_lookup"): "app.auth_lookup",
    ("fleet_enroll_tokens", "fleet_token_auth_lookup"): "app.auth_lookup",
    ("trust_links", "trust_public_lookup"): "app.trust_hash",
    ("scim_tokens", "scim_token_auth_lookup"): "app.auth_lookup",
    ("identity_providers", "identity_provider_auth_lookup"): "app.auth_lookup",
}

#: Tenant tables whose RLS policy may also honour credential lookup.
AUTH_LOOKUP_TABLES = {"app_users", "api_keys"}

#: Tables the generic row generator cannot fill (needs a structured payload).
#: Keep this SHORT; each is covered by API-level tests instead.
ROW_SKIP: dict[str, str] = {}

#: Table-level CHECKs the generator cannot infer (``a IS NOT NULL OR b IS NOT NULL``).
OVERRIDES: dict[str, dict[str, object]] = {
    "agent_actions": {"agent_id": uuid.UUID(int=7)},
    "finding_suppressions": {"rule_id": "sweep-rule"},
}


async def _relations(con):
    return await con.fetch(
        """
        SELECT c.oid, c.relname, c.relkind::text AS relkind, c.relrowsecurity, c.relforcerowsecurity,
               COALESCE(obj_description(c.oid, 'pg_class'), '') AS cmt,
               EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid
                        AND a.attname = 'tenant_id' AND NOT a.attisdropped) AS has_tenant,
               ARRAY(SELECT row_to_json(x)::text FROM (
                       SELECT p.polname AS name, p.polcmd AS cmd,
                              pg_get_expr(p.polqual, p.polrelid) AS qual,
                              pg_get_expr(p.polwithcheck, p.polrelid) AS chk
                         FROM pg_policy p WHERE p.polrelid = c.oid) x) AS policies,
               COALESCE('security_invoker=true' = ANY (c.reloptions), false) AS invoker
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND NOT c.relispartition
         ORDER BY c.relname
        """
    )


async def test_every_table_is_classified(db_pool):
    async with db_pool.acquire() as con:
        rels = await _relations(con)
    assert len(rels) > 80
    problems: list[str] = []
    tenant_tables: list[str] = []
    for r in rels:
        name, kind = r["relname"], r["relkind"]
        if kind in ("v", "m"):
            # Views must evaluate RLS as the caller; a materialized view cannot.
            if kind == "m":
                problems.append(f"{name}: materialized view bypasses RLS")
            elif not r["invoker"]:
                problems.append(f"{name}: view is not security_invoker")
            continue
        if kind == "f":
            problems.append(f"{name}: foreign table is unisolated")
            continue
        pols = [json.loads(p) for p in r["policies"]]
        by_name = {p["name"]: p for p in pols}
        if r["has_tenant"]:
            tenant_tables.append(name)
            if name in GLOBAL_ALLOWLIST:
                problems.append(f"{name}: allow-listed global but has tenant_id")
            if not (r["relrowsecurity"] and r["relforcerowsecurity"]):
                problems.append(f"{name}: tenant table without ENABLE+FORCE RLS")
            ti = by_name.get("tenant_isolation")
            if not ti:
                problems.append(f"{name}: no tenant_isolation policy")
                continue
            for part in ("qual", "chk"):
                expr = ti[part] or ""
                if "paddock_current_tenant()" not in expr or "tenant_id" not in expr:
                    problems.append(f"{name}: tenant_isolation {part} not keyed on tenant: {expr!r}")
                elif name not in AUTH_LOOKUP_TABLES and " OR " in expr.upper():
                    problems.append(f"{name}: tenant_isolation {part} has an OR arm: {expr!r}")
            for p in pols:
                if p["name"] == "tenant_isolation":
                    continue
                key = (name, p["name"])
                if key not in EXTRA_POLICIES:
                    problems.append(f"{name}: unreviewed extra policy {p['name']!r}")
                elif p["cmd"] != "r" or EXTRA_POLICIES[key] not in (p["qual"] or ""):
                    problems.append(f"{name}: policy {p['name']!r} is not a narrow SELECT-only lookup")
        else:
            if name not in GLOBAL_ALLOWLIST and "@paddock:global" not in r["cmt"]:
                problems.append(f"{name}: no tenant_id and not an allow-listed global table")
            elif name not in GLOBAL_ALLOWLIST:
                problems.append(f"{name}: marked @paddock:global but missing from GLOBAL_ALLOWLIST (review it)")
            if not r["relrowsecurity"]:
                problems.append(f"{name}: global table without RLS (writes must be platform-only)")
            if name != "tenants":
                if not {"global_read", "global_platform_write"} <= set(by_name):
                    problems.append(f"{name}: global table lacks global_read/global_platform_write")
                gw = by_name.get("global_platform_write")
                if gw and "paddock_default_tenant()" not in (gw["chk"] or ""):
                    problems.append(f"{name}: global write policy is not platform-only")
    assert not problems, "\n".join(problems)
    assert {"findings", "assets", "msp_grants", "sensors", "suppliers"} <= set(tenant_tables)


async def test_allowlisted_globals_exist(db_pool):
    """A stale allow-list entry hides a rename; keep it honest."""
    async with db_pool.acquire() as con:
        have = {r["relname"] for r in await _relations(con)}
    assert set(GLOBAL_ALLOWLIST) <= have


async def test_service_roles_cannot_bypass_rls(db_pool):
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles "
            "WHERE rolname = 'paddock_app' OR rolname LIKE 'paddock_svc\\_%'"
        )
    assert len(rows) >= 14
    for r in rows:
        assert not (r["rolsuper"] or r["rolbypassrls"] or r["rolcreatedb"] or r["rolcreaterole"]), r["rolname"]


# --------------------------------------------------------------------------- #
# Generic row generator
# --------------------------------------------------------------------------- #

_LIT = re.compile(r"'((?:[^']|'')*)'")


def _value_for(col, hints: dict[str, object], marker: str = "sweep"):
    n, t = col["attname"], col["typname"]
    if n in hints:
        return hints[n]
    if col["is_array"]:
        return []
    if t in ("text", "varchar", "bpchar", "citext", "name"):
        return f"{marker}-{n}"
    if t == "uuid":
        return uuid.uuid4()
    if t in ("int2", "int4", "int8"):
        return 1
    if t in ("float4", "float8"):
        return 0.5
    if t == "numeric":
        return 1
    if t == "bool":
        return False
    if t in ("jsonb", "json"):
        return "{}"
    if t == "timestamptz":
        return dt.datetime.now(dt.timezone.utc)
    if t == "timestamp":
        return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    if t == "date":
        return dt.date.today()
    if t == "bytea":
        return b"x"
    if t == "inet":
        return "10.0.0.1"
    if t == "cidr":
        return "10.0.0.0/24"
    return None  # unknown -> caller skips


def _hints_from_checks(checks: list[str]) -> dict[str, object]:
    """Pick the first allowed literal / a satisfying number out of CHECK exprs."""
    hints: dict[str, object] = {}
    for expr in checks:
        m = re.search(r"\(?(\w+)\)?(?:::text)? = ANY \(\(?ARRAY\[(.*?)\]", expr)
        if m:
            lit = _LIT.search(m.group(2))
            if lit:
                hints[m.group(1)] = lit.group(1).replace("''", "'")
                continue
        for m in re.finditer(r"\((\w+) >= (-?\d+)\)", expr):
            hints.setdefault(m.group(1), int(m.group(2)))
        for m in re.finditer(r"\((\w+) > (-?\d+)\)", expr):
            hints.setdefault(m.group(1), int(m.group(2)) + 1)
        for m in re.finditer(r"\((\w+) = '((?:[^']|'')*)'::text\)", expr):
            hints.setdefault(m.group(1), m.group(2))
    return hints


async def _columns(con, table: str):
    return await con.fetch(
        """
        SELECT a.attname, t.typname, (t.typcategory = 'A') AS is_array,
               a.attnotnull, a.atthasdef, a.attgenerated <> '' AS generated,
               a.attidentity <> '' AS ident,
               (SELECT e.typname FROM pg_type e WHERE e.oid = t.typelem AND t.typcategory = 'A') AS elem
          FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid
         WHERE a.attrelid = ('public.' || quote_ident($1))::regclass
           AND a.attnum > 0 AND NOT a.attisdropped
         ORDER BY a.attnum
        """,
        table,
    )


async def _make_row(con, table: str, tenant: str, marker: str = "sweep") -> tuple[dict, str | None]:
    """Insert one row as the superuser (FK triggers off); return (row, skip_reason)."""
    cols = await _columns(con, table)
    checks = [
        r["d"]
        for r in await con.fetch(
            "SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint "
            "WHERE conrelid = ('public.' || quote_ident($1))::regclass AND contype = 'c'",
            table,
        )
    ]
    hints = _hints_from_checks(checks)
    names, args, ph = [], [], []
    for c in cols:
        n = c["attname"]
        if c["generated"] or c["ident"]:
            continue
        if n == "tenant_id":
            v, ty = uuid.UUID(tenant), "uuid"
        else:
            if n not in OVERRIDES.get(table, {}) and (c["atthasdef"] or not c["attnotnull"]):
                continue
            v = OVERRIDES.get(table, {}).get(n)
            if v is None:
                v = _value_for(c, hints, marker)
            if v is None:
                return {}, f"no generator for {c['typname']} column {n}"
            ty = f"{c['elem']}[]" if c["is_array"] else c["typname"]
        names.append(f'"{n}"')
        args.append(v)
        ph.append(f"${len(args)}::{'jsonb' if ty == 'json' else ty}")
    sql = f'INSERT INTO public."{table}" ({", ".join(names)}) VALUES ({", ".join(ph)})'
    try:
        async with con.transaction():
            await con.execute(sql, *args)
    except asyncpg.PostgresError as exc:
        return {}, f"{type(exc).__name__}: {str(exc)[:160]}"
    return {"args": args, "sql": sql}, None


async def test_row_level_isolation_for_every_tenant_table(db_pool, app_pool):
    async with db_pool.acquire() as con:
        rels = await _relations(con)
    for slug, tid in (("sweep-a", TENANT_A), ("sweep-b", TENANT_B)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)
    tables = [r["relname"] for r in rels if r["relkind"] in ("r", "p") and r["has_tenant"]]
    skipped: dict[str, str] = {}
    exercised: list[str] = []
    failures: list[str] = []

    for table in tables:
        # 1. seed one row in tenant A as the superuser, FK checks off.
        async with db_pool.acquire() as su:
            await su.execute("SET session_replication_role = replica")
            try:
                row, why = await _make_row(su, table, TENANT_A)
            finally:
                await su.execute("SET session_replication_role = DEFAULT")
        if why:
            skipped[table] = why
            continue

        # 2. what the app role sees / can do, per tenant.
        counts = {}
        for who, tid in (("a", TENANT_A), ("b", TENANT_B)):
            with tenancy.tenant_context(tid):
                async with app_pool.acquire() as con:
                    counts[who] = await con.fetchval(f'SELECT count(*) FROM public."{table}"')
                    if who == "b":
                        # (a privilege error, e.g. append-only audit_log, is also isolation)
                        upd = dele = "UPDATE 0"
                        try:
                            upd = await con.execute(f'UPDATE public."{table}" SET tenant_id = tenant_id')
                            dele = await con.execute(f'DELETE FROM public."{table}"')
                        except asyncpg.InsufficientPrivilegeError:
                            dele = "DELETE 0"
                        if upd != "UPDATE 0" or dele != "DELETE 0":
                            failures.append(f"{table}: B touched A rows ({upd}, {dele})")
                        try:
                            async with con.transaction():
                                await con.execute(row["sql"], *row["args"])
                            failures.append(f"{table}: B inserted a tenant-A row")
                        except asyncpg.InsufficientPrivilegeError:
                            pass
                        except asyncpg.PostgresError as exc:
                            failures.append(f"{table}: B insert into A failed oddly: {exc}")
        if counts["a"] < 1:
            failures.append(f"{table}: tenant A cannot see its own generated row")
        if counts["b"] != 0:
            failures.append(f"{table}: tenant B sees {counts['b']} of A's rows")
        exercised.append(table)

    assert not failures, "\n".join(failures)
    unexplained = {t: w for t, w in skipped.items() if t not in ROW_SKIP}
    assert not unexplained, f"generic generator could not fill (add to ROW_SKIP with a reason): {unexplained}"
    assert len(exercised) >= 60
