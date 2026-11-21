"""Operator CLI: ``python -m app.msp enable <tenant-slug> [--name NAME] [--max-customers N]``.

Promoting a tenant to an MSP is deliberately NOT an API action (the app role
cannot write ``msp_orgs``): run it with OWNER_DATABASE_URL, the schema owner.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

import asyncpg

from ..db import _coerce_dsn


async def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="python -m app.msp")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enable", help="make an existing tenant an MSP")
    e.add_argument("slug")
    e.add_argument("--name", help="display name (default: the tenant's name)")
    e.add_argument("--max-customers", type=int, default=None)
    d = sub.add_parser("disable", help="remove the MSP marker (customers stay, grants stop working)")
    d.add_argument("slug")
    sub.add_parser("list", help="list MSP tenants")
    args = p.parse_args(argv)

    dsn = os.environ.get("OWNER_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        print("set OWNER_DATABASE_URL (schema owner) first")
        return 2
    con = await asyncpg.connect(_coerce_dsn(dsn))
    try:
        if args.cmd == "list":
            for r in await con.fetch(
                "SELECT t.slug, t.status, o.name, o.max_children, "
                "       (SELECT COUNT(*) FROM msp_children c WHERE c.tenant_id = o.tenant_id) AS customers "
                "  FROM msp_orgs o JOIN tenants t ON t.id = o.tenant_id ORDER BY t.slug"
            ):
                print(f"{r['slug']:<24} {r['status']:<10} customers={r['customers']} max={r['max_children']} {r['name']}")
            return 0
        t = await con.fetchrow("SELECT id, name FROM tenants WHERE slug = $1", args.slug)
        if t is None:
            print(f"no tenant with slug {args.slug!r}")
            return 1
        if args.cmd == "enable":
            async with con.transaction():
                await con.execute("SELECT set_config('app.tenant_id', $1, true)", str(t["id"]))
                await con.execute(
                    "INSERT INTO msp_orgs (tenant_id, name, max_children, created_by) VALUES ($1, $2, $3, 'operator') "
                    "ON CONFLICT (tenant_id) DO UPDATE SET name = EXCLUDED.name, max_children = EXCLUDED.max_children",
                    t["id"], args.name or t["name"], args.max_customers,
                )
            print(f"{args.slug} is now an MSP")
        else:
            async with con.transaction():
                await con.execute("SELECT set_config('app.tenant_id', $1, true)", str(t["id"]))
                await con.execute("DELETE FROM msp_orgs WHERE tenant_id = $1", t["id"])
            print(f"{args.slug} is no longer an MSP")
        return 0
    finally:
        await con.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(sys.argv[1:])))
