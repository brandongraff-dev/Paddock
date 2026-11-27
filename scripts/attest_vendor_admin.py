#!/usr/bin/env python3
"""Vendor-side attestation emergency controls (docs/ASSURANCE_P3.md 3.8 level 4 and 5).

Run by Paddock operators, never by a tenant. The database commands connect as the **database owner role** (row-level
security does not apply to it), so every command names the tenant explicitly, requires a written justification of at
least 8 characters and leaves an audit row in that tenant's chain (``actor`` = ``vendor-admin``).

    # a key is compromised: revoke it for one tenant (hold + objects off + seed destroyed + list re-signed)
    python scripts/attest_vendor_admin.py revoke-key --tenant <uuid> --kid <32 hex> --justification "..." [--reason key_compromise]

    # stop one tenant issuing (hosted objects keep serving until valid_until, then verify as expired)
    python scripts/attest_vendor_admin.py suspend-tenant --tenant <uuid> --justification "..." [--resume]

    # stop everybody: sets the Redis key the attest loop polls. The environment flag PADDOCK_ATTEST_ISSUING=false is the
    # authoritative switch (an unreachable Redis does NOT stop issuing); set it on every replica as well.
    python scripts/attest_vendor_admin.py global-kill on|off

    # an issuer key is compromised (run OFFLINE, with the root key): write the root-signed issuer revocation list and the
    # {kid, usage: issuer-revoked} entries to merge into the verifier release's trust_roots.json, extending --previous
    PADDOCK_ATTEST_ROOT_PASSPHRASE=... python scripts/attest_vendor_admin.py revoke-issuer \\
        --root-key-file root.pem --issuer-kid <32 hex> --reason key_compromise --out issuer_revocations.json \\
        --entries-out issuer_revoked_entries.json

``revoke-key`` and ``suspend-tenant`` read the database URL from ``--dsn`` or ``PADDOCK_DATABASE_URL``/``DATABASE_URL``
and, for ``revoke-key``, the platform material from the usual ``PADDOCK_ATTEST_*`` settings (the revoker key signs the
new list; without it the revocation still stands and the command says the list was NOT re-signed, which the attest loop
then does as soon as it can). Passphrases come from the environment or a tty prompt, never from an argument.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from paddock_verify import canon, dsse, timefmt  # noqa: E402
from paddock_verify.jsonstrict import JsonError  # noqa: E402

ROOT_PASSPHRASE_ENV = "PADDOCK_ATTEST_ROOT_PASSPHRASE"
MIN_JUSTIFICATION = 8
ACTOR = "vendor-admin"
GLOBAL_KILL_REMINDER = (
    "The Redis key is a convenience that the attest loop polls; the authoritative switch is the environment "
    "variable PADDOCK_ATTEST_ISSUING=false on every replica (an unreachable Redis does not stop issuing)."
)
_KID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)


class AdminError(SystemExit):
    def __init__(self, message: str) -> None:
        super().__init__(f"error: {message}")


def _tenant(value: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        raise AdminError("--tenant must be a tenant UUID") from None


def _justification(value: str) -> str:
    text = (value or "").strip()
    if len(text) < MIN_JUSTIFICATION:
        raise AdminError(f"--justification is required (at least {MIN_JUSTIFICATION} characters): it lands in the audit row")
    return text


async def _stamp(conn, tenant: str) -> None:
    """Make the owner connection act for ``tenant`` (the same GUC the pool stamps), so the application code that
    runs next (keys, revocation, audit) sees exactly that tenant."""
    await conn.execute("SELECT set_config('app.tenant_id', $1, false)", tenant)


# --------------------------------------------------------------------------- #
# revoke-key
# --------------------------------------------------------------------------- #

async def revoke_key(conn, tenant_id: str, kid: str, *, reason: str, justification: str, now=None) -> dict:
    from app import tenancy
    from app.attest import keys

    tenant = _tenant(tenant_id)
    why = _justification(justification)
    if not _KID.match(kid or ""):
        raise AdminError("--kid is 32 lowercase hex characters")
    await _stamp(conn, tenant)
    with tenancy.tenant_context(tenant):
        try:
            res = await keys.revoke(conn, kid, reason=reason, actor=ACTOR, justification=why, now=now)
        except keys.KeyNotFound:
            raise AdminError("no such key for that tenant") from None
        except keys.KeysError as exc:
            raise AdminError(str(exc)) from None
    out = {
        "tenant": tenant, "kid": kid, "status": res.key.status, "usage": res.key.usage, "reason": reason,
        "already_revoked": res.already_revoked, "list_signed": res.list is not None,
        "list_seq": res.list.seq if res.list is not None else None,
        "replacement": res.replacement.kid if res.replacement is not None else None,
        "replacement_status": res.replacement.status if res.replacement is not None else None,
        "replacement_error": res.replacement_error, "destroy_error": res.destroy_error,
    }
    problems = []
    if res.list is None and not res.already_revoked:
        problems.append("the revocation list was NOT re-signed (" + (res.list_error or "skipped") +
                        "): the attest loop re-signs it as soon as the revoker key is available")
    if res.destroy_error:
        problems.append("the sealed key could not be destroyed yet (" + res.destroy_error + "): the key sweep retries")
    if problems:
        out["warning"] = "; ".join(problems)
    return out


# --------------------------------------------------------------------------- #
# suspend-tenant
# --------------------------------------------------------------------------- #

async def suspend_tenant(conn, tenant_id: str, *, justification: str, resume: bool = False) -> dict:
    from app import audit as audit_svc
    from app import tenancy

    tenant = _tenant(tenant_id)
    why = _justification(justification)
    await _stamp(conn, tenant)
    with tenancy.tenant_context(tenant):
        async with conn.transaction():
            row = await conn.fetchrow(
                "UPDATE attest_estates SET issuing_suspended = $2 WHERE tenant_id = $1::uuid RETURNING estate_id",
                tenant, not resume)
            if row is None:
                raise AdminError("that tenant has no attestation estate")
            await audit_svc.record(
                None, action="attest.resumed" if resume else "attest.suspended", actor=ACTOR,
                actor_role="system", resource_type="attest_estate", resource_id=row["estate_id"],
                justification=why, details={"estate": row["estate_id"], "issuing_suspended": not resume},
                con=conn, tenant_id=tenant)
    return {"tenant": tenant, "estate": row["estate_id"], "issuing_suspended": not resume}


# --------------------------------------------------------------------------- #
# global-kill
# --------------------------------------------------------------------------- #

async def global_kill(redis, on: bool) -> dict:
    from app.attest import platform_keys

    if on:
        await redis.set(platform_keys.GLOBAL_KILL_REDIS_KEY, datetime.now(timezone.utc).isoformat())
    else:
        await redis.delete(platform_keys.GLOBAL_KILL_REDIS_KEY)
    return {"issuing_killed": on}


# --------------------------------------------------------------------------- #
# revoke-issuer (offline)
# --------------------------------------------------------------------------- #

def _inside_repo(path: Path) -> bool:
    try:
        return path.expanduser().resolve().is_relative_to(ROOT.resolve())
    except OSError:
        return False


def _root_key(path: str) -> Ed25519PrivateKey:
    pw = os.environ.get(ROOT_PASSPHRASE_ENV)
    if pw is None:
        if not sys.stdin.isatty():
            raise AdminError(f"set {ROOT_PASSPHRASE_ENV} (or run interactively)")
        pw = getpass.getpass("Passphrase for the attestation root key: ")
    try:
        key = serialization.load_pem_private_key(Path(path).expanduser().read_bytes(), password=pw.encode("utf-8"))
    except (OSError, ValueError, TypeError):
        raise AdminError("the root key cannot be opened (wrong passphrase, unencrypted or damaged)") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise AdminError("the root key is not an Ed25519 key")
    return key


def cmd_revoke_issuer(a: argparse.Namespace) -> int:
    import hashlib

    from app.attest import certs, revocation

    out = Path(a.out).expanduser()
    if _inside_repo(out):
        raise AdminError("refusing to write inside the repository checkout; write to a release working directory")
    if out.exists():
        raise AdminError(f"{out} exists; never overwrite (write a new file)")
    if not _KID.match(a.issuer_kid):
        raise AdminError("--issuer-kid is 32 lowercase hex characters")
    if a.reason not in revocation.REASONS:
        raise AdminError(f"--reason is one of {', '.join(revocation.REASONS)}")
    try:
        at = timefmt.parse(a.at) if a.at else int(datetime.now(timezone.utc).timestamp())
    except JsonError:
        raise AdminError("--at must look like 2026-12-01T00:00:00Z") from None
    key = _root_key(a.root_key_file)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = hashlib.sha256(pub).hexdigest()[:32]
    entries: dict = {}
    seq = 1
    if a.previous:
        root = certs.Root(kid, pub, "root", 0, 2 ** 40)
        try:
            data = Path(a.previous).expanduser().read_bytes()
            previous = revocation.verify_issuer_revocations(data, [root])
            seq = json.loads(dsse.parse_envelope(data).payload)["seq"] + 1
        except (OSError, revocation.RevocationError) as exc:
            raise AdminError(f"--previous is not a valid list signed by this root: {exc}") from None
        entries = {k: {"kid": k, "reason": v.reason, "revoked_at": timefmt.format(v.revoked_at)} for k, v in previous.items()}
    if a.issuer_kid not in entries:
        entries[a.issuer_kid] = {"kid": a.issuer_kid, "reason": a.reason, "revoked_at": timefmt.format(at)}
    doc = {"_type": revocation.ISSUER_LIST_TYPE, "issued_at": timefmt.format(at), "revoked": [entries[k] for k in sorted(entries)],
           "seq": seq}
    payload = canon.dumps(doc)
    envelope = dsse.build_envelope(dsse.PAYLOAD_TYPE_REVOCATION, payload, kid,
                                   key.sign(dsse.pae(dsse.PAYLOAD_TYPE_REVOCATION, payload)))
    # the same check a verifier release build performs
    check = revocation.verify_issuer_revocations(envelope, [certs.Root(kid, pub, "root", 0, 2 ** 40)])
    if a.issuer_kid not in check:
        raise AdminError("self-test failed: the issuer is not in the list")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(envelope)
    if a.entries_out:
        entries_path = Path(a.entries_out).expanduser()
        if _inside_repo(entries_path) or entries_path.exists():
            raise AdminError("--entries-out must be a new file outside the repository")
        fd = os.open(entries_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(json.dumps([{"kid": k, "usage": "issuer-revoked"} for k in sorted(entries)], indent=2) + "\n")
        print(f"verifier roots entries -> {entries_path} (append them to paddock_verify/data/trust_roots.json)")
    print(f"issuer revocation list seq {seq}: {len(entries)} issuer(s) revoked -> {out}")
    print("Ship the entries in a new verifier release (trust_roots.json); verifiers that predate it")
    print("do not know the revocation (docs/ASSURANCE_P3.md 12.2 item 7). Also re-certify every estate key under a new issuer.")
    return 0


# --------------------------------------------------------------------------- #
# command line
# --------------------------------------------------------------------------- #

def _dsn(a: argparse.Namespace) -> str:
    dsn = a.dsn or os.environ.get("PADDOCK_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        raise AdminError("give --dsn or set PADDOCK_DATABASE_URL (the database OWNER role)")
    return dsn


async def _with_conn(dsn: str, fn):
    import asyncpg

    conn = await asyncpg.connect(dsn)
    try:
        return await fn(conn)
    finally:
        await conn.close()


def cmd_revoke_key(a: argparse.Namespace) -> int:
    dsn = _dsn(a)
    out = asyncio.run(_with_conn(dsn, lambda c: revoke_key(c, a.tenant, a.kid, reason=a.reason, justification=a.justification)))
    print(json.dumps(out, indent=2, sort_keys=True))
    return 3 if out.get("warning") else 0


def cmd_suspend_tenant(a: argparse.Namespace) -> int:
    dsn = _dsn(a)
    out = asyncio.run(_with_conn(dsn, lambda c: suspend_tenant(c, a.tenant, justification=a.justification, resume=a.resume)))
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_global_kill(a: argparse.Namespace) -> int:
    import redis.asyncio as aioredis

    from app.config import settings

    url = a.redis_url or os.environ.get("PADDOCK_REDIS_URL") or os.environ.get("REDIS_URL") or settings.redis_url

    async def run():
        client = aioredis.from_url(url, decode_responses=True)
        try:
            return await global_kill(client, a.state == "on")
        finally:
            await client.aclose()

    print(json.dumps(asyncio.run(run()), sort_keys=True))
    print(GLOBAL_KILL_REMINDER)
    return 0


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("revoke-key", help="emergency-revoke one estate key of one tenant")
    r.add_argument("--tenant", required=True)
    r.add_argument("--kid", required=True)
    r.add_argument("--reason", default="key_compromise", choices=["key_compromise", "superseded", "cessation"])
    r.add_argument("--justification", required=True)
    r.add_argument("--dsn")
    r.set_defaults(fn=cmd_revoke_key)

    s = sub.add_parser("suspend-tenant", help="stop (or --resume) issuing for one tenant")
    s.add_argument("--tenant", required=True)
    s.add_argument("--justification", required=True)
    s.add_argument("--resume", action="store_true")
    s.add_argument("--dsn")
    s.set_defaults(fn=cmd_suspend_tenant)

    g = sub.add_parser("global-kill", help="set or clear the Redis kill key the attest loop polls")
    g.add_argument("state", choices=["on", "off"])
    g.add_argument("--redis-url")
    g.set_defaults(fn=cmd_global_kill)

    i = sub.add_parser("revoke-issuer", help="write the root-signed issuer revocation list (run OFFLINE)")
    i.add_argument("--root-key-file", required=True)
    i.add_argument("--issuer-kid", required=True)
    i.add_argument("--reason", required=True, choices=["key_compromise", "superseded", "cessation"])
    i.add_argument("--out", required=True)
    i.add_argument("--previous", help="an earlier list of this root to extend")
    i.add_argument("--at", help="revocation time (default now), e.g. 2026-12-01T00:00:00Z")
    i.add_argument("--entries-out", help="also write the {kid, usage: issuer-revoked} entries for the verifier's trust_roots.json")
    i.set_defaults(fn=cmd_revoke_issuer)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
