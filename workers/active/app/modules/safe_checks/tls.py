"""TLS safe checks: handshake only.

A handshake negotiates keys and reads the certificate; no application data is
ever sent. The checks use the stdlib ``ssl`` module in a throw-away,
certificate-verification-OFF context (we are *reading* the certificate, not
trusting it) and parse the leaf certificate's validity/issuer/subject with a
tiny DER reader, so no extra dependency is needed.

Honesty rules (a wrong "not_reproducible" would falsely prove a fix):

* A refusal only counts when a control handshake to the same host:port
  succeeded in the same run (so the host was reachable and speaking TLS).
* A legacy protocol / weak cipher can only be declared absent if THIS worker's
  TLS library is capable of offering it (``client_can_negotiate`` probes that
  against a loopback server). Otherwise the verdict is ``inconclusive``.
"""
from __future__ import annotations

import asyncio
import ipaddress
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import (
    CONNECT_TIMEOUT_SEC,
    CheckEnv,
    CheckResult,
    FindingCtx,
    confirmed,
    inconclusive,
    not_reproducible,
    sha_prefix,
    vetted_addrs,
)

warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"app\.modules\.safe_checks\.tls")

_V = ssl.TLSVersion
_VERSION_NAMES = {"TLSv1": _V.TLSv1, "TLSv1.1": _V.TLSv1_1, "TLSv1.2": _V.TLSv1_2, "TLSv1.3": _V.TLSv1_3}
_LEGACY = ("TLSv1", "TLSv1.1")
_LEGACY_CIPHERS = "ALL:@SECLEVEL=0"

# finding-side cipher words -> OpenSSL-name substrings that are the same family.
_WEAK_FAMILIES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "3DES": (("3DES", "DES_EDE", "DES-CBC3"), ("DES-CBC3", "3DES")),
    "DES": (("DES-", "_DES_"), ("DES-CBC-", "EXP-DES")),
    "RC4": (("RC4",), ("RC4",)),
    "NULL": (("NULL",), ("NULL",)),
    "EXPORT": (("EXPORT", "EXP-", "EXP_"), ("EXP-",)),
    "MD5": (("MD5",), ("MD5",)),
    "ANON": (("ANON", "ADH", "AECDH", "_DH_ANON"), ("ADH-", "AECDH-")),
}


@dataclass
class Handshake:
    ok: bool
    version: str | None = None
    cipher: str | None = None
    der: bytes | None = None
    error: str | None = None
    reason: str | None = None     # ssl error reason, for classification
    network: bool = False         # timeout / refused / unreachable (not a TLS verdict)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def do_handshake(
    host: str,
    port: int,
    *,
    min_version: str | None = None,
    max_version: str | None = None,
    ciphers: str | None = None,
    timeout: float = CONNECT_TIMEOUT_SEC,
    addrs: list[str] | None = None,
) -> Handshake:
    """One TLS handshake, then close. Never writes application data.

    ``addrs`` are the orchestrator-vetted addresses for ``host``: the socket
    dials ONLY those (SNI stays the hostname). Without them only a literal IP
    host is accepted; a name is never resolved here (DNS rebinding).
    """
    if addrs is None:
        if not _is_ip(host):
            raise ValueError("do_handshake needs vetted addrs for a hostname")
        addrs = [host]
    last: Handshake | None = None
    for ip in addrs[:4]:
        last = await _handshake_one(ip, host, port, min_version, max_version, ciphers, timeout)
        if not last.network:
            return last
    return last or Handshake(False, error="no vetted addresses", network=True)


async def _handshake_one(
    ip: str, host: str, port: int, min_version: str | None, max_version: str | None,
    ciphers: str | None, timeout: float,
) -> Handshake:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        if min_version:
            ctx.minimum_version = _VERSION_NAMES[min_version]
        if max_version:
            ctx.maximum_version = _VERSION_NAMES[max_version]
        if ciphers:
            ctx.set_ciphers(ciphers)
    except (ValueError, ssl.SSLError) as e:
        return Handshake(False, error=f"client cannot offer this configuration: {e}",
                         reason="CLIENT_UNSUPPORTED")
    try:
        _r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx,
                                    server_hostname=None if _is_ip(host) else host,
                                    ssl_handshake_timeout=timeout),
            timeout + 1,
        )
    except ssl.SSLError as e:
        return Handshake(False, error=f"TLS handshake failed: {e}",
                         reason=str(getattr(e, "reason", "") or "SSL_ERROR"))
    except asyncio.TimeoutError:
        return Handshake(False, error="timeout", network=True)
    except (ConnectionError, OSError) as e:
        # A reset in the middle of a handshake is the server refusing the offer;
        # refused/unreachable/DNS failures are not a TLS verdict at all.
        if isinstance(e, ConnectionResetError):
            return Handshake(False, error="connection reset during handshake", reason="RESET")
        return Handshake(False, error=f"{type(e).__name__}: {str(e)[:100]}", network=True)
    try:
        so = w.get_extra_info("ssl_object")
        cipher = so.cipher()[0] if so and so.cipher() else None
        return Handshake(True, version=so.version() if so else None, cipher=cipher,
                         der=so.getpeercert(binary_form=True) if so else None)
    finally:
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), 2)
        except Exception:  # noqa: BLE001
            pass


# -- client capability probe --------------------------------------------------

_CAN: dict[str, bool] = {}


async def client_can_negotiate(version: str) -> bool:
    """Can THIS process complete a handshake at exactly ``version``? Probed once
    against a loopback server using anonymous ciphers (no certificate needed)."""
    if version in _CAN:
        return _CAN[version]
    ok = False
    try:
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.minimum_version = sctx.maximum_version = _VERSION_NAMES[version]
        sctx.set_ciphers("aNULL:@SECLEVEL=0" if version != "TLSv1.3" else "ALL")

        async def _h(_r, w):
            try:
                await asyncio.sleep(0.3)
            finally:
                w.close()

        srv = await asyncio.start_server(_h, "127.0.0.1", 0, ssl=sctx)
        try:
            port = srv.sockets[0].getsockname()[1]
            hs = await do_handshake("127.0.0.1", port, min_version=version, max_version=version,
                                    ciphers="aNULL:@SECLEVEL=0" if version != "TLSv1.3" else None,
                                    timeout=3)
            ok = hs.ok and hs.version == version
        finally:
            srv.close()
    except Exception:  # noqa: BLE001 -- any failure means "cannot"
        ok = False
    _CAN[version] = ok
    return ok


# -- DER (just enough X.509) --------------------------------------------------

def _tlv(b: bytes, i: int) -> tuple[int, int, int]:
    tag, ln = b[i], b[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, i, ln


def _asn1_time(tag: int, raw: bytes) -> datetime:
    s = raw.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        yy = int(s[:2])
        s = ("19" if yy >= 50 else "20") + s
    return datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def parse_cert(der: bytes) -> dict[str, Any]:
    """Validity + issuer/subject identity of a DER X.509 certificate."""
    _t, i, _l = _tlv(der, 0)          # Certificate
    _t, j, _l = _tlv(der, i)          # tbsCertificate
    tag, vs, vl = _tlv(der, j)
    if tag == 0xA0:                   # [0] version
        j = vs + vl
    for _ in range(2):                # serialNumber, signature algorithm
        _t, vs, vl = _tlv(der, j)
        j = vs + vl
    _t, vs, vl = _tlv(der, j)         # issuer
    issuer = der[j:vs + vl]
    j = vs + vl
    _t, vs, vl = _tlv(der, j)         # validity
    k = vs
    t1, s1, l1 = _tlv(der, k)
    not_before = _asn1_time(t1, der[s1:s1 + l1])
    k = s1 + l1
    t2, s2, l2 = _tlv(der, k)
    not_after = _asn1_time(t2, der[s2:s2 + l2])
    j = vs + vl
    _t, vs, vl = _tlv(der, j)         # subject
    subject = der[j:vs + vl]
    return {
        "not_before": not_before, "not_after": not_after,
        "self_signed": issuer == subject, "sha256_16": sha_prefix(der),
    }


# -- shared helpers -----------------------------------------------------------

async def _handshake(env: CheckEnv, f: FindingCtx, **kw: Any) -> Handshake:
    host, port = _target(f)
    if env.tls_handshake is not None:
        await env.scope.allow(f"{host}:{port}")
        hs = await env.tls_handshake(host, port, **kw)
    else:
        hs = await do_handshake(host, port, addrs=await vetted_addrs(env, host, port), **kw)
    await env.audit(target=f"{host}:{port}", tool="safe_check:tls", method="tls_handshake",
                    scope_matched=True, error=None if hs.ok else hs.error)
    return hs


def _target(f: FindingCtx) -> tuple[str, int]:
    host = f.host
    return host, f.port or 443


def _leaf(hs: Handshake) -> dict[str, Any] | None:
    if not hs.der:
        return None
    try:
        return parse_cert(hs.der)
    except Exception:  # noqa: BLE001 -- malformed cert: not a verdict
        return None


def _iso(d: datetime) -> str:
    return d.isoformat()


# --------------------------------------------------------------------------- #
# certificate checks
# --------------------------------------------------------------------------- #

def _match_cert(f: FindingCtx) -> bool:
    return f.rule_source == "tls_check" and f.rule_id in (
        "expired-certificate", "expiring-certificate", "self-signed-certificate") and bool(f.host)


async def _run_cert(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "tls_certificate"
    hs = await _handshake(env, f)
    host, port = _target(f)
    if not hs.ok:
        return inconclusive(cid, f"no TLS handshake with {host}:{port}: {hs.error}")
    cert = _leaf(hs)
    if cert is None:
        return inconclusive(cid, "the server presented no parseable certificate")
    now = env.now()
    na, nb = cert["not_after"], cert["not_before"]
    ev = {"host": host, "port": port, "not_before": _iso(nb), "not_after": _iso(na),
          "self_signed": cert["self_signed"], "cert_sha256_16": cert["sha256_16"],
          "tls_version": hs.version}
    if f.rule_id == "expired-certificate":
        if na < now:
            return confirmed(cid, f"certificate expired on {na.date()}", **ev)
        return not_reproducible(cid, f"certificate is valid until {na.date()}", **ev,
                                days_remaining=(na - now).days)
    if f.rule_id == "expiring-certificate":
        left = na - now
        if left < timedelta(days=14):
            note = "certificate has expired" if left < timedelta(0) else \
                f"certificate expires in {left.days} day(s)"
            return confirmed(cid, note, **ev, days_remaining=left.days)
        return not_reproducible(cid, f"certificate now valid for {left.days} more days", **ev,
                                days_remaining=left.days)
    # self-signed-certificate
    if cert["self_signed"]:
        return confirmed(cid, "the server still presents a self-signed certificate", **ev)
    return not_reproducible(cid, "the server now presents a certificate issued by a separate CA", **ev)


# --------------------------------------------------------------------------- #
# protocol checks
# --------------------------------------------------------------------------- #

def _match_protocol(f: FindingCtx) -> bool:
    return f.rule_source == "tls_check" and f.rule_id in ("missing-tls-1-3", "legacy-tls-version") \
        and bool(f.host)


async def _run_protocol(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "tls_protocol"
    host, port = _target(f)
    control = await _handshake(env, f)
    if not control.ok:
        return inconclusive(cid, f"no TLS handshake with {host}:{port}: {control.error}")
    ev = {"host": host, "port": port, "negotiated_by_default": control.version}

    if f.rule_id == "missing-tls-1-3":
        if control.version == "TLSv1.3":
            return not_reproducible(cid, "the server now negotiates TLS 1.3", **ev)
        return confirmed(cid, f"the server negotiates {control.version} and not TLS 1.3", **ev)

    # legacy-tls-version
    accepted: list[str] = []
    refused: list[str] = []
    incapable: list[str] = []
    for ver in _LEGACY:
        if env.tls_handshake is None and not await client_can_negotiate(ver):
            incapable.append(ver)
            continue
        hs = await _handshake(env, f, min_version=ver, max_version=ver, ciphers=_LEGACY_CIPHERS)
        if hs.ok:
            accepted.append(ver)
        elif hs.network:
            return inconclusive(cid, f"network problem while probing {ver}: {hs.error}", **ev)
        elif hs.reason == "CLIENT_UNSUPPORTED":
            incapable.append(ver)
        else:
            refused.append(ver)
    if accepted:
        return confirmed(cid, f"the server still accepts {', '.join(accepted)}", **ev,
                         accepted=accepted, refused=refused)
    if incapable:
        return inconclusive(cid, "this worker's TLS library cannot offer "
                                 f"{', '.join(incapable)}, so absence cannot be proven", **ev,
                            refused=refused, not_testable=incapable)
    return not_reproducible(cid, "the server refuses TLS 1.0 and 1.1", **ev, refused=refused)


# --------------------------------------------------------------------------- #
# weak cipher
# --------------------------------------------------------------------------- #

def _match_cipher(f: FindingCtx) -> bool:
    return f.rule_source == "tls_check" and f.rule_id == "weak-cipher" and bool(f.host)


def _families_of(name: str | None) -> list[str]:
    up = (name or "").upper()
    return [fam for fam, (needles, _o) in _WEAK_FAMILIES.items() if any(n in up for n in needles)]


def _offerable(families: list[str]) -> list[str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers(_LEGACY_CIPHERS)
    out = []
    for c in ctx.get_ciphers():
        n = c["name"].upper()
        if any(any(o in n for o in _WEAK_FAMILIES[fam][1]) for fam in families):
            out.append(c["name"])
    return out


async def _run_weak_cipher(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "tls_weak_cipher"
    host, port = _target(f)
    control = await _handshake(env, f)
    if not control.ok:
        return inconclusive(cid, f"no TLS handshake with {host}:{port}: {control.error}")
    orig = f.evidence.get("cipher")
    fams = _families_of(orig) or ["3DES", "NULL", "EXPORT", "ANON", "DES", "MD5"]
    names = _offerable(fams)
    ev = {"host": host, "port": port, "original_cipher": orig, "families": fams,
          "default_cipher": control.cipher}
    if not names:
        return inconclusive(cid, "this worker's TLS library cannot offer the weak cipher family "
                                 f"{'/'.join(fams)}, so absence cannot be proven", **ev)
    # Offer ONLY the weak suites; if the server picks one, it still accepts it.
    hs = await _handshake(env, f, min_version="TLSv1", max_version="TLSv1.2",
                          ciphers=":".join(names) + ":@SECLEVEL=0")
    if hs.ok:
        return confirmed(cid, f"the server still negotiates the weak cipher {hs.cipher}", **ev,
                         negotiated=hs.cipher, version=hs.version)
    if hs.network or hs.reason == "CLIENT_UNSUPPORTED":
        return inconclusive(cid, f"could not probe weak ciphers: {hs.error}", **ev)
    return not_reproducible(cid, f"the server refuses all offered {'/'.join(fams)} suites",
                            **ev, offered=len(names))


TLS_CHECKS = [
    ("tls_certificate", "TLS certificate", "TLS handshake; read leaf certificate validity/issuer.",
     _match_cert, _run_cert, ("TLS handshake",)),
    ("tls_protocol", "TLS protocol versions", "TLS handshakes at TLS 1.0/1.1 and default.",
     _match_protocol, _run_protocol, ("TLS handshake",)),
    ("tls_weak_cipher", "TLS weak ciphers", "TLS handshake offering only weak cipher suites.",
     _match_cipher, _run_weak_cipher, ("TLS handshake",)),
]
