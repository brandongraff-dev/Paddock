"""TLS posture grading.

Turns the raw TLS facts gathered by :mod:`app.modules.tls_inspect` into a
letter grade (``A+``..``F``, plus ``T`` for a trust/validation failure) with a
0–100 score. The score is a deterministic function of the input facts, so a
fixed handshake always yields the same grade — important for stable tests and
screenshots.

Grading rule table (SSL-Labs flavoured, simplified — mirrors
``docs/TIER2_CONTRACT.md`` §2):

    base score ............................................ 100
    TLS 1.1 enabled ....................................... -20
    TLS 1.0 enabled ....................................... -30
    SSLv3 enabled ......................................... -40
    TLS 1.3 not offered ................................... -5
    weak cipher present ................................... -20
    missing forward secrecy ............................... -10
    certificate expiring in < 15 days ..................... -15
    certificate expiring in < 30 days (but >= 15) ......... -5

    certificate expired .............................. grade T (trust failure)
    self-signed / untrusted cert in prod ............. grade T (trust failure)

    score -> grade:  >=95 A+ | >=80 A | >=65 B | >=50 C
                     >=35 D  | >=20 E | else F

Deductions stack (e.g. TLS 1.0 + TLS 1.1 both enabled => -50). The score floors
at 0. A trust/validation failure short-circuits to grade ``T`` regardless of
score; the computed score is still reported for context.

Detection only: we read the server's advertised posture. We never attempt to
exploit a weak configuration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from app.modules import tls_inspect
from app.modules.tls_inspect import _WEAK_CIPHER_FRAGMENTS
from app.orchestrator import OrchestratorClient
from app.scope_guard import ScopeGuard
from app.util.politeness import PolitenessLimiter

log = structlog.get_logger(__name__)


# ---- grading primitives ----------------------------------------------------

# Deductions keyed by a stable issue id. Documented in the module docstring.
_PROTOCOL_DEDUCTIONS = {
    "SSLv3": 40,
    "TLS1.0": 30,
    "TLS1.1": 20,
}
_DEDUCT_NO_TLS13 = 5
_DEDUCT_WEAK_CIPHER = 20
_DEDUCT_NO_FS = 10
_DEDUCT_EXPIRING_15 = 15
_DEDUCT_EXPIRING_30 = 5

_GRADE_BANDS = (
    (95, "A+"),
    (80, "A"),
    (65, "B"),
    (50, "C"),
    (35, "D"),
    (20, "E"),
)

# Grades at or below C emit a finding; map grade -> severity.
_GRADE_SEVERITY = {
    "C": "low",
    "D": "medium",
    "E": "medium",
    "F": "high",
    "T": "high",
}


@dataclass
class GradeResult:
    host: str
    port: int
    grade: str
    score: int
    protocols: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    cert_expires: str | None = None
    trust_failure: bool = False


def _normalize_protocols(versions: Any) -> list[str]:
    """Map tlsx version strings to canonical labels, highest first."""
    if isinstance(versions, str):
        versions = [versions]
    out: set[str] = set()
    for v in versions or []:
        u = str(v).upper().replace(" ", "")
        if "SSLV3" in u or u == "SSL3" or "SSLV3.0" in u:
            out.add("SSLv3")
        elif "1.3" in u:
            out.add("TLS1.3")
        elif "1.2" in u:
            out.add("TLS1.2")
        elif "1.1" in u:
            out.add("TLS1.1")
        elif "1.0" in u:
            out.add("TLS1.0")
    order = ["TLS1.3", "TLS1.2", "TLS1.1", "TLS1.0", "SSLv3"]
    return [p for p in order if p in out]


def _extract_ciphers(obj: dict) -> list[str]:
    raw = obj.get("cipher") or obj.get("cipher_suite") or obj.get("ciphers") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(c) for c in raw if c]


def _has_forward_secrecy(protocols: list[str], ciphers: list[str]) -> bool:
    if "TLS1.3" in protocols:
        return True  # TLS 1.3 mandates ephemeral key exchange
    for c in ciphers:
        cu = c.upper()
        if "ECDHE" in cu or "DHE" in cu or cu.startswith("TLS_AES") or cu.startswith("TLS_CHACHA"):
            return True
    return False


def grade_facts(facts: dict[str, Any], *, env: str | None = None) -> GradeResult | None:
    """Deterministically grade a single host from gathered TLS facts.

    Returns ``None`` when there is nothing to grade (no handshake rows), so the
    caller emits no grade. ``env`` controls the prod-only trust-failure rule;
    it defaults to ``settings.env``.
    """
    if env is None:
        from app.config import settings
        env = settings.env

    host = facts.get("host") or ""
    port = int(facts.get("port") or 443)
    rows = facts.get("rows") or []
    if not rows:
        return None
    obj = rows[0]

    protocols = _normalize_protocols(
        obj.get("tls_version") or obj.get("tls-version") or obj.get("version") or []
    )
    ciphers = _extract_ciphers(obj)
    cert = tls_inspect._normalize_cert(obj) or {}

    score = 100
    issues: list[str] = []
    weak_ciphers: list[str] = []
    trust_failure = False

    # --- protocol deductions ---
    for proto, deduct in _PROTOCOL_DEDUCTIONS.items():
        if proto in protocols:
            score -= deduct
            issues.append(f"{proto} enabled (-{deduct})")
    if "TLS1.3" not in protocols:
        score -= _DEDUCT_NO_TLS13
        issues.append(f"TLS1.3 not offered (-{_DEDUCT_NO_TLS13})")

    # --- cipher deductions ---
    for c in ciphers:
        if any(frag in c.upper() for frag in _WEAK_CIPHER_FRAGMENTS):
            weak_ciphers.append(c)
    if weak_ciphers:
        score -= _DEDUCT_WEAK_CIPHER
        issues.append(f"weak cipher present (-{_DEDUCT_WEAK_CIPHER})")
    if ciphers and not _has_forward_secrecy(protocols, ciphers):
        score -= _DEDUCT_NO_FS
        issues.append(f"missing forward secrecy (-{_DEDUCT_NO_FS})")

    # --- certificate validity / trust ---
    cert_expires = cert.get("not_after")
    not_after = tls_inspect._parse_ts(cert_expires)
    now = datetime.now(timezone.utc)
    if not_after and not_after < now:
        trust_failure = True
        issues.append("certificate expired")
    elif not_after:
        days = (not_after - now).days
        if days < 15:
            score -= _DEDUCT_EXPIRING_15
            issues.append(f"certificate expires in {days}d (-{_DEDUCT_EXPIRING_15})")
        elif days < 30:
            score -= _DEDUCT_EXPIRING_30
            issues.append(f"certificate expires in {days}d (-{_DEDUCT_EXPIRING_30})")

    untrusted = bool(cert.get("self_signed")) or bool(obj.get("untrusted")) or bool(obj.get("mismatched"))
    if untrusted and env == "prod":
        trust_failure = True
        issues.append("self-signed / untrusted certificate in production")

    score = max(0, min(100, score))
    grade = "T" if trust_failure else _score_to_grade(score)

    return GradeResult(
        host=host, port=port, grade=grade, score=score,
        protocols=protocols, weak_ciphers=weak_ciphers, issues=issues,
        cert_expires=cert_expires, trust_failure=trust_failure,
    )


def _score_to_grade(score: int) -> str:
    for threshold, letter in _GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def result_to_item(result: GradeResult, *, asset_id: str | None = None) -> dict[str, Any]:
    """Shape a :class:`GradeResult` for ``POST /v1/tls-grades/bulk``."""
    return {
        "asset_id": asset_id,
        "host": result.host,
        "grade": result.grade,
        "score": result.score,
        "protocols": result.protocols,
        "weak_ciphers": result.weak_ciphers,
        "issues": result.issues,
        "cert_expires": result.cert_expires,
    }


def result_to_finding(result: GradeResult) -> dict | None:
    """A ``tls_grade`` finding when the grade is C or worse, else ``None``."""
    severity = _GRADE_SEVERITY.get(result.grade)
    if severity is None:
        return None
    canonical = f"{result.host}:{result.port}"
    return {
        "target_host": result.host,
        "target_canonical": canonical,
        "target_kind": "endpoint",
        "rule_id": f"tls-grade-{result.grade.lower().replace('+', 'plus')}",
        "rule_source": "tls_grade",
        "severity": severity,
        "title": f"Weak TLS posture — grade {result.grade}",
        "description": (
            f"TLS configuration for {canonical} graded {result.grade} "
            f"(score {result.score}/100). "
            + ("Trust/validation failure: clients cannot safely verify this endpoint. "
               if result.trust_failure else "")
            + "Weak protocols, ciphers or certificate hygiene reduce confidentiality "
              "and integrity guarantees."
        ),
        "remediation": (
            "Disable legacy protocols (TLS 1.0/1.1, SSLv3), enable TLS 1.3, "
            "restrict to forward-secret ciphers from the Mozilla Intermediate/Modern "
            "set, and renew/replace the certificate so it is valid and publicly trusted."
        ),
        "evidence": {
            "grade": result.grade,
            "score": result.score,
            "protocols": result.protocols,
            "weak_ciphers": result.weak_ciphers,
            "issues": result.issues,
            "cert_expires": result.cert_expires,
        },
    }


# ---- module entrypoint ------------------------------------------------------


async def grade_host(
    target: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    scan_id: str | None = None,
    asset_id: str | None = None,
    env: str | None = None,
    facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Grade ``target`` (``host`` or ``host:port``).

    Reuses ``facts`` from a prior :func:`tls_inspect.gather_facts` call when
    provided (full_recon does this to avoid a second handshake); otherwise it
    gathers them itself.

    Posts the grade to the orchestrator's ``/v1/tls-grades/bulk`` and returns
    ``{assets, edges, findings, summary}``. A ``tls_grade`` finding is included
    only when the grade is C or worse.
    """
    gathered_here = facts is None
    if facts is None:
        facts = await tls_inspect.gather_facts(
            target, scope=scope, politeness=politeness,
            orchestrator=orchestrator, scan_id=scan_id,
        )

    host, _, port_s = target.partition(":")
    host_key = host.lower()
    port = int(port_s) if port_s else 443
    findings: list[dict] = []

    if not facts.get("available"):
        # tlsx missing. When we gathered the facts ourselves, surface a
        # tool-unavailable finding (matching tls_inspect's fallback); when the
        # caller gathered them, tls_inspect already emitted that finding, so we
        # stay quiet to avoid a duplicate.
        if gathered_here:
            findings.append({
                "target_host": host_key,
                "target_canonical": f"{host_key}:{port}",
                "target_kind": "endpoint",
                "rule_id": "tool-unavailable-tlsx",
                "rule_source": "policy",
                "severity": "info",
                "title": "tlsx not installed on this worker",
                "description": "Skipping TLS grading; binary missing.",
                "evidence": {"tool": "tlsx"},
            })
        return {"assets": [], "edges": [], "findings": findings, "summary": {}}

    result = grade_facts(facts, env=env)
    if result is None:
        return {"assets": [], "edges": [], "findings": findings,
                "summary": {"graded": False, "error": facts.get("error")}}

    item = result_to_item(result, asset_id=asset_id)
    try:
        await orchestrator.tls_grades_bulk([item])
    except Exception as e:  # best-effort; a failed upsert must not crash the job
        log.warning("tls_grade.bulk_failed", host=result.host, error=str(e))

    finding = result_to_finding(result)
    if finding is not None:
        findings.append(finding)

    log.info("tls_grade.graded", host=result.host, grade=result.grade, score=result.score)
    return {
        "assets": [],
        "edges": [],
        "findings": findings,
        "summary": {
            "graded": True,
            "grade": result.grade,
            "score": result.score,
            "host": result.host,
        },
    }
