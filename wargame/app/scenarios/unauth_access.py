"""Exposed admin panel / unauthenticated endpoint.

Proof signal: an HTTP GET to the sensitive PATH on the replica (via the runner,
so only ever the replica) answers 2xx with no credentials -> vulnerable;
401/403/404 -> not vulnerable. Only the finding's *path* is used, never its host.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlsplit

from ..sandbox.types import Replica, SandboxSpec
from .base import Scenario, ScenarioCtx, ScenarioResult, ScenarioRunner
from .cve_repro import image_at

_SOURCES = frozenset({"nuclei", "zap"})
_RULE_RE = re.compile(r"exposed|admin|unauth|panel", re.I)


def sensitive_path(ctx: ScenarioCtx) -> str:
    raw = (ctx.finding.get("path") or ctx.component.get("admin_path")
           or ctx.spec.get("path") or "")
    if not raw:
        url = str(ctx.finding.get("url") or ctx.finding.get("evidence_url") or "")
        raw = urlsplit(url).path if url else ""
    raw = urlsplit(str(raw)).path or "/admin"   # drop any scheme/host/query
    return raw if raw.startswith("/") else "/" + raw


class UnauthEndpointReplica(Scenario):
    id = "unauth-endpoint-replica"
    title = "Unauthenticated admin endpoint in a replica"
    description = (
        "Replicates the service and requests the sensitive path with no credentials. "
        "Vulnerable on 2xx; re-run with authentication required (401/403/404)."
    )
    category = "unauth_access"
    technique = "T1190"

    def default_spec(self) -> dict[str, Any]:
        return {"rule_sources": sorted(_SOURCES), "rule_pattern": _RULE_RE.pattern,
                "signal": "http-status-without-auth"}

    def matches(self, ctx: ScenarioCtx) -> bool:
        text = f"{ctx.rule_id} {ctx.finding.get('title', '')} {ctx.finding.get('name', '')}"
        return bool(ctx.rule_source.lower() in _SOURCES and _RULE_RE.search(text)
                    and ctx.component.get("image"))

    def _spec(self, ctx: ScenarioCtx, protected: bool) -> SandboxSpec:
        path = sensitive_path(ctx)
        return SandboxSpec(
            component=ctx.product or "service",
            image=image_at(str(ctx.component["image"]), ctx.version),
            image_digest=ctx.component.get("image_digest"),
            version=ctx.version or None,
            port=int(ctx.component.get("port") or 80),
            env=dict(ctx.component.get("env") or {}),
            config={"serve_paths": [path],
                    "auth_required_paths": [path] if protected else []},
        )

    def build_spec(self, ctx: ScenarioCtx) -> SandboxSpec:
        return self._spec(ctx, protected=False)

    def fixed_spec(self, ctx: ScenarioCtx) -> Optional[SandboxSpec]:
        return self._spec(ctx, protected=True)

    def fix_ref(self, ctx: ScenarioCtx) -> str:
        return f"require auth on {sensitive_path(ctx)}"

    async def probe(self, runner: ScenarioRunner, replica: Replica,
                    ctx: ScenarioCtx) -> ScenarioResult:
        path = sensitive_path(ctx)
        r = await runner.http(replica, path)   # GET, no credentials, replica only
        ev = {"path": path, "status": r.status, "error": r.error}
        if not r.ok:
            return ScenarioResult.inconclusive(f"replica did not answer for {path}", **ev)
        if 200 <= r.status < 300:
            ev["body_excerpt"] = r.body_excerpt[:120]
            return ScenarioResult.vulnerable(f"{path} served {r.status} without authentication", **ev)
        if r.status in (401, 403, 404):
            return ScenarioResult.not_vulnerable(f"{path} answered {r.status}", **ev)
        if 300 <= r.status < 400 and "login" in r.headers.get("Location", "").lower():
            return ScenarioResult.not_vulnerable(f"{path} redirects to login", **ev)
        return ScenarioResult.inconclusive(f"unexpected status {r.status} for {path}", **ev)
