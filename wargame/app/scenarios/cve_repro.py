"""CVE / SCA finding: prove the vulnerable version is present in a replica of
the component, then prove the fixed version is not.

The proof signal is identification + reachability, deliberately NOT an exploit:
no payloads are sent. Inside the replica we read the product's own version
(``exec_in`` of a version command, falling back to an HTTP banner) and compare
it with the finding's fixed version, and confirm the exposure is reachable
(TCP/HTTP). That is deterministic and defensible; it is all against the replica
the runner hands us, never a live address.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from ..sandbox.types import Replica, SandboxSpec
from .base import Scenario, ScenarioCtx, ScenarioResult, ScenarioRunner

SCA_SOURCES = frozenset({"sca", "grype", "trivy", "osv", "nvd"})
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_VER_RE = re.compile(r"\d+(?:\.\d+)+|\d+")


# -- small helpers (shared with the sibling scenarios) -------------------------
def split_image(image: str) -> tuple[str, Optional[str]]:
    """``"library/redis:6.0@sha256:.."`` -> ``("library/redis", "6.0")``."""
    ref = (image or "").strip().split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        base, tag = ref.rsplit(":", 1)
        return base, tag
    return ref, None


def image_at(image: str, version: str) -> str:
    """The component image pinned to ``version`` (tag replaced, never a URL)."""
    base, _ = split_image(image)
    return f"{base}:{version}" if version else base


def parse_version(text: str) -> Optional[tuple[int, ...]]:
    m = _VER_RE.search(text or "")
    return tuple(int(p) for p in m.group(0).split(".")) if m else None


def _meta(ctx: ScenarioCtx, *keys: str) -> Optional[str]:
    meta = ctx.finding.get("metadata") or {}
    for k in keys:
        for src in (ctx.finding, meta if isinstance(meta, dict) else {}):
            v = src.get(k)
            if v:
                return str(v[0] if isinstance(v, (list, tuple)) else v)
    return None


def cve_id(ctx: ScenarioCtx) -> Optional[str]:
    for v in (ctx.finding.get("cve"), ctx.finding.get("cve_id"), ctx.rule_id):
        m = _CVE_RE.search(str(v or ""))
        if m:
            return m.group(0).upper()
    return None


def fixed_version(ctx: ScenarioCtx) -> str:
    """Fixed version from finding metadata, else bump the last numeric part."""
    explicit = _meta(ctx, "fixed_version", "fixed_in")
    if explicit:
        return explicit.lstrip("vV")
    parts = ctx.version.lstrip("vV").split(".")
    if parts and parts[-1].isdigit():
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    return (ctx.version + ".1") if ctx.version else "latest"


class CveContainerRepro(Scenario):
    id = "cve-container-repro"
    title = "Reproduce a CVE in a container replica"
    description = (
        "Stands up the component's current image/version in an isolated replica, "
        "proves the affected version is present and reachable (version + reachability "
        "only, no exploit payload), then re-runs on the fixed version."
    )
    category = "cve_repro"
    technique = "T1190"

    def default_spec(self) -> dict[str, Any]:
        return {"rule_sources": sorted(SCA_SOURCES), "requires": ["image", "version"],
                "signal": "version-identity+reachability"}

    def matches(self, ctx: ScenarioCtx) -> bool:
        is_cve = ctx.rule_source.lower() in SCA_SOURCES or cve_id(ctx) is not None
        return bool(is_cve and ctx.component.get("image") and ctx.version)

    def _spec(self, ctx: ScenarioCtx, version: str) -> SandboxSpec:
        port = ctx.component.get("port")
        return SandboxSpec(
            component=ctx.product or "component",
            image=image_at(str(ctx.component["image"]), version),
            image_digest=ctx.component.get("image_digest") if version == ctx.version else None,
            version=version,
            port=int(port) if port else None,
            env=dict(ctx.component.get("env") or {}),
        )

    def build_spec(self, ctx: ScenarioCtx) -> SandboxSpec:
        return self._spec(ctx, ctx.version)

    def fixed_spec(self, ctx: ScenarioCtx) -> Optional[SandboxSpec]:
        return self._spec(ctx, fixed_version(ctx))

    def fix_ref(self, ctx: ScenarioCtx) -> str:
        return f"upgrade {ctx.product} {ctx.version} -> {fixed_version(ctx)}"

    async def probe(self, runner: ScenarioRunner, replica: Replica,
                    ctx: ScenarioCtx) -> ScenarioResult:
        fixed = fixed_version(ctx)
        fixed_t = parse_version(fixed)
        ev: dict[str, Any] = {"cve": cve_id(ctx), "expected_vulnerable": ctx.version,
                              "fixed_version": fixed}

        # 1. identify: version command inside the replica, else an HTTP banner.
        argv = tuple(ctx.component.get("version_cmd") or (ctx.product, "--version"))
        res = await runner.exec_in(replica, argv)
        ev["version_cmd"] = list(argv)
        observed_text = f"{res.stdout}\n{res.stderr}" if res.ok else ""
        if not res.ok:
            ev["exec_exit_code"] = res.exit_code
            http = await runner.http(replica, "/")
            if http.ok:
                observed_text = f"{http.headers.get('Server', '')} {http.headers.get('X-Powered-By', '')}"
                ev["http_status"] = http.status
        observed = parse_version(observed_text)
        if observed is None or fixed_t is None:
            return ScenarioResult.inconclusive("could not identify the replica's version", **ev)
        ev["observed_version"] = ".".join(map(str, observed))

        # 2. decide against the affected range (< fixed).
        if observed >= fixed_t:
            return ScenarioResult.not_vulnerable(
                f"replica runs {ev['observed_version']} (>= fixed {fixed})", **ev)

        # 3. reachability of the exposure on the replica.
        reachable = (await runner.tcp_open(replica)) if replica.internal_port else \
            (await runner.http(replica, "/")).ok
        ev["reachable"] = reachable
        if not reachable:
            return ScenarioResult.inconclusive(
                "affected version present but the exposure is not reachable in the replica", **ev)
        return ScenarioResult.vulnerable(
            f"replica runs affected {ev['observed_version']} (< {fixed}) and is reachable", **ev)
