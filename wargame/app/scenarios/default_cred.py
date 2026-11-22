"""Default / weak credential on a replicable service.

NOTE ON CREDENTIAL USE: this is the one scenario that *uses a credential*. That
is legitimate because the target is our own throwaway replica, built from the
owner's image on an internal-only network and destroyed afterwards. The default
credential is a well-known vendor value (or the one named by the finding); it
is never a harvested secret, and the runner can only reach the replica. The
credential is redacted from recorded evidence.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from ..sandbox.types import Replica, SandboxSpec
from .base import Scenario, ScenarioCtx, ScenarioResult, ScenarioRunner
from .cve_repro import image_at

_RULE_RE = re.compile(r"default|weak[-_ ]?cred|weak[-_ ]?pass|blank[-_ ]?pass|default[-_ ]?login", re.I)
_REJECT_RE = re.compile(
    r"authentication failed|access denied|denied|noauth|wrongpass|invalid password|"
    r"unauthorized|401|403|incorrect", re.I)
ROTATED = "rotated-not-the-default-9f2c"

# product -> (default user, default password, port, env keys to set user/password,
#             argv builder(user, password) run INSIDE the replica)
_PROFILES: dict[str, dict[str, Any]] = {
    "postgres": {"user": "postgres", "password": "postgres", "port": 5432,
                 "env": lambda u, p: {"POSTGRES_USER": u, "POSTGRES_PASSWORD": p},
                 "argv": lambda u, p: ("env", f"PGPASSWORD={p}", "psql", "-h", "127.0.0.1",
                                       "-U", u, "-tAc", "select 1")},
    "mysql": {"user": "root", "password": "root", "port": 3306,
              "env": lambda u, p: {"MYSQL_ROOT_PASSWORD": p},
              "argv": lambda u, p: ("mysql", "-h", "127.0.0.1", f"-u{u}", f"-p{p}", "-e", "select 1")},
    "redis": {"user": "default", "password": "foobared", "port": 6379,
              "env": lambda u, p: {"REDIS_PASSWORD": p},
              "argv": lambda u, p: ("redis-cli", "-h", "127.0.0.1", "--user", u, "--pass", p, "ping")},
    "grafana": {"user": "admin", "password": "admin", "port": 3000,
                "env": lambda u, p: {"GF_SECURITY_ADMIN_USER": u, "GF_SECURITY_ADMIN_PASSWORD": p},
                "argv": lambda u, p: ("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                      "-u", f"{u}:{p}", "http://127.0.0.1:3000/api/user")},
}
_ALIASES = {"postgresql": "postgres", "mariadb": "mysql", "valkey": "redis"}


def _profile(ctx: ScenarioCtx) -> Optional[dict[str, Any]]:
    return _PROFILES.get(_ALIASES.get(ctx.product, ctx.product))


def _default_cred(ctx: ScenarioCtx) -> tuple[str, str]:
    given = ctx.component.get("default_credentials") or ctx.spec.get("default_credentials") or {}
    prof = _profile(ctx) or {}
    return (str(given.get("username") or prof.get("user") or "admin"),
            str(given.get("password", prof.get("password", "admin"))))


class DefaultCredentialReplica(Scenario):
    id = "default-cred-replica"
    title = "Default credential accepted by a service replica"
    description = (
        "Stands up the service in an isolated replica configured with its default "
        "credential and attempts an authenticated login inside the replica. Re-runs "
        "with the credential rotated."
    )
    category = "default_cred"
    technique = "T1078.001"

    def default_spec(self) -> dict[str, Any]:
        return {"rule_pattern": _RULE_RE.pattern, "products": sorted(_PROFILES),
                "signal": "default-credential-login-in-replica"}

    def matches(self, ctx: ScenarioCtx) -> bool:
        text = f"{ctx.rule_id} {ctx.finding.get('title', '')} {ctx.finding.get('name', '')}"
        return bool(_RULE_RE.search(text) and ctx.component.get("image")
                    and (_profile(ctx) is not None or ctx.component.get("default_credentials")))

    def _spec(self, ctx: ScenarioCtx, password: str) -> SandboxSpec:
        prof = _profile(ctx)
        user, _ = _default_cred(ctx)
        env = dict(ctx.component.get("env") or {})
        if prof:
            env.update(prof["env"](user, password))
        return SandboxSpec(
            component=ctx.product or "service",
            image=image_at(str(ctx.component["image"]), ctx.version),
            image_digest=ctx.component.get("image_digest"),
            version=ctx.version or None,
            env=env,
            port=int(ctx.component.get("port") or (prof or {}).get("port") or 0) or None,
            config={"credential_state": "default" if password == _default_cred(ctx)[1] else "rotated"},
        )

    def build_spec(self, ctx: ScenarioCtx) -> SandboxSpec:
        return self._spec(ctx, _default_cred(ctx)[1])

    def fixed_spec(self, ctx: ScenarioCtx) -> Optional[SandboxSpec]:
        return self._spec(ctx, ROTATED)

    def fix_ref(self, ctx: ScenarioCtx) -> str:
        user, _ = _default_cred(ctx)
        return f"rotate the default credential for {ctx.product} user '{user}' to a unique secret (or disable the account)"

    async def probe(self, runner: ScenarioRunner, replica: Replica,
                    ctx: ScenarioCtx) -> ScenarioResult:
        user, pw = _default_cred(ctx)
        prof = _profile(ctx)
        custom = ctx.component.get("auth_cmd")  # optional argv template with {user}/{password}
        if custom:
            argv = tuple(a.format(user=user, password=pw) for a in custom)
        elif prof:
            argv = prof["argv"](user, pw)
        else:
            return ScenarioResult.inconclusive("no login command known for this service")
        res = await runner.exec_in(replica, argv)
        ev = {"user": user, "credential": "default (redacted)", "exit_code": res.exit_code,
              "timed_out": res.timed_out, "output_excerpt": (res.stdout or res.stderr)[:120].replace(pw, "***") if pw else ""}
        out = f"{res.stdout}\n{res.stderr}"
        if res.timed_out:
            return ScenarioResult.inconclusive("login attempt timed out", **ev)
        # HTTP-style clients print the status code; others signal via exit code.
        code = res.stdout.strip()
        is_http = code.isdigit() and len(code) == 3
        accepted = code.startswith("2") if is_http else \
            (res.exit_code == 0 and not _REJECT_RE.search(out))
        if accepted:
            return ScenarioResult.vulnerable(f"default credential for '{user}' authenticated on the replica", **ev)
        if _REJECT_RE.search(out) or code in {"401", "403"}:
            return ScenarioResult.not_vulnerable(f"default credential for '{user}' was rejected", **ev)
        return ScenarioResult.inconclusive("login failed for a non-authentication reason", **ev)
