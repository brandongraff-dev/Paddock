"""Scenario library tests: no DB, no Docker, no backend -- an inline stub runner."""
from __future__ import annotations

import pytest

from app.sandbox.types import ExecResult, IsolationError, NetworkMode, Replica, SandboxSpec
from app.scenarios.base import CATEGORIES, HttpProbe, ScenarioCtx, Verdict
from app.scenarios.cve_repro import CveContainerRepro, fixed_version
from app.scenarios.default_cred import DefaultCredentialReplica
from app.scenarios.registry import REGISTRY, catalogue, resolve
from app.scenarios.unauth_access import UnauthEndpointReplica


class StubRunner:
    """Programmable ScenarioRunner; records every call (all on the given replica)."""

    def __init__(self, *, exec_result=None, http_result=None, tcp=True):
        self.exec_result = exec_result or ExecResult(0)
        self.http_result = http_result or HttpProbe(status=200)
        self.tcp = tcp
        self.calls: list[tuple] = []

    async def exec_in(self, replica, argv, *, timeout_sec=30):
        self.calls.append(("exec", replica.replica_id, argv))
        return self.exec_result

    async def http(self, replica, path="/", *, method="GET", timeout_sec=15, headers=None):
        self.calls.append(("http", replica.replica_id, path, method))
        return self.http_result

    async def tcp_open(self, replica, *, timeout_sec=5):
        self.calls.append(("tcp", replica.replica_id))
        return self.tcp


def replica(port=8080) -> Replica:
    return Replica(replica_id="r1", component="x", network_mode=NetworkMode.INTERNAL,
                   internal_host="x-r1", internal_port=port, image="x:1", verified=True)


def cve_ctx(**over):
    d = dict(component={"product": "nginx", "version": "1.20.0", "image": "library/nginx",
                        "port": 80, "version_cmd": ["nginx", "-v"]},
             finding={"rule_source": "trivy", "rule_id": "CVE-2021-23017",
                      "metadata": {"fixed_version": "1.20.1"}})
    d.update(over)
    return ScenarioCtx(**d)


def cred_ctx(product="postgres", **over):
    d = dict(component={"product": product, "version": "15", "image": "library/" + product},
             finding={"rule_source": "nuclei", "rule_id": "default-credentials-login"})
    d.update(over)
    return ScenarioCtx(**d)


def unauth_ctx(**over):
    d = dict(component={"product": "jenkins", "version": "2.400", "image": "jenkins/jenkins", "port": 8080},
             finding={"rule_source": "nuclei", "rule_id": "exposed-admin-panel",
                      "url": "https://live.example.com/manage?x=1"})
    d.update(over)
    return ScenarioCtx(**d)


# ---------------------------------------------------------------- CVE
class TestCve:
    s = CveContainerRepro()

    def test_matches(self):
        assert self.s.matches(cve_ctx())
        assert self.s.matches(cve_ctx(finding={"rule_source": "zap", "cve": "CVE-2020-1234"}))
        assert not self.s.matches(cve_ctx(finding={"rule_source": "zap", "rule_id": "x"}))
        no_img = cve_ctx(component={"product": "nginx", "version": "1.20.0"})
        assert not self.s.matches(no_img)
        assert not self.s.matches(cve_ctx(component={"product": "nginx", "image": "nginx"}))

    def test_specs_and_fix(self):
        ctx = cve_ctx()
        b, f = self.s.build_spec(ctx), self.s.fixed_spec(ctx)
        assert isinstance(b, SandboxSpec) and b.image == "library/nginx:1.20.0" and b.port == 80
        assert f.image == "library/nginx:1.20.1" and f != b
        assert "://" not in b.image
        assert self.s.fix_ref(ctx) == "upgrade nginx 1.20.0 -> 1.20.1"

    def test_fixed_version_bump_and_registry_tag(self):
        ctx = cve_ctx(finding={"rule_source": "sca"},
                      component={"product": "redis", "version": "6.0.9", "image": "reg.io:5000/redis:6.0.9"})
        assert fixed_version(ctx) == "6.0.10"
        assert self.s.build_spec(ctx).image == "reg.io:5000/redis:6.0.9"

    async def test_vulnerable(self):
        r = StubRunner(exec_result=ExecResult(0, stderr="nginx version: nginx/1.20.0"))
        res = await self.s.probe(r, replica(), cve_ctx())
        assert res.verdict is Verdict.VULNERABLE
        assert res.evidence["observed_version"] == "1.20.0" and res.evidence["reachable"]
        assert all(c[1] == "r1" for c in r.calls)

    async def test_not_vulnerable_when_fixed(self):
        r = StubRunner(exec_result=ExecResult(0, stderr="nginx version: nginx/1.20.1"))
        assert (await self.s.probe(r, replica(), cve_ctx())).verdict is Verdict.NOT_VULNERABLE

    async def test_http_banner_fallback(self):
        r = StubRunner(exec_result=ExecResult(127), http_result=HttpProbe(200, {"Server": "nginx/1.20.0"}))
        assert (await self.s.probe(r, replica(), cve_ctx())).verdict is Verdict.VULNERABLE

    async def test_unreachable_is_inconclusive(self):
        r = StubRunner(exec_result=ExecResult(0, stdout="nginx/1.20.0"), tcp=False)
        assert (await self.s.probe(r, replica(), cve_ctx())).verdict is Verdict.INCONCLUSIVE

    async def test_unidentifiable_is_inconclusive(self):
        r = StubRunner(exec_result=ExecResult(1), http_result=HttpProbe(error="boom"))
        assert (await self.s.probe(r, replica(), cve_ctx())).verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------- default cred
class TestDefaultCred:
    s = DefaultCredentialReplica()

    def test_matches(self):
        assert self.s.matches(cred_ctx())
        assert self.s.matches(cred_ctx(finding={"rule_source": "x", "rule_id": "weak-cred-redis"}))
        assert not self.s.matches(cred_ctx(finding={"rule_id": "exposed-admin-panel"}))
        assert not self.s.matches(cred_ctx(component={"product": "postgres", "version": "15"}))
        assert not self.s.matches(cred_ctx("someapp"))

    def test_specs(self):
        ctx = cred_ctx()
        b, f = self.s.build_spec(ctx), self.s.fixed_spec(ctx)
        assert b.env["POSTGRES_PASSWORD"] == "postgres" and b.config["credential_state"] == "default"
        assert f.env["POSTGRES_PASSWORD"] != "postgres" and f.config["credential_state"] == "rotated"
        assert f != b and "://" not in b.image and b.component == "postgres"
        assert "rotate" in self.s.fix_ref(ctx)

    async def test_vulnerable_when_default_authenticates(self):
        r = StubRunner(exec_result=ExecResult(0, stdout="1"))
        res = await self.s.probe(r, replica(5432), cred_ctx())
        assert res.verdict is Verdict.VULNERABLE
        assert "postgres" not in str(res.evidence.get("credential"))   # redacted
        assert r.calls[0][0] == "exec"

    async def test_not_vulnerable_when_rejected(self):
        r = StubRunner(exec_result=ExecResult(2, stderr="FATAL: password authentication failed"))
        assert (await self.s.probe(r, replica(5432), cred_ctx())).verdict is Verdict.NOT_VULNERABLE

    async def test_redis_wrongpass_exit0(self):
        r = StubRunner(exec_result=ExecResult(0, stdout="WRONGPASS invalid username-password pair"))
        assert (await self.s.probe(r, replica(6379), cred_ctx("redis"))).verdict is Verdict.NOT_VULNERABLE
        r = StubRunner(exec_result=ExecResult(0, stdout="PONG"))
        assert (await self.s.probe(r, replica(6379), cred_ctx("redis"))).verdict is Verdict.VULNERABLE

    async def test_grafana_http_code(self):
        ctx = cred_ctx("grafana")
        assert (await self.s.probe(StubRunner(exec_result=ExecResult(0, stdout="200")), replica(3000), ctx)).verdict is Verdict.VULNERABLE
        assert (await self.s.probe(StubRunner(exec_result=ExecResult(0, stdout="401")), replica(3000), ctx)).verdict is Verdict.NOT_VULNERABLE

    async def test_inconclusive(self):
        r = StubRunner(exec_result=ExecResult(1, stderr="connection refused"))
        assert (await self.s.probe(r, replica(5432), cred_ctx())).verdict is Verdict.INCONCLUSIVE
        r = StubRunner(exec_result=ExecResult(-1, timed_out=True))
        assert (await self.s.probe(r, replica(5432), cred_ctx())).verdict is Verdict.INCONCLUSIVE

    async def test_custom_credential_and_cmd(self):
        ctx = cred_ctx("acme", component={"product": "acme", "version": "1", "image": "acme/db",
                                          "default_credentials": {"username": "sa", "password": "sa"},
                                          "auth_cmd": ["acmecli", "-u", "{user}", "-p", "{password}"]})
        assert self.s.matches(ctx)
        r = StubRunner(exec_result=ExecResult(0, stdout="ok"))
        assert (await self.s.probe(r, replica(), ctx)).verdict is Verdict.VULNERABLE
        assert r.calls[0][2] == ("acmecli", "-u", "sa", "-p", "sa")


# ---------------------------------------------------------------- unauth
class TestUnauth:
    s = UnauthEndpointReplica()

    def test_matches(self):
        assert self.s.matches(unauth_ctx())
        assert self.s.matches(unauth_ctx(finding={"rule_source": "zap", "rule_id": "unauth-actuator"}))
        assert not self.s.matches(unauth_ctx(finding={"rule_source": "trivy", "rule_id": "exposed-admin"}))
        assert not self.s.matches(unauth_ctx(finding={"rule_source": "nuclei", "rule_id": "xss"}))

    def test_specs_path_only(self):
        ctx = unauth_ctx()
        b, f = self.s.build_spec(ctx), self.s.fixed_spec(ctx)
        assert b.config["serve_paths"] == ["/manage"]          # host/query stripped
        assert b.config["auth_required_paths"] == [] and f.config["auth_required_paths"] == ["/manage"]
        assert b != f and "live.example.com" not in repr(b)
        assert self.s.fix_ref(ctx) == "require auth on /manage"

    def test_default_path(self):
        ctx = unauth_ctx(finding={"rule_source": "nuclei", "rule_id": "exposed-panel"})
        assert self.s.fix_ref(ctx) == "require auth on /admin"

    @pytest.mark.parametrize("status", [200, 204])
    async def test_vulnerable(self, status):
        r = StubRunner(http_result=HttpProbe(status=status, body_excerpt="dashboard"))
        res = await self.s.probe(r, replica(), unauth_ctx())
        assert res.verdict is Verdict.VULNERABLE
        assert r.calls == [("http", "r1", "/manage", "GET")]

    @pytest.mark.parametrize("status", [401, 403, 404])
    async def test_not_vulnerable(self, status):
        r = StubRunner(http_result=HttpProbe(status=status))
        assert (await self.s.probe(r, replica(), unauth_ctx())).verdict is Verdict.NOT_VULNERABLE

    async def test_redirect_and_errors(self):
        r = StubRunner(http_result=HttpProbe(302, {"Location": "/login"}))
        assert (await self.s.probe(r, replica(), unauth_ctx())).verdict is Verdict.NOT_VULNERABLE
        r = StubRunner(http_result=HttpProbe(500))
        assert (await self.s.probe(r, replica(), unauth_ctx())).verdict is Verdict.INCONCLUSIVE
        r = StubRunner(http_result=HttpProbe(error="timeout"))
        assert (await self.s.probe(r, replica(), unauth_ctx())).verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------- registry
class TestRegistry:
    def test_resolve(self):
        assert resolve(cve_ctx()).id == "cve-container-repro"
        assert resolve(cred_ctx()).id == "default-cred-replica"
        assert resolve(unauth_ctx()).id == "unauth-endpoint-replica"
        assert resolve(ScenarioCtx(component={"product": "x"})) is None

    def test_specific_before_generic(self):
        both = cred_ctx(finding={"rule_source": "trivy", "rule_id": "CVE-2020-1-default-password",
                                 "cve": "CVE-2020-1234"})
        assert resolve(both).id == "default-cred-replica"

    def test_resolve_survives_bad_matcher(self):
        assert resolve(ScenarioCtx(component=None)) is None   # matchers raise -> skipped

    def test_catalogue(self):
        rows = catalogue()
        assert len(rows) == len(REGISTRY) == 3
        assert len({r["id"] for r in rows}) == 3
        assert all(r["category"] in CATEGORIES and r["enabled"] and isinstance(r["spec"], dict) for r in rows)
        assert {r["category"] for r in rows} == {"cve_repro", "default_cred", "unauth_access"}

    def test_spec_rejects_url_image(self):
        with pytest.raises(IsolationError):
            SandboxSpec(component="x", image="http://evil/x")
