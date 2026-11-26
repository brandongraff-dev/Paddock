"""P2.1 seam (WP0): every RBAC rule of the new routes is present, explicit and pinned.

docs/ASSURANCE_P2_1.md 4.3 and 7.1. The routes are implemented by later packages; their rules are added here first (a
rule for a route that does not exist yet is harmless) and these tests call ``required_capability`` directly, so a
package that adds a handler can never ship it under a weaker default (a GET with no rule would be ``read``).
"""
from __future__ import annotations

import uuid

import pytest

from app import auth as auth_svc

A = str(uuid.UUID(int=0xA11CE))
B = str(uuid.UUID(int=0xB0B))
ACK = str(uuid.UUID(int=0xACC))

#: (method, path, capability): the whole of contract 7.1 plus the 4.3 table, with real ids
CONTRACT = [
    # 1.11 / 7.1: KEV
    ("GET", f"/v1/fleet/agents/{A}/kev", "triage"),
    ("GET", "/v1/assurance/advisories", "read"),
    # 4.3: pairing
    ("PUT", f"/v1/fleet/agents/{A}/pairing", "admin"),
    ("DELETE", f"/v1/fleet/agents/{A}/pairing", "admin"),
    ("GET", f"/v1/fleet/agents/{A}/pairing", "triage"),
    ("GET", f"/v1/fleet/agents/{A}/pairing/candidates", "triage"),
    ("GET", "/v1/fleet/pairings", "triage"),
    # 4.3 / 4.6: conflicts and their acknowledgements
    ("GET", f"/v1/fleet/agents/{A}/conflicts", "triage"),
    ("POST", f"/v1/fleet/agents/{A}/conflicts/acks", "admin"),
    ("DELETE", f"/v1/fleet/agents/{A}/conflicts/acks/{ACK}", "admin"),
    # 6.1: releasing the findings of an invariant that is not active
    ("POST", "/v1/invariants/acme:my-rule/findings/release", "admin"),
    ("POST", "/v1/invariants/std:no-internet-to-datastore/findings/release", "admin"),
]


@pytest.mark.parametrize("method,path,cap", CONTRACT)
def test_contract_route_capability(method, path, cap):
    assert auth_svc.required_capability(method, path) == cap


@pytest.mark.parametrize("method,path,cap", CONTRACT)
def test_trailing_slash_does_not_change_the_capability(method, path, cap):
    assert auth_svc.required_capability(method, path + "/") == cap


@pytest.mark.parametrize("method,path,cap", [c for c in CONTRACT if c[0] == "GET" and c[2] == "triage"])
def test_triage_routes_are_not_readable_by_a_viewer(method, path, cap):
    """The routes name CVEs per host, asset addresses and operator justifications: not viewer-safe."""
    need = auth_svc.required_capability(method, path)
    assert need == "triage"
    assert not auth_svc.capabilities_for("viewer") >= {need}
    assert not auth_svc.capabilities_for("auditor") >= {need}
    assert auth_svc.capabilities_for("analyst") >= {need}
    assert auth_svc.capabilities_for("admin") >= {need}


@pytest.mark.parametrize("method,path,cap", [c for c in CONTRACT if c[2] == "admin"])
def test_admin_routes_are_admin_only(method, path, cap):
    """Pair as an analyst, acknowledge as an analyst, release as a service key: all refused (attack 19, 22, 24)."""
    need = auth_svc.required_capability(method, path)
    assert need == "admin"
    for role in ("viewer", "analyst", "auditor", "service"):
        assert not auth_svc.capabilities_for(role) >= {need}, role
    assert auth_svc.capabilities_for("admin") >= {need}
    # an admin's API key narrowed to triage cannot do it either
    assert not auth_svc.capabilities_for("admin", frozenset({"triage", "read"})) >= {need}


@pytest.mark.parametrize("method,tpl,cap", [
    ("GET", "/v1/fleet/agents/{}/kev", "triage"),
    ("GET", "/v1/fleet/agents/{}/pairing", "triage"),
    ("GET", "/v1/fleet/agents/{}/pairing/candidates", "triage"),
    ("GET", "/v1/fleet/agents/{}/conflicts", "triage"),
    ("PUT", "/v1/fleet/agents/{}/pairing", "admin"),
    ("DELETE", "/v1/fleet/agents/{}/pairing", "admin"),
    ("POST", "/v1/fleet/agents/{}/conflicts/acks", "admin"),
])
@pytest.mark.parametrize("agent_id", ["not-a-uuid", "x", "1", A.upper(), "%00", "a b"])
def test_a_malformed_agent_id_never_falls_to_a_weaker_default(method, tpl, cap, agent_id):
    """``_ANY`` on purpose, like the posture rule: a malformed id must not drop a GET to ``read``."""
    assert auth_svc.required_capability(method, tpl.format(agent_id)) == cap


@pytest.mark.parametrize("method,path,cap", [
    # sub-paths nobody implements: still triage/admin, never the GET default `read`
    ("GET", f"/v1/fleet/agents/{A}/pairing/anything", "triage"),
    ("GET", f"/v1/fleet/agents/{A}/pairing/candidates/x", "triage"),
    ("GET", f"/v1/fleet/agents/{A}/conflicts/acks", "triage"),
    ("GET", f"/v1/fleet/agents/{A}/conflicts/acks/{ACK}", "triage"),
    ("GET", f"/v1/fleet/pairings/{A}", "triage"),
    ("POST", f"/v1/fleet/agents/{A}/pairing", "admin"),
    ("PATCH", f"/v1/fleet/agents/{A}/pairing", "admin"),
    ("PUT", f"/v1/fleet/agents/{A}/conflicts/acks", "admin"),
    ("DELETE", f"/v1/fleet/agents/{A}/conflicts", "admin"),
    ("DELETE", f"/v1/fleet/agents/{A}/conflicts/acks", "admin"),
    ("PUT", f"/v1/fleet/agents/{A}/kev", "admin"),
    ("POST", "/v1/fleet/pairings", "admin"),
    ("PUT", "/v1/invariants/x/findings/release", "admin"),
    ("DELETE", "/v1/invariants/x/findings/release", "admin"),
    ("PUT", "/v1/assurance/advisories", "admin"),
    ("POST", "/v1/assurance/advisories", "admin"),
])
def test_neighbouring_shapes_stay_deny_closed(method, path, cap):
    assert auth_svc.required_capability(method, path) == cap


@pytest.mark.parametrize("method,path,cap", [
    # P2.1 must not move any rule that existed before
    ("GET", "/v1/fleet/agents", "read"),
    ("GET", f"/v1/fleet/agents/{A}", "read"),
    ("GET", f"/v1/fleet/agents/{A}/posture", "triage"),
    ("POST", f"/v1/fleet/agents/{A}/revoke", "admin"),
    ("POST", f"/v1/fleet/{A}/posture", "agent"),
    ("POST", f"/v1/fleet/{A}/heartbeat", "agent"),
    ("GET", "/v1/fleet/enroll-tokens", "admin"),
    ("POST", "/v1/fleet/enroll", None),
    ("GET", "/v1/invariants", "read"),
    ("GET", "/v1/invariants/acme:my-rule", "read"),
    ("GET", "/v1/invariants/acme:my-rule/runs", "read"),
    ("PUT", "/v1/invariants/acme:my-rule", "admin"),
    ("DELETE", "/v1/invariants/acme:my-rule", "admin"),
    ("GET", "/v1/assurance/coverage", "read"),
    ("GET", "/v1/assurance/sensor-scopes", "read"),
    ("PUT", f"/v1/assurance/sensor-scopes/{A}", "admin"),
    ("GET", "/v1/sensors", "read"),
    ("GET", "/v1/sensors/tokens", "admin"),
])
def test_existing_rules_are_unchanged(method, path, cap):
    assert auth_svc.required_capability(method, path) == cap


def test_no_new_rule_is_public_and_none_shadows_the_agent_routes():
    """Every rule P2.1 added is authenticated, and the agent-principal rules keep their anchored UUID patterns."""
    for method, path, cap in CONTRACT:
        assert cap is not None
        assert auth_svc.required_capability(method, path) is not None
    agent_caps = {m + " " + p: auth_svc.required_capability(m, p) for m, p in [
        ("POST", f"/v1/fleet/{A}/heartbeat"), ("POST", f"/v1/fleet/{A}/posture"),
        ("POST", f"/v1/fleet/{A}/inventory"), ("POST", f"/v1/fleet/{A}/keys/rotate"),
        ("POST", f"/v1/fleet/actions/{A}/result"),
    ]}
    assert set(agent_caps.values()) == {"agent"}


def test_an_agent_principal_holds_no_capability_of_the_new_routes():
    """The capability ``agent`` is held by no role and no key scope, so an agent credential reaches none of them."""
    agent_only = frozenset({"agent"})
    for method, path, _ in CONTRACT:
        need = auth_svc.required_capability(method, path)
        assert need not in agent_only
        assert not any(need in caps for role, caps in auth_svc.ROLE_CAPABILITIES.items() if "agent" in caps)


def test_every_new_rule_is_explicit_not_a_default():
    """Each contract route matches a RULE, not the fall-through default (a GET with no rule would be ``read`` and a
    later edit of the defaults would silently move it)."""
    def matched(method: str, path: str) -> bool:
        path = path.rstrip("/") or "/"
        return any(method in methods and pat.match(path) for methods, pat, _cap in auth_svc._RULES)

    missing = [(m, p) for m, p, _ in CONTRACT if not matched(m, p)]
    assert missing == []


def test_rule_patterns_are_anchored():
    for _methods, pat, _cap in auth_svc._RULES:
        assert pat.pattern.startswith("^") and pat.pattern.endswith("$")


# --------------------------------------------------------------------------- #
# settings (docs/ASSURANCE_P2_1.md 7.2; the seam package owns config.py alone)
# --------------------------------------------------------------------------- #

P21_SETTINGS = {
    "assurance_kev_enabled": True,
    "assurance_advisory_max_age_h": 48,
    "fleet_manifest_tenant_max_mb": 512,
    "assurance_pairing_asset_max_age_h": 72,
    "assurance_conflict_ack_max_h": 720,
    "assurance_runs_compact_days": 30,
}


def test_p21_settings_exist_with_the_contract_defaults(monkeypatch):
    from app.config import Settings

    for name in P21_SETTINGS:
        monkeypatch.delenv(name.upper(), raising=False)
    s = Settings(_env_file=None)
    assert {k: getattr(s, k) for k in P21_SETTINGS} == P21_SETTINGS


def test_p21_settings_are_overridable_from_the_environment(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("ASSURANCE_KEV_ENABLED", "false")
    monkeypatch.setenv("ASSURANCE_ADVISORY_MAX_AGE_H", "24")
    monkeypatch.setenv("FLEET_MANIFEST_TENANT_MAX_MB", "64")
    monkeypatch.setenv("ASSURANCE_PAIRING_ASSET_MAX_AGE_H", "12")
    monkeypatch.setenv("ASSURANCE_CONFLICT_ACK_MAX_H", "48")
    monkeypatch.setenv("ASSURANCE_RUNS_COMPACT_DAYS", "7")
    s = Settings(_env_file=None)
    assert (s.assurance_kev_enabled, s.assurance_advisory_max_age_h, s.fleet_manifest_tenant_max_mb,
            s.assurance_pairing_asset_max_age_h, s.assurance_conflict_ack_max_h, s.assurance_runs_compact_days
            ) == (False, 24, 64, 12, 48, 7)


@pytest.mark.parametrize("name,bad", [
    ("ASSURANCE_CONFLICT_ACK_MAX_H", "721"),         # D30: an acknowledgement may never outlive 720 h
    ("ASSURANCE_CONFLICT_ACK_MAX_H", "0"),
    ("ASSURANCE_ADVISORY_MAX_AGE_H", "0"),
    ("ASSURANCE_ADVISORY_MAX_AGE_H", "-1"),
    ("ASSURANCE_PAIRING_ASSET_MAX_AGE_H", "0"),
    ("FLEET_MANIFEST_TENANT_MAX_MB", "0"),
    ("ASSURANCE_RUNS_COMPACT_DAYS", "0"),
    ("ASSURANCE_RUNS_COMPACT_DAYS", "-5"),
])
def test_a_nonsensical_p21_setting_is_refused_at_startup_not_silently_widened(monkeypatch, name, bad):
    """Fail safe: the process does not start with a value that would widen trust (an ack past its maximum) or turn
    a bound into 'no bound' (0 MB cap, 0-day compaction that would wipe witnesses at once)."""
    from pydantic import ValidationError

    from app.config import Settings

    monkeypatch.setenv(name, bad)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
