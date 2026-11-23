"""Tests for replica precondition verification (no exploit is ever run)."""
from __future__ import annotations

import pytest

from app.engine.wargame.model import (
    EvidenceLabel,
    Precondition,
    PreconditionKind as K,
    ReplicaPlan,
)
from app.engine.wargame.replica import (
    check_precondition,
    compare_versions,
    parse_version,
    verify_fix,
    verify_preconditions,
    version_in_range,
)
from app.engine.wargame.safety import UnsafeWargameAction, assert_precondition_allowed


def P(kind, **spec):
    return Precondition(kind=kind, description="a safe precondition", spec=spec)


FACTS = {
    "versions": {"openssl": "3.0.2"},
    "flags": {"debug": True, "off": False, "str": "true"},
    "listening": ["tcp/5432", "UDP/53"],
    "reachable_symbols": ["pkg.mod.func"],
    "files": ["/etc/app/legacy.conf"],
    "config": {"tls.min": "1.0"},
}
PLAN = ReplicaPlan(component_id="c1", scope_asset_id="asset-1")


@pytest.mark.parametrize("pre,expected", [
    (P(K.VERSION_IN_RANGE, component="openssl", range="<3.0.7"), True),
    (P(K.VERSION_IN_RANGE, component="openssl", range=">=3.0.7"), False),
    (P(K.VERSION_IN_RANGE, component="nginx", range="<3.0.7"), False),
    (P(K.FLAG_ENABLED, flag="debug"), True),
    (P(K.FLAG_ENABLED, flag="off"), False),
    (P(K.FLAG_ENABLED, flag="str"), False),
    (P(K.FLAG_ENABLED, flag="missing"), False),
    (P(K.ENDPOINT_EXPOSED, port=5432, proto="tcp"), True),
    (P(K.ENDPOINT_EXPOSED, port=53, proto="udp"), True),
    (P(K.ENDPOINT_EXPOSED, port=5432, proto="udp"), False),
    (P(K.ENDPOINT_EXPOSED, port=22, proto="tcp"), False),
    (P(K.CODE_REACHABLE, symbol="pkg.mod.func"), True),
    (P(K.CODE_REACHABLE, symbol="other"), False),
    (P(K.FILE_PRESENT, path="/etc/app/legacy.conf"), True),
    (P(K.FILE_PRESENT, path="/nope"), False),
    (P(K.CONFIG_VALUE, key="tls.min", equals="1.0"), True),
    (P(K.CONFIG_VALUE, key="tls.min", equals="1.2"), False),
    (P(K.CONFIG_VALUE, key="absent", equals="x"), False),
])
def test_each_kind_true_and_false(pre, expected):
    assert check_precondition(pre, FACTS) is expected


def test_garbled_data_never_raises():
    bad = {"versions": 5, "flags": [], "listening": 3, "files": None, "config": "x"}
    for pre in [
        P(K.VERSION_IN_RANGE), P(K.VERSION_IN_RANGE, component=3, range=[]),
        P(K.FLAG_ENABLED), P(K.ENDPOINT_EXPOSED, port="x", proto=1),
        P(K.CODE_REACHABLE), P(K.FILE_PRESENT, path=[]), P(K.CONFIG_VALUE, key="k"),
    ]:
        assert check_precondition(pre, bad) is False
        assert check_precondition(pre, {}) is False
    assert check_precondition(P(K.FLAG_ENABLED, flag="x"), None) is False  # type: ignore[arg-type]


@pytest.mark.parametrize("version,rng,expected", [
    ("3.0.7", "==3.0.7", True),
    ("3.0.7", "<3.0.7", False),
    ("3.0.7", "<=3.0.7", True),
    ("3.0", "==3.0.0", True),            # zero padding
    ("3", ">=3.0.0", True),
    ("3.0.7.1", ">3.0.7", True),         # different lengths
    ("1.0.2k", "<1.0.3", True),          # alpha suffix ignored
    ("3.0.7-rc1", "==3.0.7", True),      # pre-release suffix ignored
    ("3.0.7", "3.0.7", True),            # bare version means ==
    ("1.2.3", ">=1.0,<2.0", True),
    ("2.0.0", ">=1.0,<2.0", False),
    ("10.0", ">9.9", True),              # numeric, not lexical
    ("abc", "<1.0", False),
    ("1.0", "<abc", False),
    ("1.0", "", False),
    (None, "<1.0", False),
])
def test_version_comparator(version, rng, expected):
    assert version_in_range(version, rng) is expected


def test_parse_and_compare_helpers():
    assert parse_version("v1.2.3") == (1, 2, 3)
    assert parse_version("x") is None
    assert compare_versions((1, 0), (1, 0, 0)) == 0
    assert compare_versions((1, 1), (1, 0, 9)) == 1


def test_off_allowlist_kind_raises():
    pre = P(K.FLAG_ENABLED, flag="x")
    pre.kind = "run_payload"  # type: ignore[assignment]
    with pytest.raises(UnsafeWargameAction):
        assert_precondition_allowed(pre)
    with pytest.raises(UnsafeWargameAction):
        verify_preconditions(PLAN, [pre], FACTS)
    with pytest.raises(UnsafeWargameAction):
        verify_fix(PLAN, [pre], FACTS, FACTS, {})


def test_unsafe_description_raises():
    pre = Precondition(K.FLAG_ENABLED, "send the payload and open a reverse shell", {"flag": "debug"})
    with pytest.raises(UnsafeWargameAction):
        verify_preconditions(PLAN, [pre], FACTS)


def test_verify_all_met():
    pres = [P(K.FLAG_ENABLED, flag="debug"), P(K.FILE_PRESENT, path="/etc/app/legacy.conf")]
    v = verify_preconditions(PLAN, pres, FACTS)
    assert v.preconditions_met is True
    assert v.details == {"flag_enabled": True, "file_present": True}
    assert v.label is EvidenceLabel.PROVED_REPLICA
    assert v.component_id == "c1"


def test_verify_one_missing_and_duplicate_kinds():
    pres = [P(K.FLAG_ENABLED, flag="debug"), P(K.FLAG_ENABLED, flag="off")]
    v = verify_preconditions(PLAN, pres, FACTS)
    assert v.preconditions_met is False
    assert v.details == {"flag_enabled": True, "flag_enabled#2": False}


def test_verify_empty_preconditions_not_met():
    assert verify_preconditions(PLAN, [], FACTS).preconditions_met is False


def test_not_rebuildable():
    plan = ReplicaPlan(component_id="c1", scope_asset_id="a", rebuildable=False)
    v = verify_preconditions(plan, [P(K.FLAG_ENABLED, flag="debug")], FACTS)
    assert v.preconditions_met is False
    assert v.details == {}
    assert v.note == "component not rebuildable; hop stays inferred"


@pytest.mark.parametrize("scope", ["", "   "])
def test_missing_scope_raises(scope):
    plan = ReplicaPlan(component_id="c1", scope_asset_id=scope)
    pres = [P(K.FLAG_ENABLED, flag="debug")]
    with pytest.raises(ValueError):
        verify_preconditions(plan, pres, FACTS)
    with pytest.raises(ValueError):
        verify_fix(plan, pres, FACTS, FACTS, {"h": True})


PRES = [
    P(K.VERSION_IN_RANGE, component="openssl", range="<3.0.7"),
    P(K.ENDPOINT_EXPOSED, port=5432, proto="tcp"),
]
AFTER_PATCHED = {**FACTS, "versions": {"openssl": "3.0.8"}}


def test_fix_closes_hop_and_health_ok():
    v = verify_fix(PLAN, PRES, FACTS, AFTER_PATCHED, {"smoke": True, "db": True})
    assert v.fix_closes_hop is True
    assert v.fix_breaks_service is False
    assert v.preconditions_met is False
    assert v.details == {"version_in_range": False, "endpoint_exposed": True}


def test_fix_breaks_health_check():
    v = verify_fix(PLAN, PRES, FACTS, AFTER_PATCHED, {"smoke": True, "db": False})
    assert v.fix_closes_hop is True
    assert v.fix_breaks_service is True
    assert "db" in v.note


def test_no_health_checks_is_unknown():
    v = verify_fix(PLAN, PRES, FACTS, AFTER_PATCHED, {})
    assert v.fix_breaks_service is None
    assert "no health checks" in v.note


def test_fix_that_changes_nothing_does_not_close():
    v = verify_fix(PLAN, PRES, FACTS, FACTS, {"h": True})
    assert v.fix_closes_hop is False
    assert v.preconditions_met is True


def test_hop_not_viable_before_is_not_closed():
    v = verify_fix(PLAN, PRES, AFTER_PATCHED, AFTER_PATCHED, {"h": True})
    assert v.fix_closes_hop is False
    assert "not viable before" in v.note


def test_verify_fix_not_rebuildable():
    plan = ReplicaPlan(component_id="c", scope_asset_id="a", rebuildable=False)
    v = verify_fix(plan, PRES, FACTS, AFTER_PATCHED, {"h": True})
    assert v.fix_closes_hop is None and v.fix_breaks_service is None
    assert v.preconditions_met is False
