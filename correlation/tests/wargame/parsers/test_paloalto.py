"""Tests for the PAN-OS set-format parser."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.wargame.model import Action, PortRange, Proto
from app.engine.wargame.parsers import available_vendors, parse
from app.engine.wargame.parsers.base import WarningLevel
from app.engine.wargame.parsers.paloalto import PaloAltoParser, tokenize
from app.engine.wargame.rules import evaluate

FIXTURE = Path(__file__).parent / "fixtures" / "paloalto_set.conf"


@pytest.fixture(scope="module")
def conf() -> str:
    return FIXTURE.read_text()


@pytest.fixture(scope="module")
def result(conf):
    return PaloAltoParser().parse(conf)


def _rule(result, rs_id, rule_id):
    return next(r for r in result.rulesets[rs_id].rules if r.id == rule_id)


def _mini(rule_lines: str, objects: str = ""):
    """Parse a one-off config; rules live in zone pair a>b."""
    return PaloAltoParser().parse(objects + rule_lines)


def _r(name, **f):
    base = {"from": "a", "to": "b", "source": "any", "destination": "any",
            "application": "any", "service": "any", "action": "allow"}
    base.update(f)
    return "".join(
        f"set rulebase security rules {name} {k} {v}\n" for k, v in base.items()
    )


# -- tokenizer ---------------------------------------------------------------

def test_tokenize_bracket_list_and_quotes():
    toks = tokenize('address-group g static [ a b  c ] description "two words"')
    assert toks == ["address-group", "g", "static", ["a", "b", "c"],
                    "description", "two words"]


def test_tokenize_tight_brackets_and_unclosed():
    assert tokenize("x [a b]") == ["x", ["a", "b"]]
    assert tokenize("x [ a b") == ["x", ["a", "b"]]


def test_tokenize_quoted_filter_with_inner_quotes():
    assert tokenize('filter "\'a\' and \'b\'"') == ["filter", "'a' and 'b'"]


def test_registered():
    assert "paloalto" in available_vendors()


# -- objects -----------------------------------------------------------------

def test_ip_netmask_range_and_bare_host_objects():
    res = _mini(
        _r("t", source="h", destination="n"),
        "set address h ip-netmask 10.0.0.1\n"
        "set address n ip-netmask 10.0.1.0/24\n",
    )
    r = res.rulesets["a>b"].rules[0]
    assert r.src_cidrs == ("10.0.0.1/32",)
    assert r.dst_cidrs == ("10.0.1.0/24",)
    res = _mini(_r("t", source="rg"), "set address rg ip-range 10.0.0.0-10.0.0.255\n")
    assert res.rulesets["a>b"].rules[0].src_cidrs == ("10.0.0.0/24",)


def test_fqdn_object_is_conditional():
    res = _mini(_r("t", destination="f"), "set address f fqdn x.example.test\n")
    r = res.rulesets["a>b"].rules[0]
    assert r.conditional is True
    assert any(w.level == WarningLevel.CONDITIONAL and "DNS" in w.message
               for w in res.warnings)


def test_static_group_resolves_and_is_not_conditional(result):
    r = _rule(result, "untrust>web", "inet-to-web-default")
    assert r.dst_cidrs == ("10.10.1.0/24",)
    r = _rule(result, "web>app", "deny-legacy-app")
    assert set(r.src_cidrs) == {"10.10.1.10/32", "10.10.1.11/32"}
    assert r.conditional is False


def test_dynamic_group_is_conditional(result):
    r = _rule(result, "app>db", "quarantine-block")
    assert r.conditional is True
    assert any("tag-driven" in w.message for w in result.warnings)


def test_service_comma_list_and_range(result):
    r = _rule(result, "web>app", "web-to-app")
    assert set(r.ports) == {PortRange(Proto.TCP, 8080, 8080),
                            PortRange(Proto.TCP, 8443, 8443)}
    r = _rule(result, "app>db", "app-to-db")  # via service-group
    assert PortRange(Proto.TCP, 5432, 5439) in r.ports
    assert PortRange(Proto.UDP, 53, 53) in r.ports


def test_service_any_means_any_port(result):
    r = _rule(result, "web>app", "deny-legacy-app")
    assert r.ports == (PortRange.any(),)


def test_external_list_reference_is_conditional():
    res = _mini(_r("t", source="edl1"), "set external-list edl1 type ip\n")
    assert res.rulesets["a>b"].rules[0].conditional is True
    assert any("fetched at runtime" in w.message for w in res.warnings)


# -- honesty rule ------------------------------------------------------------

def test_plain_rule_not_conditional(result):
    r = _rule(result, "web>app", "web-to-app")
    assert r.conditional is False
    assert r.action is Action.ALLOW
    assert not any(w.ref.endswith("web-to-app") and w.level in
                   (WarningLevel.CONDITIONAL, WarningLevel.UNRESOLVED)
                   for w in result.warnings)


def test_app_id_rule_conditional_with_warning(result):
    r = _rule(result, "untrust>web", "inet-to-web-apps")
    assert r.conditional is True
    assert any(w.level == WarningLevel.CONDITIONAL and "application" in w.message
               and w.ref.endswith("inet-to-web-apps") for w in result.warnings)


def test_application_default_is_conditional_and_any_port(result):
    r = _rule(result, "untrust>web", "inet-to-web-default")
    assert r.conditional is True
    assert r.ports == (PortRange.any(),)
    assert any("application" in w.message and w.ref.endswith("inet-to-web-default")
               for w in result.warnings)


def test_source_user_is_conditional_user_id(result):
    r = _rule(result, "mgmt>app", "admin-to-app")
    assert r.conditional is True
    assert any(w.level == WarningLevel.CONDITIONAL and "user" in w.message
               and w.ref.endswith("admin-to-app") for w in result.warnings)


def test_source_user_any_is_not_conditional():
    res = _mini(_r("t", **{"source-user": "any"}))
    assert res.rulesets["a>b"].rules[0].conditional is False


def test_app_and_user_both_reported():
    res = _mini(_r("t", application="ssl", **{"source-user": "bob"}))
    msgs = [w.message for w in res.warnings if w.level == WarningLevel.CONDITIONAL]
    assert any("application" in m for m in msgs)
    assert any("user" in m for m in msgs)


def test_unresolved_object_is_conditional_and_warned():
    res = _mini(_r("t", source="ghost"))
    assert res.rulesets["a>b"].rules[0].conditional is True
    assert any(w.level == WarningLevel.UNRESOLVED for w in res.warnings)


def test_negate_source_widens_and_flags():
    res = _mini(_r("t", source="10.0.0.0/8")
                + "set rulebase security rules t negate-source yes\n")
    r = res.rulesets["a>b"].rules[0]
    assert r.conditional is True
    assert "0.0.0.0/0" in r.src_cidrs


def test_disabled_rule_skipped():
    res = _mini(_r("t") + "set rulebase security rules t disabled yes\n")
    assert res.rulesets == {}


def test_deny_actions_map_to_deny():
    for act in ("deny", "drop", "reset-both"):
        res = _mini(_r("t", action=act))
        assert res.rulesets["a>b"].rules[0].action is Action.DENY


# -- ordering & evaluation ---------------------------------------------------

def test_deny_before_allow_in_same_zone_pair(result):
    rs = result.rulesets["web>app"]
    ids = [r.id for r in rs.rules]
    assert ids.index("deny-legacy-app") < ids.index("web-to-app")
    # inside the legacy range -> deny wins; elsewhere in app-net -> allow
    d = evaluate(rs, "10.10.1.10", "10.20.1.105", Proto.TCP, 8443)
    assert d.allowed is False and d.matched_rule == "deny-legacy-app"
    d = evaluate(rs, "10.10.1.10", "10.20.1.20", Proto.TCP, 8443)
    assert d.allowed is True and d.matched_rule == "web-to-app"
    assert d.conditional is False
    # wrong port falls to the cleanup deny (any>any lands in this set too)
    d = evaluate(rs, "10.10.1.10", "10.20.1.20", Proto.TCP, 22)
    assert d.allowed is False and d.matched_rule == "cleanup-deny"


def test_conditional_flag_surfaces_in_evaluate(result):
    rs = result.rulesets["mgmt>app"]
    d = evaluate(rs, "10.99.0.5", "10.20.1.20", Proto.TCP, 22)
    assert d.allowed is True and d.conditional is True


def test_order_is_appearance_order(result):
    rs = result.rulesets["web>app"]
    orders = [r.order for r in rs.rules]
    assert orders == sorted(orders) and len(set(orders)) == len(orders)


# -- zone pairs / bindings ---------------------------------------------------

def test_zone_pair_keys_and_bindings(result):
    assert set(result.rulesets) == {
        "web>app", "app>db", "untrust>web", "mgmt>app", "web>untrust",
        "web>db", "any>any",
    }
    for rs in result.rulesets.values():
        assert rs.vendor == "paloalto"
        assert rs.default_action is Action.DENY
    by_id = {b.ruleset_id: b for b in result.bindings}
    assert set(by_id) == set(result.rulesets)
    assert (by_id["web>app"].src_zone, by_id["web>app"].dst_zone) == ("web", "app")
    assert (by_id["any>any"].src_zone, by_id["any>any"].dst_zone) == ("any", "any")


def test_multi_zone_rule_emitted_into_each_pair(result):
    assert "quarantine-block" in [r.id for r in result.rulesets["web>db"].rules]
    assert "quarantine-block" in [r.id for r in result.rulesets["app>db"].rules]


def test_any_zone_rule_lands_in_concrete_pairs_last(result):
    for key, rs in result.rulesets.items():
        if key != "any>any":
            assert rs.rules[-1].id == "cleanup-deny"
    assert [r.id for r in result.rulesets["any>any"].rules] == ["cleanup-deny"]


def test_any_zone_deny_precedes_concrete_allow():
    res = _mini(
        _r("block", **{"from": "any", "to": "b", "action": "deny"})
        + _r("allow", action="allow")
    )
    rs = res.rulesets["a>b"]
    assert [r.id for r in rs.rules] == ["block", "allow"]
    assert evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 80).allowed is False


def test_noise_is_warned_not_fatal(result):
    msgs = [w.message for w in result.warnings if w.level == WarningLevel.UNSUPPORTED]
    assert any("deviceconfig" in m for m in msgs)


def test_garbage_never_raises():
    for raw in ("", "   \n# c\n", "set", "set rulebase", "garbage line",
                'set address x ip-netmask "unterminated', "set service s protocol tcp port x",
                None, b"set address a ip-netmask 1.1.1.1"):
        res = PaloAltoParser().parse(raw)  # type: ignore[arg-type]
        assert res.vendor == "paloalto"


def test_parse_via_registry(conf):
    assert parse("paloalto", conf).rulesets.keys() == PaloAltoParser().parse(conf).rulesets.keys()


# -- determinism -------------------------------------------------------------

def test_deterministic(conf):
    a = PaloAltoParser().parse(conf)
    b = PaloAltoParser().parse(conf)
    assert list(a.rulesets) == list(b.rulesets)
    assert a.rulesets == b.rulesets
    assert a.bindings == b.bindings
    assert [str(w) for w in a.warnings] == [str(w) for w in b.warnings]
