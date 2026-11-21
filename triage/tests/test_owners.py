"""Owner resolution tests: match precedence + each match key. No DB, no network."""
from __future__ import annotations

from app.owners import owner_matches, resolve_owner


def _asset(**over):
    base = {
        "kind": "subdomain",
        "value": "api.prod.example.com",
        "metadata": {"env": "prod", "tags": ["payments", "pci"], "ip": "10.1.2.3"},
    }
    base.update(over)
    return base


def _rule(name, team, match=None, priority=100, enabled=True, contact=None, system=None, rid=None):
    r = {
        "id": rid or name,
        "name": name,
        "team": team,
        "match": match or {},
        "priority": priority,
        "enabled": enabled,
        "contact": contact,
    }
    if system is not None:
        r["system"] = system
    return r


# ----------------------------------------------------------------------------
# individual match keys
# ----------------------------------------------------------------------------

def test_empty_match_is_catch_all():
    assert owner_matches({}, _asset()) is True


def test_kinds_key():
    assert owner_matches({"kinds": ["subdomain", "endpoint"]}, _asset()) is True
    assert owner_matches({"kinds": ["ipv4"]}, _asset()) is False


def test_value_regex_key():
    assert owner_matches({"value_regex": r"^api\."}, _asset()) is True
    assert owner_matches({"value_regex": r"^www\."}, _asset()) is False
    # a broken regex never matches rather than raising.
    assert owner_matches({"value_regex": r"("}, _asset()) is False


def test_cidr_key_ipv4_by_value():
    ip_asset = _asset(kind="ipv4", value="203.0.113.7", metadata={})
    assert owner_matches({"cidr": "203.0.113.0/24"}, ip_asset) is True
    assert owner_matches({"cidr": "198.51.100.0/24"}, ip_asset) is False


def test_cidr_key_via_metadata_ip():
    # subdomain/port assets carry the resolved ip in metadata.
    assert owner_matches({"cidr": "10.1.0.0/16"}, _asset()) is True
    assert owner_matches({"cidr": "192.168.0.0/16"}, _asset()) is False
    # no ip available anywhere -> no match.
    assert owner_matches({"cidr": "10.0.0.0/8"}, _asset(metadata={})) is False


def test_metadata_env_key():
    assert owner_matches({"metadata_env": "prod"}, _asset()) is True
    assert owner_matches({"metadata_env": "staging"}, _asset()) is False


def test_tag_key():
    assert owner_matches({"tag": "payments"}, _asset()) is True
    assert owner_matches({"tag": "marketing"}, _asset()) is False
    assert owner_matches({"tag": "x"}, _asset(metadata={"tags": []})) is False


def test_and_of_present_keys():
    m = {"kinds": ["subdomain"], "metadata_env": "prod", "tag": "pci"}
    assert owner_matches(m, _asset()) is True
    # any single failing predicate breaks the AND.
    assert owner_matches(m, _asset(metadata={"env": "dev", "tags": ["pci"]})) is False
    assert owner_matches({**m, "kinds": ["ipv4"]}, _asset()) is False


def test_unknown_match_key_is_ignored():
    # a carried 'system' (or any other key) does not affect matching.
    assert owner_matches({"metadata_env": "prod", "system": "github"}, _asset()) is True


# ----------------------------------------------------------------------------
# precedence / first-match-wins
# ----------------------------------------------------------------------------

def test_priority_ascending_first_match_wins():
    rules = [
        _rule("catch-all", "platform", {}, priority=100),
        _rule("payments", "payments-team", {"tag": "payments"}, priority=10),
        _rule("prod", "prod-team", {"metadata_env": "prod"}, priority=50),
    ]
    owner = resolve_owner(_asset(), rules)
    assert owner is not None
    # lowest priority number (10) that matches wins.
    assert owner["team"] == "payments-team"


def test_lower_priority_rule_used_when_higher_does_not_match():
    rules = [
        _rule("payments", "payments-team", {"tag": "payments"}, priority=10),
        _rule("prod", "prod-team", {"metadata_env": "prod"}, priority=50),
    ]
    # an asset tagged differently skips rule-10 and lands on rule-50.
    asset = _asset(metadata={"env": "prod", "tags": ["infra"]})
    owner = resolve_owner(asset, rules)
    assert owner["team"] == "prod-team"


def test_disabled_rule_skipped():
    rules = [
        _rule("payments", "payments-team", {"tag": "payments"}, priority=10, enabled=False),
        _rule("catch-all", "platform", {}, priority=100),
    ]
    owner = resolve_owner(_asset(), rules)
    assert owner["team"] == "platform"


def test_no_match_returns_none():
    rules = [_rule("ipv4-only", "net", {"kinds": ["ipv4"]}, priority=10)]
    assert resolve_owner(_asset(), rules) is None


def test_system_carried_from_rule_and_from_match():
    # top-level system on the rule.
    r1 = _rule("gh", "sec", {"metadata_env": "prod"}, system="github")
    assert resolve_owner(_asset(), [r1])["system"] == "github"
    # system carried inside the match blob (no dedicated column).
    r2 = _rule("jira", "sec", {"metadata_env": "prod", "system": "jira"})
    assert resolve_owner(_asset(), [r2])["system"] == "jira"
    # no system -> None (ticket layer defaults to 'internal').
    r3 = _rule("plain", "sec", {"metadata_env": "prod"})
    assert resolve_owner(_asset(), [r3])["system"] is None
