import pytest

from paddock_assurance import ParseError, parse_invariant
from paddock_assurance.parse import canonical_json, digest
from paddock_assurance.stdlib import list_std, load_std

from helpers import REACH_YAML

OK = REACH_YAML.format(extra="")


def test_valid_document_parses():
    inv = parse_invariant(OK)
    assert inv.id == "acme:a-cannot-reach-b"
    assert inv.assert_ == "unreachable"
    assert inv.via.max_hops == 8 and inv.coverage.require == 0.95


@pytest.mark.parametrize("patch,needle", [
    ("bogus: 1\n", "bogus"),                                  # unknown top-level key
    ("severity: urgent\n", "severity"),
    ("via: { max_hops: 99 }\n", "max_hops"),
    ("via: { protocols: [sctp] }\n", "protocols"),
    ("coverage: { require: 2 }\n", "require"),
    ("evidence: { max_age: forever }\n", "max_age"),
    ("evidence: { max_age: 90d }\n", "max_age"),
    ("evidence: { min_tier: perfect }\n", "min_tier"),
    ("on_violation: { propose: [rm_rf] }\n", "propose"),
    ("ports: 80\n", "ports"),                                  # ports belong to exposes-only
])
def test_invalid_rejected_with_path(patch, needle):
    with pytest.raises(ParseError) as e:
        parse_invariant(OK + patch)
    assert needle in str(e.value)


@pytest.mark.parametrize("text", ["", "- a\n- b\n", "just a string", "{unclosed"])
def test_non_mapping_or_broken_yaml(text):
    with pytest.raises(ParseError):
        parse_invariant(text)


def test_bad_id_rejected():
    with pytest.raises(ParseError):
        parse_invariant(OK.replace("acme:a-cannot-reach-b", "Not An Id"))


def test_empty_selector_rejected():
    with pytest.raises(ParseError, match="empty selector"):
        parse_invariant(OK.replace("{ zone: a }", "{}"))


def test_unreachable_needs_both_ends():
    with pytest.raises(ParseError, match="needs both"):
        parse_invariant(OK.replace("  from: { zone: a }\n", ""))


def test_exposes_only_needs_ports():
    txt = """apiVersion: paddock.dev/invariant/v1
id: acme:x
title: x ports
subjects: { from: { zone: internet } }
assert: exposes-only
"""
    with pytest.raises(ParseError, match="needs 'ports'"):
        parse_invariant(txt)


def test_yaml_aliases_rejected():
    bomb = "a: &a [x, x]\nb: *a\n"
    with pytest.raises(ParseError, match="alias"):
        parse_invariant(bomb)


def test_oversize_and_depth_rejected():
    with pytest.raises(ParseError, match="larger"):
        parse_invariant("x: " + "a" * 70_000)
    deep = "a: " + "[" * 30 + "]" * 30
    with pytest.raises(ParseError, match="nested"):
        parse_invariant(deep)


def test_attack_text_rejected():
    with pytest.raises(ParseError, match="attack step"):
        parse_invariant(OK.replace("A cannot reach B", "Deliver payload to B"))


def test_allow_requires_reason_and_expiry():
    base = OK + "allow:\n  - to: { id: b1 }\n    reason: ok\n"
    with pytest.raises(ParseError, match="expires"):
        parse_invariant(base)
    with pytest.raises(ParseError, match="reason"):
        parse_invariant(OK + "allow:\n  - to: { id: b1 }\n    reason: ''\n    expires: 2027-01-01\n")


def test_digest_stable_under_reordering_and_defaults():
    a = parse_invariant(OK + "via: { protocols: [udp, tcp] }\n")
    b = parse_invariant(OK.replace("severity: high\n", "") + "severity: high\n"
                        "via: { protocols: [tcp, udp, tcp], max_hops: 8 }\ncoverage: { require: 0.95 }\n")
    assert canonical_json(a) == canonical_json(b)
    assert digest(a) == digest(b) and digest(a).startswith("sha256:")


def test_digest_changes_with_meaning():
    a = parse_invariant(OK)
    assert digest(a) != digest(parse_invariant(OK + "via: { max_hops: 3 }\n"))
    assert digest(a) != digest(parse_invariant(OK.replace("zone: b", "zone: c")))
    assert digest(a) != digest(parse_invariant(OK + "coverage: { require: 0.5 }\n"))


def test_stop_at_is_part_of_the_digest():
    a = parse_invariant(OK)
    b = parse_invariant(OK + "via: { stop_at: { tag: app-tier } }\n")
    assert digest(a) != digest(b)


def test_std_library_compiles_and_ids_match():
    ids = list_std()
    # P2 ships two host-config invariants next to the four P1 ones
    assert ids == ["std:coverage-complete", "std:guest-cannot-reach-pos",
                   "std:no-internet-to-datastore", "std:public-ports-allowlist",
                   "std:server-default-deny-inbound", "std:server-ssh-hardened"]
    for sid in ids:
        assert load_std(sid).id == sid


def test_std_lookup_rejects_traversal():
    from paddock_assurance.stdlib import std_text
    for bad in ("std:../x", "std:", "nope", "std:does-not-exist"):
        with pytest.raises(KeyError):
            std_text(bad)
