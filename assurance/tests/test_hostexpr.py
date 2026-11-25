"""The predicate language: grammar, type-checking, caps, canonical form and the digest."""
from __future__ import annotations

import ast
import json
import time
from pathlib import Path

import pytest

from paddock_assurance import CompileError, ParseError, compile_text, parse_invariant
from paddock_assurance import hostexpr as X
from paddock_assurance import hostfields as HF
from tests.hostfix import HOST_YAML, host_plan, host_plan_doc

PKG = Path(__file__).resolve().parent.parent / "paddock_assurance"


def leaf(text: str) -> X.Leaf:
    return X.parse_predicate(text)


# --------------------------------------------------------------------------------------------
# grammar

@pytest.mark.parametrize("text,field,params,op,value,count", [
    ('host.sshd.maxauthtries <= 4', "host.sshd.maxauthtries", (), "<=", 4, False),
    ('host.sshd.maxauthtries == 0', "host.sshd.maxauthtries", (), "==", 0, False),
    ('host.sshd.maxauthtries >= -1', "host.sshd.maxauthtries", (), ">=", -1, False),
    ('host.sshd.maxauthtries in [3, 4, 3]', "host.sshd.maxauthtries", (), "in", (3, 4), False),
    ('host.sshd.installed == false', "host.sshd.installed", (), "==", False, False),
    ('host.sshd.installed != true', "host.sshd.installed", (), "!=", True, False),
    ('host.sshd.pubkeyauthentication == "YES"', "host.sshd.pubkeyauthentication", (), "==", "yes", False),
    ("host.sshd.pubkeyauthentication == 'yes'", "host.sshd.pubkeyauthentication", (), "==", "yes", False),
    ('host.sshd.permitrootlogin in ["no", "Prohibit-Password"]', "host.sshd.permitrootlogin", (), "in",
     ("no", "prohibit-password"), False),
    ('host.sshd.permitrootlogin == "without-password"', "host.sshd.permitrootlogin", (), "==",
     "prohibit-password", False),
    ('host.listener(22).exists == true', "host.listener.exists", (22,), "==", True, False),
    ('host.listener( 443 ).wildcard==false', "host.listener.wildcard", (443,), "==", False, False),
    ('host.listener(22).process subset_of ["sshd"]', "host.listener.process", (22,), "subset_of",
     ("sshd",), False),
    ('host.listener(22).process == []', "host.listener.process", (22,), "==", (), False),
    ('count(host.listener(22).process) == 0', "host.listener.process", (22,), "==", 0, True),
    ('count(host.listeners.addresses) <= 3', "host.listeners.addresses", (), "<=", 3, True),
    ('host.listeners.addresses subset_of ["10.0.0.0/8", "127.0.0.1"]', "host.listeners.addresses", (),
     "subset_of", ("10.0.0.0/8", "127.0.0.1/32"), False),
    ('host.sshd.allowusers subset_of ["deploy", "ops"]', "host.sshd.allowusers", (), "subset_of",
     ("deploy", "ops"), False),
])
def test_every_grammar_form(text, field, params, op, value, count):
    lf = leaf(text)
    assert (lf.field, lf.params, lf.op, lf.value, lf.count) == (field, params, op, value, count)


@pytest.mark.parametrize("text,needle", [
    ("", "expected a field name"),
    ("host.sshd.maxauthtries", "expected an operator"),
    ("host.sshd.maxauthtries <=", "expected a value"),
    ("host.sshd.maxauthtries <= 4 5", "end of the predicate"),
    ("host.sshd.maxauthtries = 4", "not an operator"),
    ("host.sshd.maxauthtries <= 4.5", "floats"),
    ("host.sshd.maxauthtries <= 4x", "unexpected"),
    ("host.sshd.nope == 1", "unknown field"),
    ("host.sshd == 1", "unknown field"),
    ("HOST.sshd.maxauthtries == 1", "unexpected character"),
    ("host.sshd.maxauthtries == 'x", "unterminated"),
    ("host.sshd.maxauthtries == \"a\\n\"", "valid escapes"),
    ("host.sshd.pubkeyauthentication == \"yés\"", "printable ASCII"),
    ("host.sshd.maxauthtries <= \"4\"", "whole number"),
    ("host.sshd.maxauthtries == true", "whole number"),
    ("host.sshd.maxauthtries in 4", "'in' needs a non-empty list"),
    ("host.sshd.maxauthtries in []", "non-empty list"),
    ("host.sshd.maxauthtries <= 99999999999", "too long"),
    ("host.sshd.maxauthtries <= 2000000000", "out of range"),
    ("host.sshd.installed < true", "not allowed"),
    ("host.sshd.installed == 1", "bool"),
    ("host.sshd.installed in [true]", "lists hold"),
    ("host.sshd.pubkeyauthentication == 1", "non-empty string"),
    ("host.sshd.pubkeyauthentication == \"maybe\"", "not a value of"),
    ("host.sshd.pubkeyauthentication < \"yes\"", "not allowed"),
    ("host.sshd.pubkeyauthentication == [\"yes\"]", "use 'in'"),
    ("host.sshd.allowusers == \"root\"", "needs a list"),
    ("host.sshd.allowusers < [\"root\"]", "not allowed"),
    ("host.sshd.allowusers in [\"root\"]", "not allowed"),
    ("host.listeners.addresses subset_of [\"10.0.0.1/8\"]", "host bits"),
    ("host.listeners.addresses subset_of [\"nonsense\"]", "not a valid CIDR"),
    ("host.listeners.addresses subset_of [1]", "CIDR"),
    ("host.listener.exists == true", "needs a parameter"),
    ("host.listener(22,80).exists == true", "exactly one"),
    ("host.listener(0).exists == true", "between 1 and 65535"),
    ("host.listener(65536).exists == true", "between 1 and 65535"),
    ("host.listener(-1).exists == true", "between 1 and 65535"),
    ("host.listener(22)(80).exists == true", "at most one"),
    ("host.sshd(22).installed == true", "takes no parameter"),
    ("host.sshd.installed(22) == true", "takes no parameter"),
    ("host.listener(\"22\").exists == true", "expected a number"),
    ("count(host.sshd.maxauthtries) == 1", "needs a set field"),
    ("count(host.listener(22).process) == \"1\"", "whole number"),
    ("count(host.listener(22).process) in 3", "comparison operator"),
    ("count(host.listener(22).process) == -1", ">= 0"),
    ("count host.listener(22).process == 1", "operator"),
    ("host.sshd.installed == true == true", "end of the predicate"),
    ("host.sshd.maxauthtries <= [1]", "whole number"),
    ("host.sshd.installed == [true]", "lists hold"),
    ("host.sshd.maxauthtries in [1, [2]]", "lists hold"),
    ("host.sshd.maxauthtries in [1,]", "lists hold"),
    ("host.sshd.maxauthtries in [1 2]", "',' or ']'"),
    ("__import__('os')", "expected a number|unexpected character|unknown field"),
    ("host.sshd.installed == true; rm", "unexpected character"),
])
def test_every_error_path(text, needle):
    with pytest.raises(X.ExprError) as e:
        X.parse_predicate(text)
    import re as _re
    assert _re.search(needle, str(e.value)), str(e.value)


def test_unknown_field_suggests_neighbours():
    with pytest.raises(X.ExprError, match="did you mean"):
        X.parse_predicate("host.sshd.passwordauth == 1")


# --------------------------------------------------------------------------------------------
# caps (the DoS surface)

def test_predicate_length_cap():
    long = "host.sshd.maxauthtries in [" + ", ".join(["1"] * 80) + "]"
    assert len(long) > X.MAX_PRED_CHARS
    with pytest.raises(X.ExprError, match="longer than 200"):
        X.parse_predicate(long)
    ok = "host.sshd.maxauthtries in [" + ", ".join(str(i) for i in range(1, 40)) + "]"
    assert len(ok) <= 200 and X.parse_predicate(ok)


def test_token_cap():
    text = "host.sshd.maxauthtries in [" + ",".join(["1"] * 60) + "]"
    assert len(text) <= X.MAX_PRED_CHARS
    with pytest.raises(X.ExprError, match="more than 120 tokens"):
        X.tokenize(text)
    with pytest.raises(X.ExprError, match="more than 120 tokens"):
        X.tokenize("(" * (X.MAX_TOKENS + 5))
    assert len(X.tokenize("(" * (X.MAX_TOKENS - 1))) == X.MAX_TOKENS


def test_list_cap():
    with pytest.raises(X.ExprError):      # 64 items would exceed 200 chars; the cap also stands alone
        p = X._P("[" + ",".join(["1"] * 70) + "]")
        p.literal()


def test_depth_cap_is_six_combinator_levels():
    def nest(levels: int):
        node: object = "host.sshd.installed == false"
        for i in range(levels):
            node = {"all": [node, "host.sshd.maxauthtries <= 4"]} if i % 2 else {"any": [node, "host.sshd.maxauthtries <= 3"]}
        return node
    assert X.depth(X.parse_assertion(nest(6))) == 6
    with pytest.raises(X.ExprError, match="deeper than 6"):
        X.parse_assertion(nest(7))
    # not counts as a level
    n: object = "host.sshd.installed == false"
    for _ in range(7):
        n = {"not": n}
    with pytest.raises(X.ExprError, match="deeper than 6"):
        X.parse_assertion(n)


def test_leaf_cap_is_64():
    ok = {"all": [f"host.sshd.maxauthtries <= {i}" for i in range(64)]}
    assert len(X.leaves(X.parse_assertion(ok))) == 64
    with pytest.raises(X.ExprError, match="more than 64"):
        X.parse_assertion({"all": [f"host.sshd.maxauthtries <= {i}" for i in range(65)]})
    with pytest.raises(X.ExprError, match="more than 64"):      # across nested groups
        X.parse_assertion({"all": [{"any": [f"host.sshd.maxauthtries <= {i}" for i in range(40)]},
                                   {"any": [f"host.sshd.maxauthtries <= {i}" for i in range(40, 80)]}]})


def test_pathological_inputs_are_linear():
    start = time.perf_counter()
    for text in ["(" * 200, "[" * 200, "host." * 40, "a" * 200, '"' * 200, "0" * 200,
                 "host.sshd.maxauthtries in [" + "1," * 60 + "1]", "=" * 200, "!" * 200]:
        with pytest.raises(X.ExprError):
            X.parse_predicate(text)
    assert time.perf_counter() - start < 1.0


def test_no_eval_no_regex_in_the_parser():
    """Structural guard: the tokenizer and parser use neither ``eval``/``exec`` nor ``re``."""
    for name in ("hostexpr.py", "hostconfig.py"):
        tree = ast.parse((PKG / name).read_text())
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                assert not any(a.name in ("re", "regex") for a in n.names), name
            if isinstance(n, ast.ImportFrom):
                assert n.module not in ("re", "regex"), name
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                assert n.func.id not in ("eval", "exec", "compile", "__import__"), name


# --------------------------------------------------------------------------------------------
# document level: strings and all / any / not

def test_mapping_forms():
    t = X.parse_assertion({"all": ["host.sshd.installed == false", {"not": "host.fw.ipv6_enabled == true"}]})
    assert isinstance(t, X.Group) and t.kind == "all" and len(t.children) == 2
    assert any(isinstance(c, X.Not) for c in t.children)


@pytest.mark.parametrize("raw,needle", [
    ({}, "exactly one key"),
    ({"all": [], }, "non-empty list"),
    ({"any": "host.sshd.installed == false"}, "non-empty list"),
    ({"all": ["host.sshd.installed == false"], "any": ["host.sshd.installed == true"]}, "exactly one key"),
    ({"not": []}, "not a list"),
    ({"not": ["host.sshd.installed == false"]}, "not a list"),
    ({"xor": ["a", "b"]}, "unknown key"),
    ({"host.sshd.installed == false": True}, "unknown key"),
    (5, "predicate string or a mapping"),
    (None, "predicate string or a mapping"),
    ({"all": [5]}, "predicate string or a mapping"),
    ({"all": ["host.sshd.nope == 1"]}, "assert.all[0]: position 0: unknown field"),
    ({"all": [{"any": ["host.sshd.installed == false", "host.sshd.x == 1"]}]},
     "assert.all[0].any[1]"),
])
def test_document_errors(raw, needle):
    with pytest.raises(X.ExprError) as e:
        X.parse_assertion(raw)
    assert needle in str(e.value)


# --------------------------------------------------------------------------------------------
# canonical form and digest

A = "host.sshd.installed == false"
B = "host.sshd.maxauthtries <= 4"
C = 'host.sshd.pubkeyauthentication == "yes"'


def digest_of(doc) -> str:
    return host_plan_doc(doc).digest


def test_digest_ignores_whitespace_quoting_case_and_order():
    base = digest_of({"all": [A, B, C]})
    assert digest_of({"all": [C, B, A]}) == base
    assert digest_of({"all": ["host.sshd.installed==false", "host.sshd.maxauthtries<=4",
                              "host.sshd.pubkeyauthentication == 'YES'"]}) == base
    assert digest_of({"all": ["  host.sshd.installed  ==  false  ", B, C]}) == base
    assert digest_of({"all": [[A][0], {"all": [B]}, {"any": [C]}]}) == base      # singletons collapse
    assert digest_of({"all": [{"any": [B, A]}, C]}) == digest_of({"all": [C, {"any": [A, B]}]})
    # set literals: order and duplicates do not matter
    assert (digest_of("host.sshd.allowusers subset_of [\"b\", \"a\"]")
            == digest_of("host.sshd.allowusers subset_of [\"a\", \"b\", \"a\"]"))
    assert (digest_of("host.listeners.addresses subset_of [\"10.0.0.0/8\", \"127.0.0.1\"]")
            == digest_of("host.listeners.addresses subset_of [\"127.0.0.1/32\", \"10.0.0.0/8\"]"))


def test_a_predicate_string_and_its_mapping_forms_agree():
    assert digest_of(A) == digest_of({"all": [A]}) == digest_of({"any": [{"all": [A]}]})


@pytest.mark.parametrize("a,b", [
    ("host.sshd.maxauthtries <= 4", "host.sshd.maxauthtries <= 5"),          # literal
    ("host.sshd.maxauthtries <= 4", "host.sshd.maxauthtries < 4"),           # operator
    ("host.sshd.maxauthtries <= 4", "host.sshd.maxauthtries >= 4"),
    ("host.sshd.maxauthtries == 4", "host.sshd.maxauthtries != 4"),
    ("host.sshd.maxauthtries <= 4", "host.sshd.usepam == \"yes\""),          # field
    ("host.listener(22).exists == true", "host.listener(23).exists == true"),  # param
    ("host.listener(22).exists == true", "host.listener(22).wildcard == true"),
    ("host.sshd.installed == true", "host.sshd.installed == false"),
    ("count(host.listener(22).process) == 1", "host.listener(22).process == [\"1\"]"),
    ("count(host.listener(22).process) == 1", "count(host.listener(22).process) == 2"),
    ("host.sshd.allowusers subset_of [\"a\"]", "host.sshd.allowusers subset_of [\"a\", \"b\"]"),
    ("host.sshd.allowusers subset_of [\"a\"]", "host.sshd.allowusers == [\"a\"]"),
    ("host.sshd.allowusers subset_of [\"A\"]", "host.sshd.allowusers subset_of [\"a\"]"),  # names are case-sensitive
    ("host.sshd.permitrootlogin in [\"no\"]", "host.sshd.permitrootlogin == \"no\""),
])
def test_digest_changes_with_any_semantic_difference(a, b):
    assert digest_of(a) != digest_of(b)


def test_digest_changes_with_not_and_combinator_and_membership():
    assert digest_of(A) != digest_of({"not": A})
    assert digest_of({"not": {"not": A}}) != digest_of(A)
    assert digest_of({"all": [A, B]}) != digest_of({"any": [A, B]})
    assert digest_of({"all": [A, B]}) != digest_of({"all": [A, B, C]})
    assert digest_of({"not": {"all": [A, B]}}) != digest_of({"all": [{"not": A}, {"not": B}]})
    assert digest_of({"all": [A, {"any": [B, C]}]}) != digest_of({"any": [A, {"all": [B, C]}]})


def test_digest_covers_the_non_assert_parts_too():
    d = host_plan_doc(A).digest
    assert host_plan_doc(A, max_age="12h").digest != d
    assert host_plan_doc(A, min_tier="declared").digest != d
    assert host_plan_doc(A, require=0.9).digest != d
    assert host_plan_doc(A, tag=("server",)).digest != d


def test_digest_is_the_structured_form_not_the_text():
    from paddock_assurance.parse import canonical_json
    inv = parse_invariant(HOST_YAML.format(assert_='{ all: ["host.sshd.installed == false"] }'))
    data = json.loads(canonical_json(inv))
    assert data["assert"] == {"f": "host.sshd.installed", "op": "==", "v": False}
    assert "expr" not in data


def test_canonical_order_is_sorted_children():
    t = X.parse_assertion({"all": [C, B, A]})
    keys = [X._key(c) for c in t.children]
    assert keys == sorted(keys)
    assert X.to_text(t) == X.to_text(X.parse_assertion({"all": [A, C, B]}))


def test_to_text_roundtrip_preserves_meaning():
    for pred in [A, B, C, "host.listener(22).process subset_of [\"sshd\"]",
                 "count(host.listeners.addresses) >= 2",
                 "host.listeners.addresses subset_of [\"10.0.0.0/8\"]",
                 "host.sshd.permitrootlogin in [\"no\", \"prohibit-password\"]"]:
        lf = leaf(pred)
        assert leaf(X.leaf_text(lf)) == lf


# --------------------------------------------------------------------------------------------
# integration with the invariant model

def test_assert_literal_host_config_is_rejected():
    with pytest.raises(ParseError):
        compile_text(HOST_YAML.format(assert_="host-config"))


def test_typo_literal_says_what_is_allowed():
    with pytest.raises(ParseError, match="not one of unreachable"):
        compile_text(HOST_YAML.format(assert_="unreachble"))


def test_expr_key_cannot_be_smuggled():
    with pytest.raises(ParseError, match="unknown key"):
        compile_text(HOST_YAML.format(assert_="covered") + "expr: {}\n")


@pytest.mark.parametrize("extra,needle", [
    ("subjects: { from: { zone: a }, to: { tag: [server] } }", "subjects.from"),
    ("ports: 22", "no ports"),
    ("via: { max_hops: 2 }", "no ports"),
    ("allow: [{ to: { tag: [server] }, reason: because, expires: 2027-01-01 }]", "no ports"),
])
def test_host_config_forbids_network_fields(extra, needle):
    text = HOST_YAML.format(assert_='"host.sshd.installed == false"')
    if extra.startswith("subjects"):
        text = text.replace("subjects: { to: { tag: [agent, server] } }", extra)
    else:
        text += extra + "\n"
    with pytest.raises(ParseError, match=needle):
        compile_text(text)


def test_host_config_needs_subjects_to():
    text = HOST_YAML.format(assert_='"host.sshd.installed == false"').replace(
        "subjects: { to: { tag: [agent, server] } }\n", "")
    with pytest.raises(ParseError, match="subjects.to"):
        compile_text(text)


def test_assert_must_be_literal_predicate_or_mapping():
    for bad in ("5", "true", "[a, b]", "null", "''", "{}"):
        with pytest.raises(ParseError):
            compile_text(HOST_YAML.format(assert_=bad))


def test_other_assertions_still_reject_expression_leftovers():
    # a literal assert keeps its P1 shape rules
    with pytest.raises(ParseError):
        compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:x
title: no from
subjects: { to: { tag: [a] } }
assert: unreachable
""")


def test_default_floor_for_host_config_is_strict_and_digested():
    text = HOST_YAML.format(assert_='"host.sshd.installed == false"').replace(
        "coverage: { require: 1.0 }\n", "")
    p = compile_text(text)
    assert p.coverage_required == 1.0
    assert p.digest == host_plan('"host.sshd.installed == false"').digest
    lowered = compile_text(text + "coverage: { require: 0.9 }\n")
    assert lowered.coverage_required == 0.9 and lowered.digest != p.digest
    empty = compile_text(text + "coverage: {}\n")
    assert empty.coverage_required == 1.0


def test_min_tier_above_a_fields_reachable_tier_is_a_compile_error():
    for tier in ("observed", "tested"):
        with pytest.raises(CompileError, match="never lifted"):
            host_plan_doc(A, min_tier=tier)
    host_plan_doc(A, min_tier="configured")
    host_plan_doc(A, min_tier="declared")


def test_registry_is_closed_and_consistent():
    for name, spec in HF.REGISTRY.items():
        assert name == spec.name and spec.type in HF.TYPES
        assert spec.collector in ("sshd", "firewall", "listeners", "patch")
        assert spec.max_tier.rank <= HF.Tier.configured.rank       # agent facts are never lifted
        assert (spec.param is None) == ("(" not in spec.display((1,) if spec.param else ()))
    assert {"host.sshd.password_login_possible", "host.sshd.root_login_possible",
            "host.fw.default_inbound_all_families"} <= set(HF.REGISTRY)
    assert HF.REGISTRY["host.fw.default_inbound_all_families"].derived
    assert HF.FUTURE_SLACK.total_seconds() == 300


def test_plan_records_collectors():
    p = host_plan_doc({"all": [A, "host.fw.engine == \"nft\"", "host.listener(22).exists == true"]})
    assert p.collectors == ("firewall", "listeners", "sshd")


def test_a_six_level_assert_survives_the_document_depth_cap_and_seven_does_not():
    """The document-level YAML depth cap must not undercut the contract's depth of 6."""
    def nest(levels):
        node = "host.sshd.installed == false"
        for i in range(levels):
            node = {"all" if i % 2 else "any": [node, "host.sshd.maxauthtries <= %d" % i]}
        return node
    assert host_plan_doc(nest(6)).kind.value == "HOSTCONFIG"
    with pytest.raises(ParseError, match="deeper than (6|14)"):
        host_plan_doc(nest(7))


def test_a_six_level_assert_in_block_yaml():
    # each level is a list item holding the next mapping
    text = ["apiVersion: paddock.dev/invariant/v1", "id: acme:deep", "title: deep nesting",
            "subjects: { to: { tag: [server] } }", "assert:"]
    indent = 2
    for i in range(6):
        text.append(" " * indent + ("any" if i % 2 == 0 else "all") + ":")
        text.append(" " * (indent + 2) + f"- host.sshd.maxauthtries <= {i}")
        text.append(" " * (indent + 2) + "-")
        indent += 4
    text.append(" " * (indent - 2) + "  host.sshd.installed == false")
    doc = "\n".join(text) + "\n"
    plan = compile_text(doc)
    assert plan.kind.value == "HOSTCONFIG" and X.depth(plan.expr) == 6
