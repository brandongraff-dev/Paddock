"""An invalid ``assert:`` no longer hides the other schema errors (P2.1 section 6.4, D36), and a compile
error reports every offending leaf.

Before: ``Invariant._host_assert`` raised on a bad ``assert:`` from a ``mode='before'`` validator, pydantic
aborted the whole model, no field validator ran, and the one message was labelled ``(document): Value error, ``.
So ``severity: urgent`` + ``assert: nonsense`` told the author about the assert only; fixing it revealed the
severity on the next round trip. Now ``parse_invariant`` collects the assert problem (a placeholder ``covered``
lets field validation continue) and reports ALL problems at once.

The soundness half: the placeholder must NEVER become an ``Invariant`` (it would judge ``covered`` where the author
wrote something else), and the digest of every valid document is unchanged.
"""
import pytest
from pydantic import ValidationError

from paddock_assurance import CompileError, Invariant, ParseError, compile_text, parse_invariant
from paddock_assurance.parse import digest, load_document

HEAD = """apiVersion: paddock.dev/invariant/v1
id: acme:x-y
title: Some title
"""


def doc(assert_="unreachable", severity="high", subjects="subjects: { from: { zone: a }, to: { zone: b } }",
        extra=""):
    return f"{HEAD}severity: {severity}\n{subjects}\nassert: {assert_}\n{extra}"


def problems(text):
    with pytest.raises(ParseError) as e:
        parse_invariant(text)
    return e.value.problems


# --------------------------------------------------------------------------------------------
# collection

def test_a_bad_severity_and_a_bad_assert_are_both_reported():
    p = problems(doc("nonsense", "urgent"))
    assert len(p) == 2
    assert p[0].startswith("assert:") and "expected an operator" in p[0]
    assert p[1].startswith("severity:") and "Input should be" in p[1]


def test_the_assert_problem_is_labelled_assert_not_document_and_carries_no_value_error_prefix():
    p = problems(doc("nonsense", "urgent"))
    assert not any("(document)" in x or "Value error" in x for x in p)


def test_a_bad_assert_alone_gives_exactly_one_problem_with_the_old_text_minus_the_noise():
    (p,) = problems(doc("nonsense"))
    assert p.startswith("assert: position 8: expected an operator")
    assert "(not one of unreachable, exposes-only, covered)" in p       # the author's hint survives
    assert "Value error" not in p and "(document)" not in p


def test_a_bad_assert_type_is_collected_too():
    for bad in ("12", "[a, b]", "true", "null"):
        p = problems(doc(bad, "urgent"))
        assert len(p) == 2, (bad, p)
        assert p[0].startswith("assert: must be unreachable, exposes-only, covered")
        assert p[1].startswith("severity:")


def test_a_bad_host_predicate_path_is_kept():
    # ExprError messages may already name the path (assert.all[0]: ...): it is not doubled to "assert: assert.all[0]"
    text = doc("{ all: [ 'host.sshd.nope == true' ] }", "urgent",
               subjects="subjects: { to: { tag: [server] } }")
    p = problems(text)
    assert p[0].startswith("assert.all[0]: ") and "unknown field" in p[0]
    assert not p[0].startswith("assert: assert")
    assert p[1].startswith("severity:")


def test_several_field_errors_are_all_listed_after_the_assert_problem():
    text = doc("host.sshd.installed ==", "urgent",
               subjects="subjects: { to: { tag: [server] } }", extra="coverage: { require: 7 }\nports: nope\n")
    p = problems(text)
    assert p[0].startswith("assert:")
    locs = {x.split(":")[0] for x in p[1:]}
    assert {"severity", "coverage.require", "ports"} <= locs, p


def test_the_placeholder_adds_no_bogus_shape_noise():
    # the placeholder is 'covered', which needs subjects.to and takes no subjects.from, ports, allow or via.
    # An author who wrote a (bad) host predicate with a host-shaped document must not also be told
    # "'covered' needs ..." or "'covered' takes no ...".
    for subjects in ("subjects: { to: { tag: [server] } }",
                     "subjects: { from: { zone: a }, to: { zone: b } }",
                     "subjects: { from: { zone: a } }"):
        p = problems(doc("nonsense", subjects=subjects, extra="ports: [80]\nvia: { max_hops: 3 }\n"))
        assert len(p) == 1 and p[0].startswith("assert:"), p
    assert not any("covered" in x and "needs" in x for x in problems(doc("nonsense", "urgent")))


def test_problems_are_deterministic():
    text = doc("nonsense", "urgent")
    assert problems(text) == problems(text)


def test_parse_error_message_joins_every_problem():
    with pytest.raises(ParseError, match=r"assert: .*; severity: "):
        parse_invariant(doc("nonsense", "urgent"))


# --------------------------------------------------------------------------------------------
# the placeholder never becomes an Invariant

def test_a_bad_assert_with_an_otherwise_valid_document_still_raises():
    with pytest.raises(ParseError) as e:
        parse_invariant(doc("nonsense"))
    assert len(e.value.problems) == 1


def test_every_bad_assert_is_refused_when_everything_else_is_valid():
    # no assert form that fails to parse may slip through as the 'covered' placeholder
    for bad in ("nonsense", "host.sshd.installed ==", "host.sshd.installed == maybe", "12", "[1]",
                "{ all: [] }", "{ not: [a, b] }", "unreachable-ish", "COVERED"):
        subjects = "subjects: { to: { tag: [server] } }"
        with pytest.raises(ParseError):
            parse_invariant(doc(bad, subjects=subjects))


def test_the_internal_context_never_yields_an_invariant_directly_either():
    # defence in depth: even a caller that passes the collecting context itself cannot obtain a model carrying the
    # placeholder; the document is refused, it is just not described as nicely
    d = load_document(doc("nonsense", subjects="subjects: { to: { tag: [server] } }"))
    with pytest.raises(ValidationError):
        Invariant.model_validate(d, context={"assert_problems": []})
    d2 = load_document(doc("unreachable"))
    inv = Invariant.model_validate(d2, context={"assert_problems": []})     # a VALID document is unaffected
    assert inv.assert_ == "unreachable"


def test_without_a_context_the_validator_raises_exactly_as_before():
    d = load_document(doc("nonsense", "urgent"))
    with pytest.raises(ValidationError) as e:
        Invariant.model_validate(d)
    errs = e.value.errors()
    assert len(errs) == 1 and errs[0]["loc"] == () and "expected an operator" in errs[0]["msg"]


def test_a_collected_context_is_not_reused_between_parses():
    # a failing parse must not leave state that poisons the next one
    problems(doc("nonsense"))
    assert parse_invariant(doc("unreachable")).assert_ == "unreachable"
    problems(doc("nonsense"))


# --------------------------------------------------------------------------------------------
# valid documents are byte-for-byte what they were

PINNED = {
    "reach": (doc("unreachable").replace("title: Some title", "title: A cannot reach B")
              .replace("id: acme:x-y", "id: acme:a-b"),
              "sha256:4837997e63465ff493b0e578c47bf20fd2a1b171ddf404aee2f792d248a23fb6"),
    "host": (f"""{HEAD}subjects:
  to: {{ tag: [server] }}
assert:
  all:
    - host.sshd.permitrootlogin == "no"
    - host.sshd.installed == true
""".replace("id: acme:x-y", "id: acme:ssh-hard").replace("title: Some title", "title: SSH hardened"),
             "sha256:92a37ff1a2e0685e07fe82b8c471ad5bebc7b93f0d0b53e69f8b40e079a268bc"),
}


@pytest.mark.parametrize("name", sorted(PINNED))
def test_the_digest_of_a_valid_document_is_unchanged(name):
    text, want = PINNED[name]
    assert digest(parse_invariant(text)) == want


def test_every_shipped_std_invariant_still_parses_to_the_same_digest():
    from paddock_assurance import stdlib   # noqa: F401  (package import: the yaml files ship inside it)
    import pathlib
    root = pathlib.Path(stdlib.__file__).parent if hasattr(stdlib, "__file__") and stdlib.__file__ \
        else pathlib.Path(list(stdlib.__path__)[0])
    files = sorted(root.glob("*.yaml"))
    assert files
    for f in files:
        inv = parse_invariant(f.read_text())
        assert digest(inv) == digest(parse_invariant(f.read_text()))      # stable across parses


# --------------------------------------------------------------------------------------------
# compile: every offending leaf, in one CompileError

HOST = """apiVersion: paddock.dev/invariant/v1
id: acme:many-leaves
title: Many leaves
subjects:
  to: {{ tag: [server] }}
assert:
  all:
{leaves}
evidence: {{ min_tier: {tier}, max_age: 6h }}
coverage: {{ require: 1.0 }}
"""


def host_text(leaves, tier="observed"):
    return HOST.format(leaves="\n".join(f"    - {x}" for x in leaves), tier=tier)


def test_compile_reports_every_leaf_above_the_reachable_tier_not_just_the_first():
    text = host_text(['host.sshd.permitrootlogin == "no"', "host.sshd.installed == true",
                      "host.fw.ipv6_enabled == false"])
    with pytest.raises(CompileError) as e:
        compile_text(text)
    msgs = e.value.problems
    assert len(msgs) == 3
    for field in ("host.sshd.permitrootlogin", "host.sshd.installed", "host.fw.ipv6_enabled"):
        assert any(field in m for m in msgs), (field, msgs)
    assert all("never lifted" in m for m in msgs)
    assert str(e.value) == "; ".join(msgs)


def test_compile_error_problems_are_sorted_and_deduplicated_per_field():
    # the same field twice (different values) is one problem; order is the canonical leaf order, not the author's
    text = host_text(['host.sshd.permitrootlogin == "no"', 'host.sshd.permitrootlogin != "yes"',
                      "host.sshd.installed == true"])
    with pytest.raises(CompileError) as e:
        compile_text(text)
    assert len(e.value.problems) == 2
    again = host_text(['host.sshd.installed == true', 'host.sshd.permitrootlogin != "yes"',
                       'host.sshd.permitrootlogin == "no"'])
    with pytest.raises(CompileError) as e2:
        compile_text(again)
    assert e2.value.problems == e.value.problems


def test_one_offending_leaf_among_valid_ones_is_still_one_problem_and_valid_tiers_compile():
    compile_text(host_text(['host.sshd.installed == true'], tier="configured"))
    with pytest.raises(CompileError) as e:
        compile_text(host_text(['host.sshd.installed == true'], tier="tested"))
    assert len(e.value.problems) == 1


def test_a_compile_error_without_a_list_still_has_one_problem():
    # the other CompileError raise site (icmp-only exposes-only) keeps working and exposes ``problems`` too
    text = """apiVersion: paddock.dev/invariant/v1
id: acme:only-web
title: Only web
subjects: { from: { zone: internet } }
assert: exposes-only
ports: [80]
via: { protocols: [icmp] }
"""
    with pytest.raises(CompileError, match="icmp only") as e:
        compile_text(text)
    assert len(e.value.problems) == 1 and e.value.problems[0] == str(e.value)
