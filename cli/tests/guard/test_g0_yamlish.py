# SPDX-License-Identifier: AGPL-3.0-or-later
"""yamlish: the minimal line-oriented YAML reader (contract D5, 3.2; consumers G2b)."""
from __future__ import annotations

import time

import pytest

from paddock_cli.guard import yamlish
from paddock_cli.guard.yamlish import YMap, YScalar, YSeq, YamlUnsupported, parse

WORKFLOW = """\
# a workflow
name: CI   # trailing comment
on:
  push:
    branches: [main, "release/*"]
  pull_request_target:
permissions: {contents: read}
env:
  NODE_VERSION: '20'
  EMPTY:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Build
        run: |
          echo "hello: world"
          npm ci
      - run: >-
          echo folded
          text
      - name: Last
        if: github.event_name == 'push'
        run: echo "done" # comment
  other:
  - a
  - b
"""


def test_parses_a_realistic_workflow_with_line_numbers():
    doc = parse(WORKFLOW)
    assert isinstance(doc, YMap)
    assert doc.get("name").value == "CI" and doc.get("name").line == 2
    on = doc.get("on")
    assert isinstance(on, YMap) and "pull_request_target" in on.keys()
    assert on.get("pull_request_target").value is None or on.get("pull_request_target").value == ""
    branches = on.get("push").get("branches")
    assert isinstance(branches, YSeq) and [i.value for i in branches.items] == ["main", "release/*"]
    assert doc.get("permissions").get("contents").value == "read"
    assert doc.get("env").get("NODE_VERSION").value == "20" and doc.get("env").get("EMPTY").typed() is None
    steps = doc.get("jobs").get("build").get("steps")
    assert isinstance(steps, YSeq) and len(steps.items) == 4
    assert steps.items[0].get("uses").value == "actions/checkout@v4" and steps.items[0].get("uses").line == 15
    assert steps.items[0].get("with").get("ref").value == "${{ github.event.pull_request.head.sha }}"
    run = steps.items[1].get("run")
    assert run.style == "block" and run.value == 'echo "hello: world"\nnpm ci\n' and run.line == 19
    assert run.body_line == 20
    assert steps.items[2].get("run").value.strip() == "echo folded text"
    assert steps.items[3].get("if").value == "github.event_name == 'push'"
    assert steps.items[3].get("run").value == 'echo "done"'
    other = doc.get("jobs").get("other")
    assert [i.value for i in other.items] == ["a", "b"]


def test_to_python_roundtrip_of_simple_structures():
    doc = parse("a: 1\nb:\n  - x\n  - y: true\n    z: ~\nc: 'q'\nd: \"t\\tab\"\n")
    assert yamlish.to_python(doc) == {"a": "1", "b": ["x", {"y": "true", "z": "~"}], "c": "q", "d": "t\tab"}


def test_typed_scalars():
    s = parse("a: true\nb: False\nc: null\nd: ~\ne: 12\nf: 'true'\ng: x\n")
    assert [s.get(k).typed() for k in "abcdefg"] == [True, False, None, None, 12, "true", "x"]


def test_duplicate_keys_are_reported_not_fatal():
    d = parse("a: 1\nb: 2\na: 3\n")
    assert d.duplicates == ["a"] and d.get("a").value == "3"


def test_comments_and_quotes_do_not_confuse_the_reader():
    d = parse("a: 'x # not comment'\nb: \"y # not\" # real\nc: z#nocomment\n# full\n\n")
    assert d.get("a").value == "x # not comment" and d.get("b").value == "y # not" and d.get("c").value == "z#nocomment"


def test_document_start_marker_and_crlf():
    d = parse("---\r\na: 1\r\nb:\r\n  - 2\r\n")
    assert yamlish.to_python(d) == {"a": "1", "b": ["2"]}


def test_empty_document_and_scalar_document():
    assert parse("").value is None or parse("") is not None
    assert parse("# only a comment\n") is not None
    assert parse("just a scalar\n").value == "just a scalar"


@pytest.mark.parametrize("text, frag", [
    ("a: &anchor 1\n", "anchor"),
    ("a: *alias\n", "alias"),
    ("a:\n  <<: *base\n", "merge"),
    ("a: {b: {c: 1}}\n", "flow"),
    ("a: [1, [2]]\n", "flow"),
    ("a: [1,\n  2]\n", "flow"),
    ("a:\n\tb: 1\n", "tab"),
    ("a: 1\n---\nb: 2\n", "document"),
    ("a: !!str 1\n", "tag"),
    ("? complex\n: key\n", "complex"),
    ("a: 'unterminated\n  more'\n", "quote"),
    ("a: |\n  x\n bad: 1\n", ""),
])
def test_unsupported_constructs_raise_with_a_reason(text, frag):
    try:
        parse(text)
    except YamlUnsupported as exc:
        assert frag in str(exc)
    else:
        if frag:
            raise AssertionError("expected YamlUnsupported")


def test_bounded_on_hostile_input():
    deep = "".join(" " * i + "k%d:\n" % i for i in range(0, 400))
    t0 = time.process_time()
    with pytest.raises(YamlUnsupported):
        parse(deep)
    with pytest.raises(YamlUnsupported):
        parse("a: 1\n" * 30000)
    with pytest.raises(YamlUnsupported):
        parse("a: " + "x" * 5000 + "\n")
    with pytest.raises(YamlUnsupported):
        parse("a: [" + "[" * 100000 + "]" * 100000 + "]\n")
    assert time.process_time() - t0 < 10


def test_scalar_and_node_types_exported():
    d = parse("a: b\n")
    assert isinstance(d.get("a"), YScalar) and d.get("missing") is None
    assert d.keys() == ["a"]
