import json

import pytest

from paddock_agent.collectors import base, payload_bytes

from .helpers import res


def test_constructors_and_shapes():
    s = base.ok({"a": 1})
    assert s == {"s": "ok", "v": {"a": 1}, "conf": "exact", "partial": False}
    assert base.unavailable("tool_missing") == {"s": "unavailable", "reason": "tool_missing"}
    e = base.error("timeout", "x" * 500)
    assert e["s"] == "error" and len(e["detail"]) == 120
    for sec in (s, base.unavailable("no_data"), e):
        base.validate_section(sec)


def test_constructors_reject_unknown_reasons_and_conf():
    with pytest.raises(ValueError):
        base.unavailable("whatever")
    with pytest.raises(ValueError):
        base.error("whatever")
    with pytest.raises(ValueError):
        base.ok({}, conf="maybe")


@pytest.mark.parametrize("bad", [
    {"s": "ok", "v": {}, "conf": "exact"},
    {"s": "ok", "v": [], "conf": "exact", "partial": False},
    {"s": "ok", "v": {"f": 1.5}, "conf": "exact", "partial": False},
    {"s": "unavailable", "reason": "nope"},
    {"s": "error", "reason": "timeout"},
    {"s": "weird"},
])
def test_validate_section_rejects_malformed(bad):
    with pytest.raises((ValueError, TypeError)):
        base.validate_section(bad)


def test_classify_run_never_maps_failure_to_none():
    assert base.classify_run(res(missing=True), "t") == {"s": "unavailable", "reason": "tool_missing"}
    assert base.classify_run(res(timed_out=True, rc=None), "t")["reason"] == "timeout"
    assert base.classify_run(res(truncated=True, rc=-9), "t")["reason"] == "truncated"
    assert base.classify_run(res(rc=1, err="Operation not permitted"), "t") == {
        "s": "unavailable", "reason": "permission_denied"}
    assert base.classify_run(res(rc=2, err="kaboom"), "t")["reason"] == "exit_nonzero"
    assert base.classify_run(res(rc=None), "t")["reason"] == "exit_nonzero"
    assert base.classify_run(res(out="x"), "t") is None
    # success with no output is NOT a failure by itself: that is the caller's call
    assert base.classify_run(res(out=""), "t") is None


def test_payload_bytes_is_the_documented_canonical_form():
    obj = {"b": [1, 2, {"z": None, "a": True}], "a": "é", "c": ""}
    got = payload_bytes(obj)
    assert got == b'{"a":"\xc3\xa9","b":[1,2,{"a":true,"z":null}],"c":""}'
    assert got == json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")


@pytest.mark.parametrize("bad", [{"f": 1.0}, {"f": float("nan")}, {1: "x"}, {"t": (1, 2)},
                                 {"s": {1, 2}}, {"b": b"x"}])
def test_payload_bytes_rejects_floats_and_non_json(bad):
    with pytest.raises((TypeError, ValueError)):
        payload_bytes(bad)


def test_clean_str_removes_control_and_surrogates():
    assert base.clean_str("a\x00b\nc\udcff") == "a?b?c?"
    assert len(base.clean_str("x" * 1000, 10)) == 10
