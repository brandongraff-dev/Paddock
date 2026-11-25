"""Tri-state ``Section`` results, run classification and the canonical encoding.

A Section is exactly one of::

    {"s": "ok", "v": {...}, "conf": "exact"|"approximate", "partial": false}
    {"s": "unavailable", "reason": <UNAVAILABLE_REASONS>}
    {"s": "error", "reason": <ERROR_REASONS>, "detail": "<=120 chars"}

An ``ok`` is never produced to mean "I could not look". Python 3.8 syntax only.
"""
import json

SCHEMA = 2

UNAVAILABLE_REASONS = frozenset([
    "tool_missing", "permission_denied", "not_applicable", "unsupported_platform",
    "daemon_not_running", "unmanaged_kernel", "containerised_agent", "no_data",
])
ERROR_REASONS = frozenset(["timeout", "exit_nonzero", "parse_error", "truncated", "exception"])
CONFS = ("exact", "approximate")
DETAIL_MAX = 120

_PERMISSION_HINTS = (
    "operation not permitted", "permission denied", "must be root", "you must be root",
    "are you root", "not permitted", "need to be root", "requires root", "eperm",
    "no hostkeys available",
)


def clean_str(value, maxlen=256):
    """Printable, valid-UTF-8, length-capped copy of ``value`` (never raises)."""
    if not isinstance(value, str):
        value = str(value)
    value = value.encode("utf-8", "replace").decode("utf-8", "replace")
    value = "".join(c if (c >= " " and c != "\x7f") else "?" for c in value)
    return value[:maxlen]


def ok(v, conf="exact", partial=False):
    if conf not in CONFS:
        raise ValueError("bad conf %r" % (conf,))
    return {"s": "ok", "v": v, "conf": conf, "partial": bool(partial)}


def unavailable(reason):
    if reason not in UNAVAILABLE_REASONS:
        raise ValueError("bad unavailable reason %r" % (reason,))
    return {"s": "unavailable", "reason": reason}


def error(reason, detail=""):
    if reason not in ERROR_REASONS:
        raise ValueError("bad error reason %r" % (reason,))
    return {"s": "error", "reason": reason, "detail": clean_str(detail, DETAIL_MAX)}


def looks_like_permission_error(text):
    low = (text or "").lower()
    return any(h in low for h in _PERMISSION_HINTS)


def classify_run(res, tool):
    """Map a failed runner result to an unavailable/error Section, else ``None``.

    ``None`` means the command ran to completion with rc 0 and its output is whole.
    """
    if res.get("missing"):
        return unavailable("tool_missing")
    if res.get("timed_out"):
        return error("timeout", "%s timed out" % tool)
    if res.get("truncated"):
        return error("truncated", "%s output exceeded the cap" % tool)
    rc = res.get("rc")
    if rc != 0:
        tail = res.get("err_tail", "")
        if looks_like_permission_error(tail):
            return unavailable("permission_denied")
        return error("exit_nonzero", "%s rc=%s %s" % (tool, rc, tail[:70]))
    return None


def _check_canonical(obj, depth=0):
    if depth > 40:
        raise ValueError("payload nesting too deep")
    if obj is None or isinstance(obj, (bool, str)):
        return
    if isinstance(obj, float):
        raise TypeError("floats are not allowed in a payload")
    if isinstance(obj, int):
        return
    if isinstance(obj, list):
        for item in obj:
            _check_canonical(item, depth + 1)
        return
    if isinstance(obj, dict):
        for k, val in obj.items():
            if not isinstance(k, str):
                raise TypeError("payload keys must be strings")
            _check_canonical(val, depth + 1)
        return
    raise TypeError("type %s is not allowed in a payload" % type(obj).__name__)


def payload_bytes(payload):
    """The canonical encoding signed and hashed by the agent (and never re-made by the server).

    Sorted keys, compact separators, ``ensure_ascii=False``, ``allow_nan=False``, UTF-8.
    Rejects floats, non-string keys, tuples and any non-JSON type so the stdlib
    form equals RFC 8785 for these inputs.
    """
    _check_canonical(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def validate_section(sec):
    """Raise ValueError unless ``sec`` is a well-formed Section (used by tests and collect_all)."""
    if not isinstance(sec, dict) or "s" not in sec:
        raise ValueError("not a section")
    kind = sec["s"]
    if kind == "ok":
        if set(sec) != {"s", "v", "conf", "partial"}:
            raise ValueError("ok section keys %r" % sorted(sec))
        if sec["conf"] not in CONFS or not isinstance(sec["partial"], bool):
            raise ValueError("ok section conf/partial")
        if not isinstance(sec["v"], dict):
            raise ValueError("ok section v must be an object")
    elif kind == "unavailable":
        if set(sec) != {"s", "reason"} or sec["reason"] not in UNAVAILABLE_REASONS:
            raise ValueError("bad unavailable section")
    elif kind == "error":
        if set(sec) != {"s", "reason", "detail"} or sec["reason"] not in ERROR_REASONS:
            raise ValueError("bad error section")
        if len(sec["detail"]) > DETAIL_MAX:
            raise ValueError("error detail too long")
    else:
        raise ValueError("unknown section state %r" % (kind,))
    _check_canonical(sec)
