"""Test helpers: a fake probe runner and a Ctx rooted in a temporary directory."""
import os

from paddock_agent.runner import Ctx

FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


def fixture(*parts):
    with open(os.path.join(FIX, *parts), "r", encoding="utf-8") as fh:
        return fh.read()


def res(out="", rc=0, err="", timed_out=False, missing=False, truncated=False):
    return {"rc": None if missing else rc, "out": out, "err_tail": err,
            "timed_out": timed_out, "missing": missing, "truncated": truncated}


class FakeRunner(object):
    """Maps argv tuples (or a callable) to runner results and records every call."""

    def __init__(self, table=None, default=None):
        self.table = dict(table or {})
        self.default = default
        self.calls = []

    def __call__(self, argv, timeout, max_bytes):
        self.calls.append(list(argv))
        key = tuple(argv)
        if key in self.table:
            hit = self.table[key]
            return hit(argv) if callable(hit) else hit
        for k, hit in self.table.items():
            if isinstance(k, str) and argv and os.path.basename(argv[0]) == k:
                return hit(argv) if callable(hit) else hit
        if self.default is not None:
            return self.default(argv) if callable(self.default) else self.default
        return res(missing=True)


def put(root, path, content, mode=None):
    full = os.path.join(root, path.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    if isinstance(content, str):
        content = content.encode("utf-8")
    with open(full, "wb") as fh:
        fh.write(content)
    if mode is not None:
        os.chmod(full, mode)
    return full


def make_ctx(tmp_path, runner=None, files=None, bins=(), is_root=True, containerised=False,
             now=1795000000, **kw):
    """Ctx whose host files live under ``tmp_path/root`` and ``/proc`` under ``tmp_path/proc``."""
    root = os.path.join(str(tmp_path), "root")
    proc = os.path.join(str(tmp_path), "proc")
    os.makedirs(root, exist_ok=True)
    os.makedirs(proc, exist_ok=True)
    for path, content in (files or {}).items():
        if path == "/proc" or path.startswith("/proc/"):
            put(proc, path[len("/proc"):], content)
        else:
            put(root, path, content)
    for b in bins:
        put(root, b, "#!/bin/sh\n", mode=0o755)
    ctx = Ctx(os.path.join(str(tmp_path), "state"), "0.2.0-test", seq=7, key_id="k" * 32,
              machine_salt=b"salt", now=now, proc_root=proc, host_root=root,
              runner=runner or FakeRunner(), is_root=is_root, containerised=containerised,
              platform="linux", **kw)
    ctx.cache["machine"] = "x86_64"
    return ctx
