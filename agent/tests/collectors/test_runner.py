import os
import sys
import time

from paddock_agent.runner import FIXED_PATH, Ctx, run_command

from .helpers import make_ctx, put

PY = sys.executable


def _alive(pid):
    try:
        with open("/proc/%d/stat" % pid) as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
        return state != "Z"
    except (OSError, IndexError):
        return False


def test_returns_rc_out_and_err_tail():
    r = run_command([PY, "-c", "import sys; print('hi'); sys.stderr.write('boom\\n'); sys.exit(3)"])
    assert r["rc"] == 3 and r["out"].strip() == "hi" and "boom" in r["err_tail"]
    assert not r["timed_out"] and not r["missing"] and not r["truncated"]
    assert set(r) == {"rc", "out", "err_tail", "timed_out", "missing", "truncated"}


def test_missing_binary_is_missing_not_empty_success():
    for argv in (["definitely-not-a-real-binary-xyz"], ["/nonexistent/bin/xyz"], []):
        r = run_command(argv)
        assert r["missing"] is True and r["rc"] is None and r["out"] == ""


def test_timeout_kills_the_whole_process_group(tmp_path):
    pidfile = str(tmp_path / "grandchild.pid")
    code = ("import subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            "open(%r,'w').write(str(p.pid));time.sleep(60)" % pidfile)
    t0 = time.monotonic()
    r = run_command([PY, "-c", code], timeout=1.5)
    assert r["timed_out"] is True
    assert time.monotonic() - t0 < 10
    for _ in range(50):
        if os.path.exists(pidfile) and open(pidfile).read().strip():
            break
        time.sleep(0.05)
    pid = int(open(pidfile).read())
    for _ in range(50):
        if not _alive(pid):
            break
        time.sleep(0.05)
    assert not _alive(pid), "grandchild survived the timeout"


def test_output_cap_truncates_and_kills():
    t0 = time.monotonic()
    r = run_command([PY, "-c", "import sys\nwhile True: sys.stdout.write('x'*65536)"],
                    timeout=20, max_bytes=100000)
    assert r["truncated"] is True and len(r["out"]) <= 100000
    assert time.monotonic() - t0 < 10


def test_fixed_environment_no_shell_stdin_devnull(monkeypatch):
    monkeypatch.setenv("PATH", "/evil/bin")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    r = run_command([PY, "-c", "import os,sys;print(os.environ['PATH']);print(os.environ['LC_ALL']);"
                     "print(repr(sys.stdin.read()));print(sys.argv[1])", "a; echo injected $HOME"])
    lines = r["out"].splitlines()
    assert lines[0] == FIXED_PATH and lines[1] == "C"
    assert lines[2] == "''"
    assert lines[3] == "a; echo injected $HOME"


def test_env_cannot_override_path():
    r = run_command([PY, "-c", "import os;print(os.environ['PATH'])"], env={"PATH": "/x", "FOO": "1"})
    assert r["out"].strip() == FIXED_PATH


def test_ctx_clock_and_iso(tmp_path):
    ctx = make_ctx(tmp_path, now=1700000000)
    assert ctx.now_s() == 1700000000 and ctx.now_iso() == "2023-11-14T22:13:20Z"
    assert Ctx(str(tmp_path), "1").now_s() > 1700000000
    ctx2 = Ctx(str(tmp_path), "1", now=lambda: 5)
    assert ctx2.now_s() == 5


def test_ctx_pinned_signature():
    ctx = Ctx("/var/lib/x", "0.2.0", seq=4, key_id="kid", machine_salt=b"s", clock_skew_ms=12,
              enable_imds=True, now=1)
    assert (ctx.seq, ctx.key_id, ctx.machine_salt, ctx.clock_skew_ms, ctx.enable_imds) == (
        4, "kid", b"s", 12, True)
    assert Ctx("/x", "1").enable_imds is False and Ctx("/x", "1").clock_skew_ms is None


def test_ctx_fs_mapping_and_reads(tmp_path):
    ctx = make_ctx(tmp_path, files={"/etc/a": "hello", "/proc/self/status": "CapEff:\t0000000000001000\n"})
    assert ctx.read_text("/etc/a") == ("ok", "hello")
    assert ctx.read_text("/etc/missing")[0] == "missing"
    st, data = ctx.read_bytes("/etc/a", 3)
    assert st == "truncated" and data == b"hel"
    assert ctx.cap_eff() == 0x1000 and ctx.has_cap(12) and not ctx.has_cap(19)
    assert ctx.listdir("/etc") == ("ok", ["a"])


def test_ctx_which_uses_only_the_fixed_path(tmp_path):
    ctx = make_ctx(tmp_path, bins=["/usr/sbin/nft", "/opt/evil/ssh"])
    assert ctx.which("nft") == "/usr/sbin/nft"
    assert ctx.which("ssh") is None


def test_containerised_detection(tmp_path):
    assert make_ctx(tmp_path / "a", containerised=None).containerised is False
    assert make_ctx(tmp_path / "b", containerised=None, files={"/.dockerenv": ""}).containerised is True
    c = make_ctx(tmp_path / "c", containerised=None,
                 files={"/proc/1/cgroup": "0::/docker/" + "a" * 64 + "\n"})
    assert c.containerised is True
    c = make_ctx(tmp_path / "d", containerised=None, files={"/proc/1/cgroup": "0::/init.scope\n"})
    assert c.containerised is False


def test_ctx_deadline(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.set_deadline(1)
    ctx.check()
    ctx._deadline = time.monotonic() - 1
    import pytest
    from paddock_agent.runner import CollectorTimeout
    with pytest.raises(CollectorTimeout):
        ctx.check()
    assert ctx.run(["x"])["timed_out"] is True
    put(str(tmp_path), "x", "y")


def test_ctx_accepts_str_salt_and_datetime_now():
    import datetime
    when = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    ctx = Ctx("/x", "1", machine_salt="salt", now=when)
    assert ctx.machine_salt == b"salt" and ctx.now_iso() == "2026-01-02T03:04:05Z"
    assert Ctx("/x", "1", now=lambda: 86400).now_iso() == "1970-01-02T00:00:00Z"
    assert Ctx("/x", "1", now=1.9).now_s() == 1  # floats are truncated, never stored
