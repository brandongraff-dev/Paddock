"""State directory: atomic 0600 writes, refusal of loose files, write-ahead seq, bounded outbox."""
from __future__ import annotations

import gzip
import json
import os
import stat

import pytest

from paddock_agent import signing, state


def _state(tmp_path, **kw):
    d = tmp_path / "state"
    d.mkdir(mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return state.State(str(d), **kw)


def _creds(**kw):
    base = dict(agent_id="11111111-1111-4111-8111-111111111111", agent_token="fat_" + "a" * 12 + "_" + "s" * 32,
                tenant_id="22222222-2222-4222-8222-222222222222", server="https://paddock.example",
                hostname="web-01", key_id="k" * 32)
    base.update(kw)
    return state.Credentials(**base)


# --------------------------------------------------------------------------- #
# atomic, private writes
# --------------------------------------------------------------------------- #

def test_atomic_write_is_0600_from_the_first_byte_and_fsynced_before_replace(tmp_path, monkeypatch):
    events = []
    real_replace, real_fsync = os.replace, os.fsync
    modes = []

    def replace(src, dst):
        modes.append(stat.S_IMODE(os.stat(src).st_mode))      # the temp file, before it is visible
        events.append("replace")
        return real_replace(src, dst)

    def fsync(fd):
        events.append("fsync")
        return real_fsync(fd)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "fsync", fsync)
    target = tmp_path / "secret"
    state.atomic_write(str(target), b"data")
    assert modes == [0o600]
    assert events[0] == "fsync" and events.index("replace") > events.index("fsync")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert not [n for n in os.listdir(tmp_path) if n.startswith(".tmp-")]


def test_atomic_write_leaves_the_old_file_and_no_temp_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "secret"
    state.atomic_write(str(target), b"old")
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        state.atomic_write(str(target), b"new")
    monkeypatch.undo()
    assert target.read_bytes() == b"old"
    assert not [n for n in os.listdir(tmp_path) if n.startswith(".tmp-")]


def test_secrets_are_refused_when_group_or_world_accessible(tmp_path):
    st = _state(tmp_path)
    st.save_credentials(_creds())
    assert st.load_credentials().agent_id == "11111111-1111-4111-8111-111111111111"
    os.chmod(st.cred_path, 0o640)
    with pytest.raises(state.StateError, match="accessible by other users"):
        st.load_credentials()
    os.chmod(st.cred_path, 0o604)
    with pytest.raises(state.StateError):
        st.load_credentials()
    os.chmod(st.cred_path, 0o600)
    assert st.load_credentials() is not None


def test_key_file_refused_when_loose(tmp_path):
    st = _state(tmp_path)
    st.save_key(bytes(range(32)))
    os.chmod(st.key_path, 0o644)
    with pytest.raises(state.StateError):
        st.load_key()


def test_a_secret_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    st = _state(tmp_path)
    st.save_credentials(_creds())
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(st.cred_path).st_uid + 1)
    with pytest.raises(state.StateError, match="owned by"):
        st.load_credentials()


def test_symlinked_secret_is_refused(tmp_path):
    st = _state(tmp_path)
    st.ensure_dir()
    real = tmp_path / "elsewhere"
    real.write_text("{}")
    os.chmod(real, 0o600)
    os.symlink(real, st.cred_path)
    with pytest.raises(state.StateError, match="not a regular file"):
        st.load_credentials()


def test_state_dir_other_users_can_write_is_refused(tmp_path):
    st = _state(tmp_path)
    os.chmod(st.dir, 0o777)
    with pytest.raises(state.StateError, match="writable by other users"):
        st.ensure_dir()
    with pytest.raises(state.StateError):
        st.save_credentials(_creds())


def test_state_dir_is_created_0700(tmp_path):
    st = state.State(str(tmp_path / "new" / "agent"))
    st.ensure_dir()
    assert stat.S_IMODE(os.stat(st.dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(st.keys_dir).st_mode) == 0o700


def test_missing_files_read_as_none(tmp_path):
    st = _state(tmp_path)
    assert st.load_credentials() is None and st.load_key() is None and st.load_pending_key() is None
    assert st.current_seq() == 0 and st.load_handled() == {}


def test_credentials_roundtrip_hide_token_in_repr_and_reject_v1_files(tmp_path):
    st = _state(tmp_path)
    c = _creds()
    st.save_credentials(c)
    back = st.load_credentials()
    assert (back.agent_id, back.agent_token, back.tenant_id, back.server) == (
        c.agent_id, c.agent_token, c.tenant_id, c.server)
    assert c.agent_token not in repr(back)
    # a v1 credential file has no tenant_id: it must not be silently accepted
    state.atomic_write(st.cred_path, json.dumps({"agent_id": "x", "agent_token": "y"}).encode())
    with pytest.raises(state.StateError, match="re-enroll"):
        st.load_credentials()


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #

def test_key_roundtrip_pending_and_promote(tmp_path):
    st = _state(tmp_path)
    a, b = signing.generate_seed(), signing.generate_seed()
    st.save_key(a)
    st.save_pending_key(b)
    assert st.load_key() == a and st.load_pending_key() == b
    st.promote_pending_key()
    assert st.load_key() == b and st.load_pending_key() is None
    with pytest.raises(state.StateError):
        st.promote_pending_key()
    st.save_pending_key(a)
    st.discard_pending_key()
    assert st.load_pending_key() is None and st.load_key() == b


def test_corrupt_or_inconsistent_key_files_are_errors_not_none(tmp_path):
    st = _state(tmp_path)
    st.ensure_dir()
    state.atomic_write(st.key_path, b"not json")
    with pytest.raises(state.StateError):
        st.load_key()
    good = json.loads(st._encode_key(bytes(range(32))))
    for mutate in (lambda d: d.update(key_id="0" * 32), lambda d: d.update(seed_b64="AAAA"),
                   lambda d: d.update(alg="rsa"), lambda d: d.pop("seed_b64")):
        d = dict(good)
        mutate(d)
        state.atomic_write(st.key_path, json.dumps(d).encode())
        with pytest.raises(state.StateError):
            st.load_key()


# --------------------------------------------------------------------------- #
# write-ahead sequence
# --------------------------------------------------------------------------- #

def test_seq_is_persisted_and_fsynced_before_next_seq_returns(tmp_path, monkeypatch):
    st = _state(tmp_path)
    seen = {}
    real_replace = os.replace

    def replace(src, dst):
        seen["fsynced_before_replace"] = seen.get("fsync_calls", 0) > 0
        return real_replace(src, dst)

    real_fsync = os.fsync

    def fsync(fd):
        seen["fsync_calls"] = seen.get("fsync_calls", 0) + 1
        return real_fsync(fd)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "fsync", fsync)
    assert st.next_seq() == 1
    monkeypatch.undo()
    assert seen["fsynced_before_replace"] is True
    assert json.loads(open(st.seq_path).read()) == {"seq": 1}      # already on disk when it returned


def test_a_crash_after_reserving_can_skip_a_number_but_never_reuse_one(tmp_path):
    st = _state(tmp_path)
    assert [st.next_seq() for _ in range(3)] == [1, 2, 3]
    # the process "crashes" after reserving 3 and before sending it; a new process continues at 4
    st2 = state.State(st.dir)
    assert st2.next_seq() == 4


def test_seq_state_loss_is_corrected_only_upwards(tmp_path):
    st = _state(tmp_path)
    st.next_seq()
    os.unlink(st.seq_path)
    assert st.next_seq() == 1                 # lost state restarts low ...
    assert st.fast_forward(50) is True        # ... and a server 409 expected_min lifts it
    assert st.next_seq() == 50
    assert st.fast_forward(10) is False       # never down
    assert st.next_seq() == 51
    for bad in (0, -3, "7", 1.5, None, True, state.MAX_SEQ + 1):
        assert st.fast_forward(bad) is False
    assert st.next_seq() == 52


def test_corrupt_seq_file_is_a_hard_error(tmp_path):
    st = _state(tmp_path)
    st.ensure_dir()
    for junk in (b"garbage", b'{"seq": -1}', b'{"seq": "5"}', b'{"seq": true}', b'[]',
                 json.dumps({"seq": state.MAX_SEQ + 5}).encode()):
        state.atomic_write(st.seq_path, junk)
        with pytest.raises(state.StateError):
            st.next_seq()


# --------------------------------------------------------------------------- #
# outbox
# --------------------------------------------------------------------------- #

def test_outbox_is_fifo_gzip_0600_and_roundtrips(tmp_path):
    box = _state(tmp_path).outbox
    for i in range(5):
        box.put({"n": i})
    files = box.files()
    assert len(box) == 5 and [box.read(f)["n"] for f in files] == [0, 1, 2, 3, 4]
    assert stat.S_IMODE(os.stat(files[0]).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(box.path).st_mode) == 0o700
    assert json.loads(gzip.decompress(open(files[0], "rb").read())) == {"n": 0}
    box.delete(files[0])
    assert len(box) == 4


def test_outbox_evicts_oldest_first_when_over_the_cap(tmp_path):
    box = _state(tmp_path, outbox_max_bytes=2500).outbox
    blob = os.urandom(300).hex()
    total_evicted = 0
    for i in range(30):
        total_evicted += box.put({"n": i, "blob": blob})
    survivors = [box.read(f)["n"] for f in box.files()]
    assert total_evicted == box.dropped > 0
    assert survivors == sorted(survivors) and survivors[-1] == 29         # newest kept
    assert 0 not in survivors                                             # oldest gone
    assert box.size() <= 2500


def test_outbox_drops_corrupt_items_and_stale_temp_files(tmp_path):
    st = _state(tmp_path)
    st.outbox.put({"ok": 1})
    bad = os.path.join(st.outbox.path, "00000000000000000001.json.gz")
    open(bad, "wb").write(b"not gzip")
    open(os.path.join(st.outbox.path, "00000000000000000002.tmp"), "wb").write(b"x")
    box = state.Outbox(st.outbox.path)          # a fresh process: cleans temp files on first put
    box.put({"ok": 2})
    assert not [n for n in os.listdir(box.path) if n.endswith(".tmp")]
    items = []
    for f in box.files():
        item = box.read(f)
        if item is not None:
            items.append(item["ok"])
    assert items == [1, 2] and not os.path.exists(bad)


def test_handled_actions_are_capped_to_the_newest(tmp_path):
    st = _state(tmp_path)
    items = dict(("a%d" % i, {"at": i, "status": "applied"}) for i in range(300))
    st.save_handled(items, keep=10)
    back = st.load_handled()
    assert sorted(back, key=lambda k: back[k]["at"]) == ["a%d" % i for i in range(290, 300)]
