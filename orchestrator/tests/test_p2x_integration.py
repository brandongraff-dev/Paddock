"""P2 adversarial review, round 2, package I: the agent <-> server integration and the wire/audit residuals.

Everything here drives the REAL agent code (collectors over the fixture host, the real envelope signer, the real
client) into the REAL server (ASGI app, store, ``host_fw`` builder, graph loader, the ``paddock_assurance`` library),
so a mismatch between what the agent produces and what the server accepts shows up here and nowhere else:

* I-1: a real posture was refused 422 because the server's ``extra=forbid`` models did not know ``sshd.v.daemon``,
  ``sshd.v.truncated`` and ``listeners.v.dropped``; and a clean host must HOLD, a bad one must be VIOLATED, and a host
  whose evidence is incomplete must read UNKNOWN (never HOLDS).

The wire and audit residuals (I-2 .. I-5) are in ``test_p2x_wire_i.py``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import fleet_posture as fp

from . import p2_support as sup
from .p2_support import FixtureHost
from .test_assurance_p2_e2e import (  # noqa: F401  (fixtures are shared on purpose)
    FWD, SSH, World, _fresh_limiters, enable_std, enforce, evaluate, findings, invariant, mint, runtime, verdicts,
    world)
from .test_fleet_posture import good_posture, pbytes


# =========================================================================== #
# I-1: what the REAL collectors produce is what the wire models accept
# =========================================================================== #

def _collect(tmp_path: Path, mutate=None) -> bytes:
    """The exact bytes the real agent signs, for a fixture host ``mutate`` has changed."""
    from paddock_agent.collectors import collect_all, payload_bytes

    host = FixtureHost(tmp_path / "host")
    if mutate is not None:
        mutate(host)
    ctx = host.make_ctx(str(tmp_path / "state"), seq=1, key_id="0" * 32, machine_salt=b"salt")
    return payload_bytes(collect_all(ctx))


def _many_names(host: FixtureHost) -> None:
    host.extra_sshd_T = "allowusers " + " ".join("user%03d" % i for i in range(60)) + "\n"


def _text_source(host: FixtureHost) -> None:
    host.sshd_T_fails = True


def _text_source_cut(host: FixtureHost) -> None:
    host.sshd_T_fails = True
    cfg = host.root / "root/etc/ssh/sshd_config"
    cfg.write_text(cfg.read_text() + "AllowUsers " + " ".join("user%03d" % i for i in range(60)) + "\n")


def _many_listeners(host: FixtureHost) -> None:
    tcp = host.root / "proc/net/tcp"
    rows = ["  %d: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %d 1 "
            "0000000000000000 100 0 0 10 0" % (i + 100, 1024 + i, 90000 + i) for i in range(2100)]
    tcp.write_text(tcp.read_text() + "\n".join(rows) + "\n")


def _no_daemon(host: FixtureHost) -> None:
    import shutil

    shutil.rmtree(host.root / "proc" / str(FixtureHost.SSHD_PID))


def _no_sshd(host: FixtureHost) -> None:
    (host.root / "root/usr/sbin/sshd").unlink()
    _no_daemon(host)


VARIANTS = {
    "clean": (None, {}),
    "no_daemon_found": (_no_daemon, {"daemon_found": False}),
    "config_value_cut": (_many_names, {"truncated": ["allowusers"]}),
    "text_source": (_text_source, {"source": "text"}),
    "text_source_cut": (_text_source_cut, {"source": "text", "truncated": ["allowusers"]}),
    "listener_table_cut": (_many_listeners, {"dropped": True}),
    "no_sshd_at_all": (_no_sshd, {"sshd_s": "unavailable"}),
}


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_i1_a_real_agent_posture_is_accepted_by_the_wire_models(tmp_path, name):
    """Round 1's collectors added ``sshd.v.daemon`` (always), ``sshd.v.truncated`` and ``listeners.v.dropped`` (when
    set); the server's strict models refused every posture with 'payload_schema'. Each variant is what the real
    collectors print for that host, byte for byte as the agent would sign it."""
    mutate, expect = VARIANTS[name]
    raw = _collect(tmp_path, mutate)
    parsed = fp.validate_posture(raw)                    # raises PayloadError('payload_schema', ...) when refused
    sshd, lis = parsed["sections"]["sshd"], parsed["sections"]["listeners"]
    if "sshd_s" in expect:
        assert sshd["s"] == expect["sshd_s"]
        return
    assert sshd["s"] == "ok" and set(sshd["v"]["daemon"]) == {
        "found", "masters", "pid", "start_epoch", "reexec_epoch", "config_path", "config_default",
        "options_override", "binary_matches", "config_mtime", "reload_pending"}
    assert sshd["v"]["daemon"]["found"] is expect.get("daemon_found", True)
    assert sshd["v"]["source"] == expect.get("source", "sshd_T")
    assert sshd["v"].get("truncated") == expect.get("truncated")
    if expect.get("truncated"):
        assert sshd["conf"] == "approximate"             # a cut value is never exact
    assert ("dropped" in lis["v"]) is bool(expect.get("dropped"))
    if expect.get("dropped"):
        assert lis["partial"] is True and lis["v"]["dropped"] >= 1


def _posture_with(mutate) -> bytes:
    p = good_posture()
    mutate(p["sections"])
    return pbytes(p)


@pytest.mark.parametrize("label,mutate", [
    ("daemon_missing", lambda s: s["sshd"]["v"].pop("daemon")),
    ("daemon_null", lambda s: s["sshd"]["v"].update(daemon=None)),
    ("daemon_extra_key", lambda s: s["sshd"]["v"]["daemon"].update(cmdline="sshd -D")),
    ("daemon_key_missing", lambda s: s["sshd"]["v"]["daemon"].pop("reload_pending")),
    ("daemon_found_not_bool", lambda s: s["sshd"]["v"]["daemon"].update(found=1)),
    ("daemon_masters_negative", lambda s: s["sshd"]["v"]["daemon"].update(masters=-1)),
    ("daemon_config_path_relative", lambda s: s["sshd"]["v"]["daemon"].update(config_path="etc/ssh/x")),
    ("daemon_config_path_with_space", lambda s: s["sshd"]["v"]["daemon"].update(config_path="/etc/ssh/a b")),
    ("daemon_epoch_float", lambda s: s["sshd"]["v"]["daemon"].update(config_mtime=1.5)),
    ("truncated_null", lambda s: s["sshd"]["v"].update(truncated=None)),
    ("truncated_empty", lambda s: s["sshd"]["v"].update(truncated=[])),
    ("truncated_unknown_key", lambda s: s["sshd"]["v"].update(truncated=["passwordauthentication"])),
    ("truncated_not_a_list", lambda s: s["sshd"]["v"].update(truncated="allowusers")),
    ("delta_key_not_lowercase", lambda s: s["sshd"]["v"]["probes"]["deltas"].append(
        {"user": "root", "addr": "203.0.113.7", "delta": {"MaxAuthTries": 10}})),
    ("delta_key_not_a_word", lambda s: s["sshd"]["v"]["probes"]["deltas"].append(
        {"user": "root", "addr": "203.0.113.7", "delta": {"max auth": 10}})),
    ("dropped_zero", lambda s: s["listeners"]["v"].update(dropped=0)),
    ("dropped_null", lambda s: s["listeners"]["v"].update(dropped=None)),
    ("dropped_bool", lambda s: s["listeners"]["v"].update(dropped=True)),
    ("dropped_string", lambda s: s["listeners"]["v"].update(dropped="5")),
    ("dropped_negative", lambda s: s["listeners"]["v"].update(dropped=-3)),
])
def test_i1_the_new_keys_are_strict_not_merely_allowed(label, mutate):
    """Accepting the keys must not loosen the models: a daemon block that is absent or has a stray or missing key,
    and a ``truncated``/``dropped`` of the wrong shape, are still refused (``extra=forbid``, strict types)."""
    with pytest.raises(fp.PayloadError) as exc:
        fp.validate_posture(_posture_with(mutate))
    assert exc.value.reason in ("payload_schema", "payload_not_json")      # a float is not even strict JSON here


def test_i1_a_probe_delta_with_lowercase_config_names_is_accepted():
    """The real agent's deltas name the allowlisted (lower-case) sshd keys; the strict key check must let them by."""
    def delta(s):
        s["sshd"]["v"]["probes"]["deltas"].append(
            {"user": "<nonexistent>", "addr": "10.255.255.1", "delta": {"maxauthtries": 10, "x11forwarding": None,
                                                                         "allowusers": ["a", "b"]}})
    parsed = fp.validate_posture(_posture_with(delta))
    assert parsed["sections"]["sshd"]["v"]["probes"]["deltas"][0]["delta"]["maxauthtries"] == 10


def test_i1_the_reference_posture_with_the_new_keys_is_accepted():
    """The strict tests above are only meaningful if the unmutated posture is accepted."""
    def both(s):
        s["sshd"]["v"]["truncated"] = ["allowusers", "port"]
        s["listeners"]["v"]["dropped"] = 7
        s["listeners"]["partial"] = True
    parsed = fp.validate_posture(_posture_with(both))
    assert parsed["sections"]["listeners"]["v"]["dropped"] == 7


def test_i1_the_agent_and_the_server_agree_on_the_seq_cap_and_the_collector_name_charset():
    """The contract's two envelope limits that the agent and the server each enforce: the last integer RFC 8785
    prints exactly, and ASCII-only collector names (the sort order differs between code points and UTF-16 units)."""
    from paddock_agent import envelope as ae

    assert ae.MAX_SEQ == fp.MAX_SEQ == 2 ** 53 - 1
    assert ae._COLLECTOR_KEY_RE.pattern.strip("^$") == fp._COLLECTOR_KEY_RE.pattern
    assert ae._HEADER_FIELDS == fp._HEADER_FIELDS
    for good in ("sshd", "a.b_c-1", "x" * 64):
        assert fp._COLLECTOR_KEY_RE.fullmatch(good) and ae._COLLECTOR_KEY_RE.fullmatch(good)
    for bad in ("", "Sshd", "x" * 65, "sshd\n", "sshé", "a b"):
        assert not fp._COLLECTOR_KEY_RE.fullmatch(bad) and not ae._COLLECTOR_KEY_RE.fullmatch(bad)


# ---- the whole path, with the verdicts -------------------------------------------------------------------------- #

async def _verdicts_for(w: World, mutate=None, *, hostname: str = "web-1", **host_kw) -> tuple[dict, dict]:
    """Enroll a real agent on a fixture host, post its real posture, evaluate; ``(ack, verdicts)``."""
    host = FixtureHost(w.tmp / f"host-{hostname}", hostname=hostname, **host_kw)
    if mutate is not None:
        mutate(host)
    rt = runtime(w, hostname, host=host)
    await rt.enroll((await mint(w))["token"])
    ack = await rt.posture()
    assert ack["ok"] and ack["stored"], ack
    await enable_std(w)
    await evaluate(w)
    return ack, await verdicts(w)


async def test_i1_a_clean_host_holds_and_a_bad_host_is_violated_end_to_end(world: World):
    """The real collectors, the real signed envelope, the real ASGI app, the builder and the library."""
    _, v = await _verdicts_for(world)
    assert v == {SSH: "HOLDS", FWD: "HOLDS"}
    res = (await invariant(world, SSH))["last_result"]
    assert res["evidence_tier"] == "configured" and res["hosts"] == {"selected": 1, "holds": 1, "violated": 0,
                                                                     "unknown": 0}


async def test_i1_a_bad_host_is_violated_with_a_finding(world: World):
    _, v = await _verdicts_for(world, lambda h: setattr(h, "password_auth", "yes"))
    assert v == {SSH: "VIOLATED", FWD: "HOLDS"}
    f = await findings(world, SSH)
    assert len(f) == 1 and f[0]["status"] == "open"


async def test_i1_an_open_firewall_is_violated_end_to_end(world: World):
    _, v = await _verdicts_for(world, nft=sup.open_nft())
    assert v[FWD] == "VIOLATED" and v[SSH] == "HOLDS"


@pytest.mark.parametrize("name,mutate,host_kw", [
    ("no running sshd found", _no_daemon, {}),
    ("a config value the collector cut", _many_names, {}),
    ("sshd -T failed, files parsed", _text_source, {}),
])
async def test_i1_incomplete_ssh_evidence_is_unknown_never_holds(world: World, name, mutate, host_kw):
    """Accepting the posture is not trusting it: without positive evidence that the daemon runs the files, or with a
    value that was cut, the ssh invariant must read UNKNOWN. A false HOLDS is the one outcome that is never allowed."""
    _, v = await _verdicts_for(world, mutate, **host_kw)
    assert v[SSH] == "UNKNOWN", (name, v)
    assert await findings(world, SSH) == []


async def test_i1_a_listener_table_the_agent_had_to_cut_is_carried_into_the_fact_and_never_complete(world: World):
    """2100 listeners exceed the agent's 2000-row cap (``dropped``): the table is a sample, so no claim of absence can
    rest on it. The fact the library reads says so (``dropped``), and the host gets no inbound coverage. The firewall
    default-deny invariant reads only the firewall, so it may still hold."""
    _, v = await _verdicts_for(world, _many_listeners)
    row = await world.db.fetchrow("SELECT payload_raw FROM agent_posture ORDER BY id DESC LIMIT 1")
    body = json.loads(bytes(row["payload_raw"]))
    assert body["sections"]["listeners"]["v"]["dropped"] >= 1 and body["sections"]["listeners"]["partial"] is True
    assert v == {SSH: "HOLDS", FWD: "HOLDS"}
    facts = await world.db.fetchrow("SELECT facts FROM reach_node_facts WHERE source = 'host_fw' AND node_ref LIKE 'agent:%'")
    doc = json.loads(facts["facts"]) if isinstance(facts["facts"], str) else facts["facts"]
    assert doc["listeners"]["partial"] is True and doc["listeners"]["data"]["dropped"] >= 1
    cov = await world.db.fetch("SELECT * FROM reach_coverage WHERE node_ref LIKE 'agent:%'")
    assert cov == [], "a cut listener table must not buy inbound coverage"


def test_i1_a_dropped_count_makes_the_listener_table_incomplete_even_if_the_agent_said_complete():
    """A signed fact is not a true fact: a (forged or buggy) section that says ``partial: false`` and carries a
    ``dropped`` count contradicts itself, and the builder reads the table as incomplete."""
    from app.assurance.builders import host_fw as hf

    from .test_assurance_host_fw import covered, lis_section, one, sections

    secs = sections(listeners=lis_section())
    assert covered(one(secs)) != []                                    # the reference host has coverage
    secs = sections(listeners=lis_section())
    secs["listeners"]["v"]["dropped"] = 3
    assert covered(one(secs)) == []
    fact = hf._compact_listeners(secs["listeners"]["v"])
    assert fact["dropped"] == 3
