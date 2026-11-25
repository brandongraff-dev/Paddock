"""Regression tests for the P2 adversarial review (coll-8, coll-9): the listeners collector."""
import sys

from paddock_agent.collectors import base, listeners

from .helpers import make_ctx
from .test_listeners import U, enc6, fake_proc, line4


# ------------------------------------------------------------------------- coll-8
def test_coll8_little_endian_is_unchanged(monkeypatch):
    monkeypatch.setattr(sys, "byteorder", "little")
    assert listeners.decode_addr("0100007F") == ("127.0.0.1", 4)
    assert listeners.decode_addr(enc6("fe80::1234")) == ("fe80::1234", 6)


def test_coll8_big_endian_hosts_print_network_order(monkeypatch):
    # on a big-endian kernel the %08X of the in-memory u32 IS the network order
    monkeypatch.setattr(sys, "byteorder", "big")
    assert listeners.decode_addr("7F000001") == ("127.0.0.1", 4)
    assert listeners.decode_addr("0A010203") == ("10.1.2.3", 4)
    assert listeners.decode_addr("00000000") == ("0.0.0.0", 4)
    assert listeners.decode_addr("00000000000000000000000000000001") == ("::1", 6)
    assert listeners.decode_addr("20010DB8000000000000000000000001") == ("2001:db8::1", 6)
    rows, bad = listeners.parse_proc_net(line4(0, "7F000001", 80, 5), "tcp", 4)
    assert bad == 0 and rows[0]["bind_class"] == "loopback"


# ------------------------------------------------------------------------- coll-9
def _table(rows):
    """rows: (hexip, port) -> a /proc/net/tcp body with unique inodes."""
    return "  sl  local_address rem_address   st\n" + "".join(
        line4(i, hexip, port, 1000 + i) for i, (hexip, port) in enumerate(rows))


def test_coll9_over_the_cap_keeps_a_prioritised_sample_and_stays_partial(tmp_path):
    loop = [("0100007F", 10000 + i) for i in range(1500)]
    wild = [("00000000", 20000 + i) for i in range(700)]
    spec = [("0201A8C0", 30000 + i) for i in range(300)]
    priv = [("00000000", p) for p in (22, 80, 443)] + [("0201A8C0", 25)]
    sec = listeners.collect(fake_proc(tmp_path, tcp=_table(loop + wild + spec + priv)))
    base.validate_section(sec)
    assert sec["s"] == "ok" and sec["partial"] is True
    v = sec["v"]
    assert v["count"] == listeners.MAX_LISTENERS == len(v["listeners"])
    ports = [l["port"] for l in v["listeners"]]
    assert ports == sorted(ports)
    assert {22, 80, 443, 25} <= set(ports)                                   # privileged: never cut
    assert all(20000 + i in ports for i in range(700))                       # wildcard: never cut
    assert sum(1 for l in v["listeners"] if l["bind_class"] == "loopback") == 2000 - 4 - 700 - 300
    assert v["dropped"] == 2504 - 2000


def test_coll9_exactly_at_the_cap_is_complete_and_has_no_dropped_key(tmp_path):
    sec = listeners.collect(fake_proc(tmp_path, tcp=_table([("00000000", 1 + i) for i in range(2000)])))
    assert sec["s"] == "ok" and sec["partial"] is False and "dropped" not in sec["v"]
    assert sec["v"]["count"] == 2000


def test_coll9_local_loopback_flood_cannot_displace_a_wildcard_listener(tmp_path):
    rows = [("0100007F", 1024 + i) for i in range(2100)] + [("00000000", 8080)]
    sec = listeners.collect(fake_proc(tmp_path, tcp=_table(rows)))
    assert sec["partial"] is True and any(l["port"] == 8080 and l["bind_class"] == "wildcard4"
                                          for l in sec["v"]["listeners"])


def test_coll9_attribution_budget_ends_partial_instead_of_timing_out(tmp_path, monkeypatch):
    ctx = fake_proc(tmp_path, procs={9: {"sockets": [1921], "comm": "prog"}})
    ctx.set_deadline(100)
    monkeypatch.setattr(ctx, "time_left", lambda: 1.0)           # the collector budget is nearly spent
    sec = listeners.collect(ctx)
    assert sec["s"] == "ok" and sec["partial"] is True
    assert sec["v"]["attribution"]["status"] in ("partial", "denied")
