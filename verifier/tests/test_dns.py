# SPDX-License-Identifier: Apache-2.0
"""DNS layer: the TXT parser (against the primitive table), resolvers, quorum, the DoH wire format.

Nothing here touches the network: DoH goes through an injected transport, UDP/TCP through loopback sockets.
"""
from __future__ import annotations

import base64
import json
import socket
import struct
import threading
from pathlib import Path

import pytest

from paddock_verify.dns import doh, filefix, resolver, txtparse, udp

SPEC = Path(__file__).resolve().parents[2] / "docs" / "spec" / "containment-attestation-v1"
TXT_VECTORS = json.loads((SPEC / "vectors" / "primitives" / "dns-txt-parse.json").read_text(encoding="ascii"))

KID = "2ceb61e24df5fde7c0ab24b2a2774fa4"
FP = "sha256:2ceb61e24df5fde7c0ab24b2a2774fa4cccecbb50a4b7f487b874c4baf7807a8"
REC = "v=1; kid=%s; fp=%s" % (KID, FP)
NAME = "_paddock-attest.example.com"


# ------------------------------------------------------------------------------------------ TXT parser
@pytest.mark.parametrize("case", TXT_VECTORS["cases"], ids=lambda c: c["id"])
def test_txt_parse_vectors(case):
    res = txtparse.parse_rrset(case["records"])
    exp = case["expect"]
    assert res.too_many == exp["too_many"]
    got = [] if res.too_many else res.records
    assert len(got) == len(exp["records"])
    for g, e in zip(got, exp["records"]):
        assert g.status == e["status"]
        if e["status"] == "ok":
            assert (g.kid, g.fp, g.keys) == (e["kid"], e["fp"], e.get("keys"))
        else:
            assert (g.kid, g.fp, g.keys) == (None, None, None)


def test_build_txt_roundtrip_and_sizes():
    t = txtparse.build_txt(KID, FP)
    assert t == REC and len(t) == 117                      # the contract's measured minimum
    full = txtparse.build_txt(KID, FP, "https://example.com/.well-known/paddock/keys.json")
    assert txtparse.parse_txt([full]).keys == "https://example.com/.well-known/paddock/keys.json"
    assert txtparse.parse_txt([t]).status == "ok"


def test_build_txt_refuses_inconsistent_or_oversized_records():
    with pytest.raises(ValueError):
        txtparse.build_txt(KID, "sha256:" + "0" * 64)       # kid is not the first half of fp
    with pytest.raises(ValueError):
        txtparse.build_txt(KID, FP, "http://example.com/k.json")
    with pytest.raises(ValueError):
        txtparse.build_txt(KID, FP, "https://example.com/" + "a" * 440)      # over the 450 byte hard cap
    with pytest.raises(ValueError):
        txtparse.build_txt("x", FP)


def test_chunking_matches_the_parser():
    long = txtparse.build_txt(KID, FP, "https://example.com/" + "a" * 100)
    chunks = txtparse.chunk_txt(long)
    assert all(len(c) <= 255 for c in chunks) and "".join(chunks) == long
    assert txtparse.parse_txt(chunks).status == "ok"
    assert txtparse.needs_split(long) is (len(long) > 255)


def test_parse_txt_never_raises_on_hostile_input():
    for strings in ([""], ["\x00\xff"], ["v=1;" * 1000], ["=" * 5], ["v=1; kid=%s; fp=%s; é=1" % (KID, FP)], [], [REC] * 3):
        r = txtparse.parse_txt(strings)
        assert r.status in ("ok", "ignored", "malformed")


# ------------------------------------------------------------------------------------------- wire format
def build_response(qname, answers, rcode=0, ad=False, tc=False, qid=0, qr=True, compress=True, qtype=16, extra_flags=0):
    flags = (0x8000 if qr else 0) | 0x0100 | 0x0080 | rcode | (0x0020 if ad else 0) | (0x0200 if tc else 0) | extra_flags
    q = doh.encode_name(qname) + struct.pack(">HH", qtype, 1)
    body = b""
    for owner, rtype, rclass, ttl, rdata in answers:
        if owner == "ptr" and compress:
            name = b"\xc0\x0c"
        elif owner == "ptr":
            name = doh.encode_name(qname)
        else:
            name = doh.encode_name(owner)
        body += name + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata
    head = struct.pack(">HHHHHH", qid, flags, 1, len(answers), 0, 0)
    return head + q + body


def txt_rdata(*chunks):
    return b"".join(bytes([len(c)]) + c for c in chunks)


def test_query_wire_bytes_are_exact():
    q = doh.build_query(NAME, 16, qid=0)
    assert q[:12] == bytes.fromhex("000001000001000000000001")                   # id 0, RD, 1 question, 1 additional
    assert q[12:] == (b"\x0f_paddock-attest\x07example\x03com\x00" + bytes.fromhex("00100001") +
                      bytes.fromhex("00" "0029" "1000" "00" "00" "8000" "0000"))  # OPT: 4096 payload, DO set


def test_encode_name_rejects_bad_names():
    for bad in ("a" * 64 + ".com", "", "a..b", "x" * 130 + "." + "y" * 130, "café.com"):
        with pytest.raises(ValueError):
            doh.encode_name(bad)
    assert doh.encode_name("Example.COM.") == b"\x07Example\x03COM\x00"


def test_parse_single_txt_with_compression_pointer_and_chunks():
    ans = doh.parse_response(build_response(NAME, [("ptr", 16, 1, 300, txt_rdata(REC[:20].encode(), REC[20:].encode()))], ad=True), qid=0,
                             qname=NAME)
    assert ans.status == "ok" and ans.txt == [REC] and ans.ad is True and ans.ttl == 300


def test_parse_two_records_and_uncompressed_owner():
    r = build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(b"a=1")), (NAME, 16, 1, 30, txt_rdata(b"b=2"))], compress=False)
    ans = doh.parse_response(r, qid=0, qname=NAME)
    assert ans.status == "ok" and ans.txt == ["a=1", "b=2"] and ans.ttl == 30 and ans.ad is False


def test_parse_rcodes_and_nodata():
    assert doh.parse_response(build_response(NAME, [], rcode=3), 0, NAME).status == "nxdomain"
    assert doh.parse_response(build_response(NAME, [], rcode=0), 0, NAME).status == "nodata"
    assert doh.parse_response(build_response(NAME, [], rcode=2), 0, NAME).status == "servfail"
    assert doh.parse_response(build_response(NAME, [], rcode=5), 0, NAME).status == "error"        # REFUSED is not an answer
    # an answer section that holds only other record types is NODATA, never records
    r = build_response(NAME, [("ptr", 1, 1, 60, b"\x01\x02\x03\x04")])
    assert doh.parse_response(r, 0, NAME).status == "nodata"
    r = build_response(NAME, [("ptr", 16, 3, 60, txt_rdata(b"x=1"))])                             # class CH
    assert doh.parse_response(r, 0, NAME).status == "nodata"


def test_parse_follows_cname_to_txt_and_ignores_foreign_owner():
    cname_target = doh.encode_name("host.example.net")
    r = build_response(NAME, [("ptr", 5, 1, 60, cname_target), ("host.example.net", 16, 1, 60, txt_rdata(b"c=3"))], compress=True)
    assert doh.parse_response(r, 0, NAME).txt == ["c=3"]
    r = build_response(NAME, [("other.example.org", 16, 1, 60, txt_rdata(b"evil=1"))])
    assert doh.parse_response(r, 0, NAME).status == "nodata"


@pytest.mark.parametrize("mutate", [
    lambda b: b[:11],                                    # shorter than a header
    lambda b: b[:-3],                                    # rdata cut off
    lambda b: b[:20],                                    # inside the question
    lambda b: b + b"\x00",                               # trailing byte after the last record is tolerated? no: strict
])
def test_parse_truncated_or_trailing_is_error(mutate):
    good = build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(b"x=1"))])
    assert doh.parse_response(good, 0, NAME).status == "ok"
    assert doh.parse_response(mutate(good), 0, NAME).status == "error"


def test_parse_rejects_wrong_id_non_response_and_truncated_flag():
    good = build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(b"x=1"))], qid=7)
    assert doh.parse_response(good, 7, NAME).status == "ok"
    assert doh.parse_response(good, 8, NAME).status == "error"                          # id mismatch
    assert doh.parse_response(build_response(NAME, [], qr=False), 0, NAME).status == "error"
    t = doh.parse_response(build_response(NAME, [], tc=True), 0, NAME)
    assert t.status == "error" and getattr(t, "truncated", False) is True


def test_parse_question_must_match():
    good = build_response("_paddock-attest.other.com", [("ptr", 16, 1, 60, txt_rdata(b"x=1"))])
    assert doh.parse_response(good, 0, NAME).status == "error"


def test_parse_pointer_loops_forward_pointers_and_bad_labels_are_errors():
    head = struct.pack(">HHHHHH", 0, 0x8180, 1, 1, 0, 0)
    q = doh.encode_name(NAME) + struct.pack(">HH", 16, 1)
    base = len(head) + len(q)
    loop = head + q + struct.pack(">H", 0xC000 | base) + struct.pack(">HHIH", 16, 1, 60, 0)             # points at itself
    assert doh.parse_response(loop, 0, NAME).status == "error"
    fwd = head + q + struct.pack(">H", 0xC000 | (base + 40)) + struct.pack(">HHIH", 16, 1, 60, 0) + b"\x00" * 60
    assert doh.parse_response(fwd, 0, NAME).status == "error"
    badlabel = head + q + b"\x40abc" + struct.pack(">HHIH", 16, 1, 60, 0)                               # 0x40 label type
    assert doh.parse_response(badlabel, 0, NAME).status == "error"


def test_parse_rdlength_overrun_and_chunk_overrun_are_errors():
    r = build_response(NAME, [("ptr", 16, 1, 60, b"\x09abc")])                         # chunk says 9 bytes, 3 present
    assert doh.parse_response(r, 0, NAME).status == "error"


def test_parse_oversize_response_is_error():
    big = build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(b"a" * 255)) for _ in range(20)])
    assert len(big) > 4096
    assert doh.parse_response(big, 0, NAME).status == "error"


def test_parse_non_ascii_txt_is_kept_for_the_parser_to_reject():
    r = build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(b"x=\xc3\xa9"))])
    ans = doh.parse_response(r, 0, NAME)
    assert ans.status == "ok" and txtparse.parse_txt(ans.txt).status == "malformed"


# --------------------------------------------------------------------------------------------- DoH client
def test_doh_resolver_uses_get_with_unpadded_base64url_and_accept_header():
    seen = {}

    def transport(url, headers, timeout, max_bytes):
        seen.update(url=url, headers=headers, timeout=timeout, max_bytes=max_bytes)
        return build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(REC.encode()))], ad=True)

    r = doh.DohResolver("https://doh.test/dns-query", transport=transport)
    ans = r.resolve_txt(NAME, 3.5)
    assert ans.status == "ok" and ans.txt == [REC] and ans.ad is True and ans.source == "doh:https://doh.test/dns-query"
    url, qs = seen["url"].split("?dns=")
    assert url == "https://doh.test/dns-query" and "=" not in qs and "+" not in qs and "/" not in qs
    assert base64.urlsafe_b64decode(qs + "=" * (-len(qs) % 4)) == doh.build_query(NAME, 16, qid=0)
    assert seen["headers"]["Accept"] == "application/dns-message" and seen["timeout"] == 3.5 and seen["max_bytes"] == 4096


def test_doh_resolver_transport_failure_is_timeout_or_error_not_exception():
    def boom(url, headers, timeout, max_bytes):
        raise socket.timeout()

    assert doh.DohResolver("https://doh.test/q", transport=boom).resolve_txt(NAME, 1).status == "timeout"

    def boom2(url, headers, timeout, max_bytes):
        raise OSError("down")

    assert doh.DohResolver("https://doh.test/q", transport=boom2).resolve_txt(NAME, 1).status == "error"


def test_doh_resolver_refuses_non_https():
    with pytest.raises(ValueError):
        doh.DohResolver("http://doh.test/q")
    with pytest.raises(ValueError):
        doh.DohResolver("https://user:pw@doh.test/q")


def test_default_doh_set_is_cloudflare_and_google():
    urls = [r.url for r in doh.default_resolvers()]
    assert urls == ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]


# ---------------------------------------------------------------------------------------------- UDP / TCP
class LoopbackDns(object):
    """A one-shot UDP+TCP DNS server on 127.0.0.1 answering from a function."""

    def __init__(self, answer_udp, answer_tcp=None):
        self.answer_udp, self.answer_tcp = answer_udp, answer_tcp
        self.usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.usock.bind(("127.0.0.1", 0))
        self.port = self.usock.getsockname()[1]
        self.tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tsock.bind(("127.0.0.1", self.port))
        self.tsock.listen(1)
        self.queries = []
        self.threads = [threading.Thread(target=self._udp, daemon=True), threading.Thread(target=self._tcp, daemon=True)]
        for t in self.threads:
            t.start()

    def _udp(self):
        try:
            data, addr = self.usock.recvfrom(4096)
        except OSError:
            return
        self.queries.append(("udp", data))
        out = self.answer_udp(data)
        if out is not None:
            self.usock.sendto(out, addr)

    def _tcp(self):
        try:
            conn, _ = self.tsock.accept()
        except OSError:
            return
        with conn:
            ln = conn.recv(2)
            data = conn.recv(struct.unpack(">H", ln)[0])
            self.queries.append(("tcp", data))
            out = (self.answer_tcp or self.answer_udp)(data)
            conn.sendall(struct.pack(">H", len(out)) + out)

    def close(self):
        for s in (self.usock, self.tsock):
            s.close()


def _echo_id(resp_builder):
    def fn(query):
        qid = struct.unpack(">H", query[:2])[0]
        return resp_builder(qid)
    return fn


def test_udp_resolver_answers_over_udp():
    srv = LoopbackDns(_echo_id(lambda qid: build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(REC.encode()))], qid=qid)))
    try:
        ans = udp.UdpResolver("127.0.0.1", srv.port).resolve_txt(NAME, 2.0)
    finally:
        srv.close()
    assert ans.status == "ok" and ans.txt == [REC] and ans.source == "udp:127.0.0.1:%d" % srv.port
    assert ans.ad is None                                  # a plaintext channel can say nothing about validation
    assert srv.queries[0][0] == "udp" and srv.queries[0][1][2:4] != b"\x00\x00"


def test_udp_resolver_falls_back_to_tcp_on_truncation():
    srv = LoopbackDns(_echo_id(lambda qid: build_response(NAME, [], tc=True, qid=qid)),
                      _echo_id(lambda qid: build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(REC.encode()))], qid=qid)))
    try:
        ans = udp.UdpResolver("127.0.0.1", srv.port).resolve_txt(NAME, 2.0)
    finally:
        srv.close()
    assert ans.status == "ok" and ans.txt == [REC]
    assert [q[0] for q in srv.queries] == ["udp", "tcp"]


def test_udp_resolver_timeout_and_wrong_id():
    srv = LoopbackDns(lambda q: None)
    try:
        assert udp.UdpResolver("127.0.0.1", srv.port).resolve_txt(NAME, 0.3).status == "timeout"
    finally:
        srv.close()
    srv = LoopbackDns(lambda q: build_response(NAME, [("ptr", 16, 1, 60, txt_rdata(b"x=1"))], qid=0xBEEF))
    try:
        assert udp.UdpResolver("127.0.0.1", srv.port).resolve_txt(NAME, 0.5).status in ("timeout", "error")
    finally:
        srv.close()


def test_system_resolver_reads_nameservers_and_never_raises(tmp_path):
    rc = tmp_path / "resolv.conf"
    rc.write_text("# c\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch example.org\noptions ndots:2\n")
    assert udp.read_nameservers(str(rc)) == ["192.0.2.53", "2001:db8::53"]
    assert udp.read_nameservers(str(tmp_path / "missing")) == []
    ans = udp.SystemResolver(resolv_conf=str(tmp_path / "missing")).resolve_txt(NAME, 0.2)
    assert ans.status == "error" and ans.source == "system"


# ----------------------------------------------------------------------------------- file fixtures + specs
def test_file_resolver_fixture_formats(tmp_path):
    p = tmp_path / "fx.json"
    p.write_text(json.dumps({"resolver": "fx1", "ad": True, "answers": {
        NAME: {"status": "ok", "txt": [REC, [REC[:10], REC[10:]]], "ttl": 120},
        "_paddock-attest.nodata.example": {"status": "nodata", "txt": []},
        "_paddock-attest.sf.example": {"status": "servfail"},
        "_paddock-attest.noad.example": {"status": "ok", "txt": [REC], "ad": False}}}))
    r = filefix.FileResolver(str(p))
    ans = r.resolve_txt(NAME, 1)
    assert (ans.status, ans.txt, ans.ad, ans.ttl, ans.source) == ("ok", [REC, REC], True, 120, "file:fx1")
    assert r.resolve_txt("_paddock-attest.nodata.example", 1).status == "nodata"
    assert r.resolve_txt("_paddock-attest.sf.example", 1).status == "servfail"
    assert r.resolve_txt("_paddock-attest.noad.example", 1).ad is False
    assert r.resolve_txt("_paddock-attest.unlisted.example", 1).status == "nxdomain"            # an absent name does not exist
    assert r.resolve_txt(NAME.upper(), 1).status == "ok"                                        # names are case-insensitive


def test_file_resolver_rejects_bad_fixtures(tmp_path):
    for text in ("not json", "[]", '{"answers": 3}', '{"answers": {"x": {"status": "weird"}}}',
                 '{"answers": {"x": {"status": "ok", "txt": [5]}}}', '{"answers": {"x": {"status": "ok"}}, "answers": {}}'):
        p = tmp_path / "bad.json"
        p.write_text(text)
        with pytest.raises(filefix.FixtureError):
            filefix.FileResolver(str(p))
    with pytest.raises(filefix.FixtureError):
        filefix.FileResolver(str(tmp_path / "does-not-exist.json"))


def test_parse_resolver_specs(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('{"answers": {}}')
    rs = resolver.parse_specs(["doh:https://x.test/q", "udp:192.0.2.1", "udp:192.0.2.2:5353", "system", "file:%s" % p])
    assert [type(r).__name__ for r in rs] == ["DohResolver", "UdpResolver", "UdpResolver", "SystemResolver", "FileResolver"]
    assert rs[2].port == 5353 and rs[1].port == 53
    for bad in ("", "doh:", "doh:http://x", "udp:", "udp:not-an-ip", "udp:1.2.3.4:99999", "ftp:x", "file:", "system:x"):
        with pytest.raises(ValueError):
            resolver.parse_specs([bad])


def test_offline_filter_keeps_only_resolvers_without_network(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('{"answers": {}}')
    rs = resolver.parse_specs(["doh:https://x.test/q", "file:%s" % p, "udp:192.0.2.1", "system"])
    kept = [type(r).__name__ for r in resolver.offline_safe(rs)]
    assert kept == ["FileResolver"]


# ---------------------------------------------------------------------------------------- quorum / agreement
def A(status="ok", txt=(REC,), ad=None, source="r"):
    return resolver.DnsAnswer(status, list(txt), ad, source)


def test_quorum_all_agree():
    q = resolver.quorum([A(source="a"), A(source="b")], min_resolvers=2)
    assert q.error is None and q.records == [REC] and q.answered == 2


def test_quorum_disagreement_is_unverifiable_never_pick_the_match():
    other = "v=1; kid=%s; fp=sha256:%s%s" % (KID, KID, "0" * 32)
    q = resolver.quorum([A(source="a"), A(txt=(other,), source="b")], 2)
    assert q.error == "dns.resolvers_disagree"
    q = resolver.quorum([A(source="a"), A(status="nxdomain", txt=(), source="b")], 2)
    assert q.error == "dns.resolvers_disagree"


def test_quorum_record_order_and_chunk_joins_do_not_matter_but_content_does():
    a = A(txt=("a=1", "b=2"))
    b = A(txt=("b=2", "a=1"))
    assert resolver.quorum([a, b], 2).error is None
    c = A(txt=("a=1", "b=3"))
    assert resolver.quorum([a, c], 2).error == "dns.resolvers_disagree"


def test_quorum_nxdomain_and_nodata_agree_as_no_records():
    q = resolver.quorum([A(status="nxdomain", txt=()), A(status="nodata", txt=())], 2)
    assert q.error is None and q.records == [] and q.status == "none"


def test_quorum_counts_only_definitive_answers():
    q = resolver.quorum([A(source="a"), A(status="timeout", txt=(), source="b")], 2)
    assert q.error == "dns.insufficient_resolvers" and q.answered == 1
    q = resolver.quorum([A(source="a"), A(status="timeout", txt=(), source="b")], 1)
    assert q.error is None and q.records == [REC]
    q = resolver.quorum([A(status="servfail", txt=()), A(status="error", txt=())], 1)
    assert q.error == "dns.lookup_failed" and q.answered == 0
    assert resolver.quorum([], 1).error == "dns.lookup_failed"


def test_quorum_ad_aggregation():
    assert resolver.quorum([A(ad=True), A(ad=True)], 2).ad == "ad_asserted"
    assert resolver.quorum([A(ad=True), A(ad=False)], 2).ad == "not_asserted"
    assert resolver.quorum([A(ad=True), A(ad=None)], 2).ad == "unknown"
    assert resolver.quorum([A(ad=False), A(ad=None)], 2).ad == "not_asserted"
    assert resolver.quorum([A(ad=None)], 1).ad == "unknown"
    assert resolver.quorum([A(ad=True), A(status="timeout", txt=(), ad=None)], 1).ad == "ad_asserted"   # only answers count


def test_resolver_set_default_min_resolvers():
    rs = resolver.ResolverSet(doh.default_resolvers())
    assert rs.min_resolvers == 2 and rs.is_default
    custom = resolver.ResolverSet([resolver.FakeResolver({})])
    assert custom.min_resolvers == 1 and not custom.is_default
    assert resolver.ResolverSet([resolver.FakeResolver({})], min_resolvers=3).min_resolvers == 3
    with pytest.raises(ValueError):
        resolver.ResolverSet([], min_resolvers=1)


def test_fake_resolver_and_set_lookup():
    f1 = resolver.FakeResolver({NAME: A(source="f1")}, name="f1")
    f2 = resolver.FakeResolver({}, name="f2")
    q = resolver.ResolverSet([f1, f2], min_resolvers=1).lookup(NAME, 1.0)
    assert q.error == "dns.resolvers_disagree"                                  # one has the record, the other says nothing exists
    q = resolver.ResolverSet([f1], min_resolvers=1).lookup(NAME, 1.0)
    assert q.error is None and q.records == [REC]


def test_resolver_exceptions_become_error_answers():
    class Boom(object):
        name = "boom"

        def resolve_txt(self, qname, timeout):
            raise RuntimeError("bug")

    q = resolver.ResolverSet([Boom()], min_resolvers=1).lookup(NAME, 1.0)
    assert q.error == "dns.lookup_failed"
