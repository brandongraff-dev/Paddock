# SPDX-License-Identifier: Apache-2.0
"""DNS wire format (RFC 1035, EDNS0 RFC 6891) and the DoH resolver (RFC 8484), standard library only.

The query is hand built with EDNS0 and the DO bit; the response parser handles name compression pointers (only
backward ones, so a loop is impossible), follows a CNAME chain to the TXT records, caps a message at 4 KiB, and
never raises: anything unexpected is an ``error`` answer. The AD flag is reported as the resolver's claim.
"""
from __future__ import annotations

import base64
import socket
import ssl
import struct
import http.client
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple

from .. import fetch
from .resolver import DnsAnswer

MAX_MESSAGE = 4096
TYPE_TXT, TYPE_CNAME, CLASS_IN = 16, 5, 1
_MAX_NAME_WIRE = 255
DEFAULT_URLS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query")


def encode_name(qname: str) -> bytes:
    if not isinstance(qname, str):
        raise ValueError("a name is a string")
    try:
        raw = qname.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("a DNS name here is ASCII (use the A-label form)") from None
    if raw.endswith(b"."):
        raw = raw[:-1]
    if not raw:
        raise ValueError("empty name")
    out = b""
    for label in raw.split(b"."):
        if not 1 <= len(label) <= 63:
            raise ValueError("a label is 1 to 63 bytes")
        out += bytes([len(label)]) + label
    out += b"\x00"
    if len(out) > _MAX_NAME_WIRE:
        raise ValueError("name too long")
    return out


def build_query(qname: str, qtype: int = TYPE_TXT, qid: int = 0) -> bytes:
    """A recursive query with one EDNS0 OPT record advertising 4096 bytes and DO=1."""
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    question = encode_name(qname) + struct.pack(">HH", qtype, CLASS_IN)
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)          # root name, OPT, payload size, ext-rcode/version/flags (DO)
    return header + question + opt


class _Bad(Exception):
    pass


def _read_name(msg: bytes, pos: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) name at ``pos``. Returns (lowercase dotted text, position after the name)."""
    labels = []  # type: List[str]
    end = None   # type: Optional[int]
    total = 0
    jumps = 0
    while True:
        if pos >= len(msg):
            raise _Bad("name runs off the message")
        ln = msg[pos]
        if ln == 0:
            pos += 1
            break
        kind = ln & 0xC0
        if kind == 0xC0:
            if pos + 1 >= len(msg):
                raise _Bad("pointer runs off the message")
            target = ((ln & 0x3F) << 8) | msg[pos + 1]
            if target >= pos:
                raise _Bad("pointer does not go backward")
            if end is None:
                end = pos + 2
            jumps += 1
            if jumps > 32:
                raise _Bad("too many pointers")
            pos = target
            continue
        if kind != 0:
            raise _Bad("unsupported label type")
        if pos + 1 + ln > len(msg):
            raise _Bad("label runs off the message")
        total += ln + 1
        if total > _MAX_NAME_WIRE:
            raise _Bad("name too long")
        labels.append(msg[pos + 1:pos + 1 + ln].decode("latin-1").lower())
        pos += 1 + ln
    return ".".join(labels), (end if end is not None else pos)


def parse_response(data: bytes, qid: int, qname: str, source: str = "doh") -> DnsAnswer:
    """Turn a response message into a DnsAnswer. Never raises."""
    try:
        return _parse(bytes(data), qid, qname, source)
    except _Bad:
        return DnsAnswer("error", [], None, source)
    except Exception:
        return DnsAnswer("error", [], None, source)


def _parse(msg: bytes, qid: int, qname: str, source: str) -> DnsAnswer:
    if len(msg) > MAX_MESSAGE or len(msg) < 12:
        raise _Bad("size")
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000 or (flags >> 11) & 0xF != 0 or qd != 1:
        raise _Bad("not the response to our query")
    if flags & 0x0200:
        return DnsAnswer("error", [], None, source, None, True)
    name, pos = _read_name(msg, 12)
    if pos + 4 > len(msg):
        raise _Bad("short question")
    qtype, qclass = struct.unpack(">HH", msg[pos:pos + 4])
    pos += 4
    if name != qname.lower().rstrip(".") or qtype != TYPE_TXT or qclass != CLASS_IN:
        raise _Bad("question differs")
    rcode = flags & 0xF
    records = []  # type: List[Tuple[str, int, int, int, int, int]]   # owner, type, class, ttl, rdata start, rdata end
    for _ in range(an + ns + ar):
        owner, pos = _read_name(msg, pos)
        if pos + 10 > len(msg):
            raise _Bad("short record")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(msg):
            raise _Bad("rdata runs off the message")
        records.append((owner, rtype, rclass, ttl, pos, pos + rdlen))
        pos += rdlen
    if pos != len(msg):
        raise _Bad("trailing bytes")
    ad = bool(flags & 0x0020)
    if rcode == 3:
        return DnsAnswer("nxdomain", [], ad, source)
    if rcode == 2:
        return DnsAnswer("servfail", [], ad, source)
    if rcode != 0:
        return DnsAnswer("error", [], None, source)
    answers = records[:an]
    owners = {name}
    grew = True
    while grew:
        grew = False
        for owner, rtype, rclass, _ttl, start, end in answers:
            if rtype == TYPE_CNAME and rclass == CLASS_IN and owner in owners:
                target, after = _read_name(msg, start)
                if after != end:
                    raise _Bad("bad CNAME rdata")
                if target not in owners:
                    owners.add(target)
                    grew = True
    txt = []  # type: List[str]
    ttls = []  # type: List[int]
    for owner, rtype, rclass, ttl, start, end in answers:
        if rtype != TYPE_TXT or rclass != CLASS_IN or owner not in owners:
            continue
        p, chunks = start, []
        while p < end:
            ln = msg[p]
            if p + 1 + ln > end:
                raise _Bad("character string runs off the rdata")
            chunks.append(msg[p + 1:p + 1 + ln])
            p += 1 + ln
        txt.append(b"".join(chunks).decode("latin-1"))
        ttls.append(ttl)
    if not txt:
        return DnsAnswer("nodata", [], ad, source)
    return DnsAnswer("ok", txt, ad, source, min(ttls))


Transport = Callable[[str, Dict[str, str], float, int], bytes]


def _https_transport(url: str, headers: Dict[str, str], timeout: float, max_bytes: int) -> bytes:
    """GET over TLS (host name checked), no redirects, under one wall-clock deadline for connect, headers and body."""
    parts = urllib.parse.urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    if parts.scheme != "https" or not host:
        raise OSError("a DoH endpoint is an https URL")
    target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    ctx = ssl.create_default_context()
    dl = fetch.Deadline(timeout)
    raw = tls = conn = None
    try:
        raw = fetch.bounded_call(lambda: socket.create_connection((host, port), timeout=dl.remaining()), dl.remaining())
        tls = ctx.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
        dl.watch(tls)
        tls.settimeout(dl.remaining())
        tls.do_handshake()
        conn = http.client.HTTPSConnection(host, port, timeout=dl.remaining(), context=ctx)
        conn.sock = tls
        status, _hdrs, body = fetch.read_exchange(conn, target, headers, max_bytes, dl)
    except Exception:
        if dl.expired():
            raise socket.timeout("deadline") from None
        raise
    finally:
        dl.close()
        for c in (conn, tls, raw):
            try:
                if c is not None:
                    c.close()
            except OSError:
                pass
    if status != 200:                                                # a redirect or any other status is a failure
        raise OSError("HTTP %d" % status)
    if len(body) > max_bytes:
        raise OSError("response over %d bytes" % max_bytes)
    return body


class DohResolver(object):
    network = True

    def __init__(self, url: str, transport: Optional[Transport] = None) -> None:
        if not isinstance(url, str) or not url.startswith("https://") or len(url) <= len("https://"):
            raise ValueError("a DoH endpoint is an https:// URL")
        rest = url[len("https://"):].split("/", 1)[0]
        if "@" in rest or any(ord(c) < 0x21 or ord(c) > 0x7E for c in url):
            raise ValueError("a DoH URL carries no credentials")
        self.url = url
        self.name = "doh:" + url
        self._transport = transport or _https_transport

    def resolve_txt(self, qname: str, timeout: float) -> DnsAnswer:
        try:
            query = build_query(qname, TYPE_TXT, qid=0)
        except ValueError:
            return DnsAnswer("error", [], None, self.name)
        dns = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
        url = self.url + ("&" if "?" in self.url else "?") + "dns=" + dns
        try:
            body = self._transport(url, {"Accept": "application/dns-message", "Accept-Encoding": "identity"}, timeout, MAX_MESSAGE)
        except (socket.timeout, TimeoutError):
            return DnsAnswer("timeout", [], None, self.name)
        except Exception:
            return DnsAnswer("error", [], None, self.name)
        a = parse_response(body, 0, qname, self.name)
        return a


def default_resolvers() -> List[DohResolver]:
    return [DohResolver(u) for u in DEFAULT_URLS]
