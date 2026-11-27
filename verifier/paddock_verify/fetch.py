# SPDX-License-Identifier: Apache-2.0
"""Acquiring a bundle: local directories and files, and HTTPS with the verifier's safety rules (spec/06, 07).

Every byte comes in through a ``Source`` (``read(path, max_bytes)`` returns the bytes, ``None`` for "not there",
and raises ``FetchError`` for anything else), so verification itself is pure and an embedder can inject its own
source. The HTTPS rules: https only, no credentials, no IP-literal host, at most 3 redirects (https to https),
a 10 second timeout over the whole request, ``Accept-Encoding: identity``, byte caps enforced while streaming,
and every resolved address must be a global one unless ``allow_private``. The connection goes to the address
that was validated (not to a second lookup), which closes the check-then-connect race for this client; an
embedder that injects its own transport carries that responsibility itself.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
from typing import Callable, Dict, List, NamedTuple, Optional

from . import limits
from .model import Bundle

_REL = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z", re.ASCII)
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
USER_AGENT = "paddock-verify"
MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 10.0


class FetchError(Exception):
    """Acquisition failed; ``code`` is an ``input.*`` reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__("%s%s" % (code, (": " + detail) if detail else ""))
        self.code = code
        self.detail = detail


def check_relative(path: str) -> str:
    if not isinstance(path, str) or not _REL.match(path) or any(seg in (".", "..") for seg in path.split("/")):
        raise FetchError("input.unreadable", "a bundle path is a plain relative path")
    return path


# ----------------------------------------------------------------------------------------- local sources
class DirSource(object):
    def __init__(self, root: str) -> None:
        self.root = os.path.realpath(root)

    def describe(self) -> str:
        return self.root

    def read(self, path: str, max_bytes: int) -> Optional[bytes]:
        check_relative(path)
        full = os.path.join(self.root, *path.split("/"))
        real = os.path.realpath(full)
        if real != self.root and not real.startswith(self.root + os.sep):
            raise FetchError("input.unreadable", "a path leaves the bundle directory")
        return read_file(real, max_bytes)


class MemorySource(object):
    def __init__(self, files: Dict[str, bytes]) -> None:
        self.files = dict(files)

    def describe(self) -> str:
        return "memory"

    def read(self, path: str, max_bytes: int) -> Optional[bytes]:
        check_relative(path)
        data = self.files.get(path)
        if data is not None and len(data) > max_bytes:
            raise FetchError("input.too_large", "%s is over %d bytes" % (path, max_bytes))
        return data


def read_file(path: str, max_bytes: int) -> Optional[bytes]:
    """The file's bytes, ``None`` when absent or a directory; ``input.too_large`` over the cap."""
    try:
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as e:
        raise FetchError("input.unreadable", e.strerror or "read error") from None
    if len(data) > max_bytes:
        raise FetchError("input.too_large", "a file is over %d bytes" % max_bytes)
    return data


def locate(target: str, keys: Optional[str] = None, revoked: Optional[str] = None, budget: int = limits.MAX_RUN_BYTES,
           **http_kwargs) -> Bundle:
    """The bundle a local or https TARGET names (a domain target is resolved by the caller, which knows the resolvers)."""
    overrides = {}  # type: Dict[str, str]
    for name, path in (("keys.json", keys), ("revoked.json", revoked)):
        if path is not None:
            if not os.path.isfile(path):
                raise FetchError("input.not_found", "%s does not exist" % name)
            overrides[name] = path
    if target.startswith("https://"):
        return Bundle(HttpSource(target, **http_kwargs), "attestation/latest.json", overrides=overrides, label=target, budget=budget)
    if target.lower().startswith("http://"):
        raise FetchError("input.insecure_transport", "https is required")
    if os.path.isdir(target):
        for rel in ("", ".well-known/paddock"):
            root = os.path.join(target, *rel.split("/")) if rel else target
            latest = os.path.join(root, "attestation", "latest.json")
            if os.path.isfile(latest):
                return Bundle(DirSource(root), "attestation/latest.json", overrides=overrides, label=target, budget=budget)
            if os.path.lexists(latest):
                raise FetchError("input.unreadable", "attestation/latest.json is not a regular file")
        raise FetchError("input.not_found", "no attestation/latest.json under the directory")
    if os.path.isfile(target):
        parent = os.path.dirname(os.path.abspath(target))
        root = os.path.dirname(parent) if os.path.basename(parent) == "attestation" else parent
        return Bundle(DirSource(root), None, envelope_file=target, overrides=overrides, label=target, budget=budget)
    if os.path.lexists(target):
        raise FetchError("input.unreadable", "not a regular file or a directory")
    raise FetchError("input.not_found", "no such file or directory")


# --------------------------------------------------------------------------------------------- https
class Deadline(object):
    """One wall-clock bound over a whole network exchange (connect, handshake, headers and body).

    A per-operation socket timeout is not a deadline: a server that sends one byte every few seconds satisfies it
    forever. A watchdog therefore shuts the socket down when the time is up, which wakes any blocked read; the
    caller must then treat the exchange as failed (``expired``), never as a short success.
    """

    def __init__(self, seconds: float) -> None:
        self.end = time.monotonic() + max(0.05, float(seconds))
        self.fired = False
        self._sock = None  # type: Optional[socket.socket]
        self._lock = threading.Lock()
        self._timer = threading.Timer(max(0.05, float(seconds)), self._fire)
        self._timer.daemon = True
        self._timer.start()

    def remaining(self) -> float:
        return max(0.05, self.end - time.monotonic())

    def expired(self) -> bool:
        return self.fired or time.monotonic() > self.end

    def watch(self, sock: socket.socket) -> None:
        with self._lock:
            self._sock = sock
            late = self.fired
        if late:
            self._shutdown(sock)

    @staticmethod
    def _shutdown(sock: socket.socket) -> None:
        try:
            socket.socket.shutdown(sock, socket.SHUT_RDWR)          # not SSLSocket.shutdown: it would drop the TLS object under a reader
        except (OSError, ValueError):
            pass

    def _fire(self) -> None:
        with self._lock:
            self.fired = True
            sock = self._sock
        if sock is not None:
            self._shutdown(sock)

    def close(self) -> None:
        self._timer.cancel()


def bounded_call(fn: Callable, seconds: float):
    """``fn()`` with a wall-clock bound; ``TimeoutError`` when it does not return in time (the thread is abandoned)."""
    box = []  # type: List

    def run() -> None:
        try:
            box.append((True, fn()))
        except BaseException as e:                                  # handed back to the caller's thread
            box.append((False, e))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(max(0.05, seconds))
    if not box:
        raise TimeoutError("deadline")
    ok, value = box[0]
    if not ok:
        raise value
    return value


def read_exchange(conn: "http.client.HTTPSConnection", target: str, headers: Dict[str, str], max_bytes: int, dl: Deadline):
    """GET ``target`` on an open ``conn`` and read at most ``max_bytes + 1`` of the body under ``dl``.

    Returns ``(status, lowercase headers, body)``. Raises ``socket.timeout`` when the deadline passed and ``OSError``
    when the body is shorter than its declared length; a truncated body is never returned as a success.
    """
    conn.request("GET", target, headers=headers)
    r = conn.getresponse()
    chunks, total = [], 0
    while total <= max_bytes:
        if dl.expired():
            raise socket.timeout("deadline")
        piece = r.read(min(8192, max_bytes + 1 - total))
        if not piece:
            break
        chunks.append(piece)
        total += len(piece)
    if dl.expired():
        raise socket.timeout("deadline")
    hdrs = dict((k.lower(), v) for k, v in r.getheaders())
    if total <= max_bytes and "content-length" in hdrs:
        declared = hdrs["content-length"].strip()
        if not declared.isdigit() or int(declared) != total:
            raise OSError("the body is not as long as declared")
    return r.status, hdrs, b"".join(chunks)


class Response(NamedTuple):
    status: int
    headers: Dict[str, str]      # lowercase names
    body: bytes


Transport = Callable[[str, List[str], Dict[str, str], float, int], Response]
Resolve = Callable[[str, int], List[str]]


def _system_resolve(host: str, port: int) -> List[str]:
    return sorted(set(ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))


def _numeric_label(label: str) -> bool:
    return bool(re.match(r"(?:[0-9]+|0[xX][0-9a-fA-F]*)\Z", label))


def _is_global(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def split_url(url: str):
    """(host, port, request target) for an acceptable https URL, else ``input.insecure_transport``."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise FetchError("input.insecure_transport", "unusable URL") from None
    if parts.scheme != "https" or not host or "@" in parts.netloc:
        raise FetchError("input.insecure_transport", "https without credentials is required")
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal or _numeric_label(host.rsplit(".", 1)[-1]) or any(ord(c) < 0x21 or ord(c) > 0x7E for c in url):
        raise FetchError("input.insecure_transport", "a host name is required, not an address")
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return host, (port or 443), target


class HttpSource(object):
    def __init__(self, base: str, timeout: float = DEFAULT_TIMEOUT, allow_private: bool = False, transport: Optional[Transport] = None,
                 resolve: Optional[Resolve] = None, max_redirects: int = MAX_REDIRECTS, ssl_context: Optional[ssl.SSLContext] = None) -> None:
        split_url(base)                                            # refuses a bad base immediately
        self.base = base if base.endswith("/") else base + "/"
        self.timeout = float(timeout)
        self.allow_private = allow_private
        self.max_redirects = max_redirects
        self._resolve = resolve or _system_resolve
        self._ctx = ssl_context
        self._transport = transport or self._tls_transport

    def describe(self) -> str:
        return self.base

    def read(self, path: str, max_bytes: int) -> Optional[bytes]:
        check_relative(path)
        url = self.base + path
        end = time.monotonic() + self.timeout                       # one bound for the whole read, redirects included
        for hop in range(self.max_redirects + 1):
            left = end - time.monotonic()
            if left <= 0:
                raise FetchError("input.fetch_failed", "deadline exceeded")
            host, port, _target = split_url(url)
            ips = self._addresses(host, port, left)
            left = end - time.monotonic()
            if left <= 0:
                raise FetchError("input.fetch_failed", "deadline exceeded")
            try:
                resp = self._transport(url, ips, {"User-Agent": USER_AGENT, "Accept": "application/json", "Accept-Encoding": "identity"},
                                       left, max_bytes)
            except FetchError:
                raise
            except Exception:
                raise FetchError("input.fetch_failed", "network error") from None
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location")
                if not loc:
                    raise FetchError("input.fetch_failed", "redirect without a location")
                url = urllib.parse.urljoin(url, loc)
                continue
            if resp.status in (404, 410):
                return None
            if resp.status != 200:
                raise FetchError("input.fetch_failed", "HTTP %d" % resp.status)
            enc = resp.headers.get("content-encoding", "identity").strip().lower()
            if enc not in ("", "identity"):
                raise FetchError("input.fetch_failed", "a content encoding was applied")
            if len(resp.body) > max_bytes:
                raise FetchError("input.too_large", "%s is over %d bytes" % (path, max_bytes))
            return resp.body
        raise FetchError("input.fetch_failed", "too many redirects")

    def _addresses(self, host: str, port: int, seconds: float = DEFAULT_TIMEOUT) -> List[str]:
        try:
            ips = list(bounded_call(lambda: self._resolve(host, port), seconds))
        except Exception:
            raise FetchError("input.fetch_failed", "name resolution failed") from None
        if not ips:
            raise FetchError("input.fetch_failed", "name resolution returned nothing")
        if not self.allow_private and not all(_is_global(a) for a in ips):
            raise FetchError("input.insecure_transport", "the host resolves to a non-public address")
        return ips

    def _tls_transport(self, url: str, ips: List[str], headers: Dict[str, str], timeout: float, max_bytes: int) -> Response:
        host, port, target = split_url(url)
        ctx = self._ctx or ssl.create_default_context()
        dl = Deadline(timeout)
        raw = tls = None
        conn = None
        try:
            last = None  # type: Optional[Exception]
            for ip in ips:
                if dl.expired():
                    break
                try:
                    raw = socket.create_connection((ip, port), timeout=dl.remaining())
                    break
                except OSError as e:
                    last = e
            if raw is None:
                raise last if last is not None else OSError("no address")
            tls = ctx.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)   # SNI and certificate checks use the host name
            dl.watch(tls)
            tls.settimeout(dl.remaining())
            tls.do_handshake()
            conn = http.client.HTTPSConnection(host, port, timeout=dl.remaining(), context=ctx)
            conn.sock = tls
            status, hdrs, body = read_exchange(conn, target, headers, max_bytes, dl)
            return Response(status, hdrs, body)
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


def default_base(domain: str) -> str:
    return "https://%s/.well-known/paddock/" % domain


def base_from_keys_hint(url: str) -> Optional[str]:
    """The bundle root named by a ``keys=`` hint: the directory of the URL. ``None`` for anything unusable."""
    if not isinstance(url, str) or len(url) > 300 or not url.startswith("https://"):
        return None
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port
    except ValueError:
        return None
    if not parts.hostname or "@" in parts.netloc or parts.query or parts.fragment or not parts.path or parts.path.endswith("/"):
        return None
    return "https://" + parts.netloc + parts.path.rsplit("/", 1)[0] + "/"


def looks_like_domain(text: str) -> bool:
    if not isinstance(text, str) or not text or len(text) > 253 or "/" in text:
        return False
    labels = text.split(".")
    if len(labels) < 2 or not all(_DOMAIN_LABEL.match(l) for l in labels) or _numeric_label(labels[-1]):
        return False
    return True
