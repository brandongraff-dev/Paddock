"""HTTP client for the orchestrator fleet API: standard library (``urllib``) only.

* **Every** transport problem (DNS, refused, reset, timeout, TLS, malformed reply, bad URL, a reply nested
  deeper than the JSON parser can take) becomes a :class:`FleetClientError`; nothing else escapes, so one
  network blip can never kill the run loop. A request also has a TOTAL deadline (the socket timeout alone is
  per operation, so a server dribbling one byte at a time could otherwise hold the single-threaded loop for
  hours); past it the connection is torn down and the call fails like any other transport error.
* ``http://`` is refused unless the server is loopback (enrollment tokens and ``X-Agent-Token`` must not
  cross a network in clear text). Redirects are never followed (a redirect must not carry credentials to
  another host or downgrade to http).
* Envelope routes send ``Idempotency-Key: <seq>``; the server treats an identical retry as success.
* The ``Date`` header of every reply feeds a round-trip-corrected clock skew estimate that the agent
  reports in its self-health section (it does not alter the clock the agent signs with).

Agent-authenticated calls use ``X-Agent-Token`` (never ``Authorization: Bearer``, which the orchestrator
reserves for JWTs and ``pak_`` keys).
"""
import email.utils
import functools
import http.client
import ipaddress
import json
import random
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit

from . import __version__, envelope

MAX_BACKOFF_S = 300.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_TRANSIENT_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


class FleetClientError(RuntimeError):
    """A failed call. ``status`` is None for transport errors (no HTTP answer at all)."""

    def __init__(self, message, status=None, body=None, retry_after=None, local=False):
        super(FleetClientError, self).__init__(message)
        self.status = status
        self.body = body
        self.retry_after = retry_after
        # ``local``: refused before anything was sent (a malformed id, an envelope the contract forbids).
        # Retrying the same input can never succeed, so it is permanent, never "transient".
        self.local = bool(local)

    @property
    def transient(self):
        """True when retrying the same request may succeed (no answer, 5xx, 408/425/429)."""
        if self.local:
            return False
        return self.status is None or self.status in _TRANSIENT_STATUSES or self.status >= 500

    def structured_codes(self):
        """The machine-readable verdict codes of a JSON-object body (``error`` / ``reason``), lower-cased.

        Only a structured body counts: an HTML error page that happens to mention a code proves nothing."""
        out = set()
        if isinstance(self.body, dict):
            for key in ("error", "reason"):
                val = self.body.get(key)
                if isinstance(val, str):
                    out.add(val.strip().lower())
        return out

    @property
    def auth_failure(self):
        return self.status in (401, 403)

    def body_mentions(self, needle):
        text = json.dumps(self.body, default=str) if not isinstance(self.body, str) else self.body
        return needle.lower() in (text or "").lower()


def backoff_delay(failures, base=5.0, cap=MAX_BACKOFF_S, rand=random.random):
    """Jittered exponential backoff, never above ``cap``: ``min(cap, base*2^(n-1)) * U[0.5, 1.0]``."""
    n = max(1, int(failures))
    exp = min(float(cap), float(base) * (2.0 ** min(n - 1, 32)))
    return min(float(cap), exp * (0.5 + 0.5 * rand()))


def _is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _valid_host(host):
    if _HOST_RE.match(host):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_server(server):
    """A clean base URL, or :class:`FleetClientError`. ``http://`` only for loopback."""
    s = (server or "").strip()
    if "://" not in s:
        s = "https://" + s
    s = s.rstrip("/")
    # scheme and host are case-insensitive: normalise them so every later "is it https?" check is exact
    if "://" in s:
        scheme, rest = s.split("://", 1)
        netloc, sep, path = rest.partition("/")
        s = scheme.lower() + "://" + netloc.lower() + sep + path
    try:
        parts = urlsplit(s)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError:
        raise FleetClientError("%r is not a valid server URL (expected https://host:port)" % (server,))
    if parts.scheme not in ("http", "https") or not host or not _valid_host(host):
        raise FleetClientError("%r is not a valid server URL (expected https://host:port)" % (server,))
    if parts.username or parts.password:
        raise FleetClientError("credentials in the server URL are not allowed")
    if parts.query or parts.fragment:
        raise FleetClientError("the server URL must not carry a query or fragment")
    if parts.scheme == "http" and not _is_loopback(host):
        raise FleetClientError(
            "refusing plain http:// to a non-loopback server: enrollment tokens and agent credentials "
            "must travel over TLS (use https://)")
    return s


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_TLS = threading.local()


def _track(sock):
    holder = getattr(_TLS, "holder", None)
    if holder is not None:
        holder.append(sock)
    return sock


class _TrackedMixin(object):
    """Hands every socket a request opens to the caller's ``holder`` so a total deadline can close them."""

    def __init__(self, *args, **kwargs):
        super(_TrackedMixin, self).__init__(*args, **kwargs)
        create = self._create_connection

        def tracked(*a, **k):
            return _track(create(*a, **k))
        self._create_connection = tracked

    def connect(self):
        super(_TrackedMixin, self).connect()
        _track(self.sock)


class _TrackedHTTPConnection(_TrackedMixin, http.client.HTTPConnection):
    pass


class _TrackedHTTPSConnection(_TrackedMixin, http.client.HTTPSConnection):
    pass


class _TrackedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_TrackedHTTPConnection, req)


class _TrackedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(functools.partial(_TrackedHTTPSConnection, context=self._context), req)


def _abort(sock):
    for fn in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
        try:
            fn()
        except (OSError, ValueError):
            pass


def _default_transport(opener, deadline):
    """``deadline`` is a callable returning the total seconds one request may take."""
    def one(method, url, headers, body, timeout):
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - scheme validated above
                data = resp.read(MAX_RESPONSE_BYTES + 1)
                return resp.status, dict((k.lower(), v) for k, v in resp.headers.items()), data
        except urllib.error.HTTPError as exc:
            try:
                data = exc.read(MAX_RESPONSE_BYTES + 1)
            except Exception:  # noqa: BLE001
                data = b""
            hdrs = dict((k.lower(), v) for k, v in (exc.headers.items() if exc.headers else []))
            return exc.code, hdrs, data

    def send(method, url, headers, body, timeout):
        limit = float(deadline())
        holder, box = [], {}

        def work():
            _TLS.holder = holder
            try:
                box["ok"] = one(method, url, headers, body, timeout)
            except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
                box["err"] = exc

        worker = threading.Thread(target=work, name="paddock-http", daemon=True)
        worker.start()
        worker.join(limit)
        if worker.is_alive():
            for sock in list(holder):          # tear the connection down; the worker then fails fast
                _abort(sock)
            worker.join(5.0)
            raise FleetClientError("%s %s exceeded the %.0f s total request deadline" % (method, url, limit))
        if "err" in box:
            raise box["err"]
        return box["ok"]
    return send


class FleetClient(object):
    def __init__(self, server, *, agent_id=None, agent_token=None, timeout_s=20, transport=None,
                 ca_file=None, user_agent=None, deadline_s=None):
        self.base = normalize_server(server)
        self.agent_id = _check_agent_id(agent_id) if agent_id else None
        self.agent_token = agent_token
        self._timeout = float(timeout_s)
        # total seconds one request may take (the socket timeout is per operation; see the module docstring)
        self._deadline = float(deadline_s) if deadline_s else max(30.0, 3.0 * self._timeout)
        self.clock_skew_ms = None
        self._ua = user_agent or "paddock-agent/%s" % __version__
        if transport is None:
            host = urlsplit(self.base).hostname or ""
            handlers = [_NoRedirect(), _TrackedHTTPHandler()]
            if _is_loopback(host):
                handlers.append(urllib.request.ProxyHandler({}))
            if self.base.startswith("https://"):
                ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
                handlers.append(_TrackedHTTPSHandler(context=ctx))
            transport = _default_transport(urllib.request.build_opener(*handlers), lambda: self._deadline)
        self._transport = transport

    # -- low level ----------------------------------------------------------- #
    def _agent_headers(self):
        if not self.agent_token:
            raise FleetClientError("no agent token; enroll first")
        return {"X-Agent-Token": self.agent_token}

    def _note_date(self, headers, t0, t1):
        date = headers.get("date")
        if not date:
            return
        try:
            server_epoch = email.utils.parsedate_to_datetime(date).timestamp()
        except (TypeError, ValueError, IndexError, OverflowError):
            return
        # The Date header has one-second resolution (it is a floor); add half a second, and compare with
        # the midpoint of the round trip.
        self.clock_skew_ms = int(round((server_epoch + 0.5 - (t0 + t1) / 2.0) * 1000.0))

    def _req(self, method, path, *, body=None, json_body=None, content_encoding=None, headers=None,
             idempotency_key=None):
        hdrs = {"User-Agent": self._ua, "Accept": "application/json"}
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        if content_encoding:
            hdrs["Content-Encoding"] = content_encoding
        if idempotency_key is not None:
            hdrs["Idempotency-Key"] = str(idempotency_key)
        hdrs.update(headers or {})
        label = "%s %s" % (method, path)
        t0 = time.time()
        try:
            status, resp_headers, data = self._transport(method, self.base + path, hdrs, body,
                                                         self._timeout)
        except FleetClientError:
            raise
        except Exception as exc:  # noqa: BLE001 - ALL transport errors become FleetClientError
            raise FleetClientError("%s failed: %s" % (label, _describe(exc)))
        t1 = time.time()
        self._note_date(resp_headers or {}, t0, t1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise FleetClientError("%s: response too large" % label, status=status)
        parsed = None
        if data:
            try:
                parsed = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):   # RecursionError: a hostile, deeply nested reply
                parsed = None if status < 400 else data[:512].decode("utf-8", "replace")
                if status < 400:
                    raise FleetClientError("%s: the server answered %d with a body that is not JSON"
                                           % (label, status), status=status)
        if status >= 400:
            retry_after = _retry_after((resp_headers or {}).get("retry-after"))
            raise FleetClientError("%d on %s" % (status, label), status=status, body=parsed,
                                   retry_after=retry_after)
        if status >= 300:
            raise FleetClientError("%s: unexpected redirect/status %d (redirects are not followed)"
                                   % (label, status), status=status)
        return parsed

    # -- enrollment ---------------------------------------------------------- #
    def enroll(self, *, token, hostname, public_key_b64, proof_b64, agent_version=None,
               capabilities=None):
        """``POST /v1/fleet/enroll``. Public route: the token travels in the body, never in a header."""
        body = {"token": token, "hostname": hostname, "public_key_b64": public_key_b64,
                "proof_b64": proof_b64, "agent_version": agent_version}
        if capabilities is not None:
            body["capabilities"] = list(capabilities)
        out = self._req("POST", "/v1/fleet/enroll", json_body=body)
        if not isinstance(out, dict):
            raise FleetClientError("enroll: the server returned no JSON object")
        return out

    # -- agent-authenticated, signed envelopes ------------------------------- #
    def _signed(self, route, env):
        if not self.agent_id:
            raise FleetClientError("no agent id; enroll first")
        try:
            body, enc = envelope.encode_body(env)
        except envelope.EnvelopeError as exc:
            raise FleetClientError("refusing to send: %s" % exc, local=True)
        return self._req("POST", "/v1/fleet/%s/%s" % (self.agent_id, route), body=body,
                         content_encoding=enc, headers=self._agent_headers(),
                         idempotency_key=env.get("seq"))

    def heartbeat(self, env):
        """``POST /v1/fleet/{id}/heartbeat`` with a signed ``kind=heartbeat`` envelope. The reply carries
        ``pending_actions`` (approved, real work for this host)."""
        return self._signed("heartbeat", env)

    def post_posture(self, env):
        return self._signed("posture", env)

    def rotate_key(self, env):
        return self._signed("keys/rotate", env)

    # -- agent-authenticated, unsigned --------------------------------------- #
    def post_inventory(self, inventory):
        """v1 inventory (unsigned; the server marks it as never evidence)."""
        return self._req("POST", "/v1/fleet/%s/inventory" % self._need_id(), json_body=inventory,
                         headers=self._agent_headers())

    def post_result(self, action_id, *, status, output, revert=None):
        body = {"status": status, "output": output}
        if revert is not None:
            body["revert"] = revert
        return self._req("POST", "/v1/fleet/actions/%s/result" % _check_agent_id(action_id),
                         json_body=body, headers=self._agent_headers(),
                         idempotency_key="result-%s" % action_id)

    def _need_id(self):
        if not self.agent_id:
            raise FleetClientError("no agent id; enroll first")
        return self.agent_id

    # -- operator (read; uses the ambient operator credential) --------------- #
    def list_actions(self, *, agent=None, status=None, operator_headers=None):
        params = []
        if agent:
            params.append("agent=%s" % agent)
        if status:
            params.append("status=%s" % status)
        qs = ("?" + "&".join(params)) if params else ""
        return self._req("GET", "/v1/fleet/actions" + qs, headers=operator_headers)

    def get_agent(self, agent_id, *, operator_headers=None):
        return self._req("GET", "/v1/fleet/agents/%s" % _check_agent_id(agent_id),
                         headers=operator_headers)


def _check_agent_id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise FleetClientError("%r is not a valid id" % (value,), local=True)


def _retry_after(value):
    try:
        return max(0.0, min(MAX_BACKOFF_S, float(value)))
    except (TypeError, ValueError):
        return None


def _describe(exc):
    """A short, secret-free description of a transport exception."""
    detail = getattr(exc, "reason", None) or str(exc)
    return ("%s: %s" % (type(exc).__name__, detail))[:160]
