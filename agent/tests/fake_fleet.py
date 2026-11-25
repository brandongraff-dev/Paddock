"""An in-process fake of the orchestrator fleet API implementing contract section 2 (checks 2-8, in order),
used to drive the real agent code. ``FakeFleet.transport`` plugs into ``FleetClient(transport=...)``;
``serve()`` exposes the same logic on a loopback socket for a real-HTTP test."""
import gzip
import hashlib
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from paddock_agent import envelope

PREFIX = b"paddock-agent-envelope/v1\n"


def _no_dups(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def b64u_decode(s):
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FakeFleet:
    def __init__(self, token=None, now=time.time):
        self.now = now
        self.tenant_id = str(uuid.uuid4())
        self.agent_id = str(uuid.uuid4())
        self.token = token or "fet_0123456789ab_" + "s" * 32
        self.token_used = False
        self.agent_token = "fat_aabbccddeeff_" + "t" * 32
        self.keys = {}               # kid -> {"pub": bytes, "status": "active|rotated|revoked", "last_seq": int}
        self.accepted = []           # (kind, envelope) of everything accepted, in order
        self.rejected = []           # (code, reason)
        self.results = []
        self.pending_actions = []
        self.requests = []
        self.fail = []               # scripted: a status int, or an Exception instance, consumed first
        self.legacy = False
        self.require_reenroll = False
        self.omit_tenant = False
        self.hostname = None
        self.inventory = []

    # -- plumbing ------------------------------------------------------------ #
    def transport(self, method, url, headers, body, timeout):
        path = "/" + url.split("//", 1)[1].split("/", 1)[1]
        status, hdrs, payload = self.handle(method, path, headers, body)
        data = json.dumps(payload).encode()
        return status, dict((k.lower(), v) for k, v in hdrs.items()), data

    def handle(self, method, path, headers, body):
        self.requests.append((method, path, dict(headers)))
        if self.fail:
            f = self.fail.pop(0)
            if isinstance(f, BaseException):
                raise f
            return f, {}, {"detail": "scripted"}
        if self.require_reenroll and path != "/v1/fleet/enroll":
            return 403, {}, {"error": "re_enroll_required"}
        if path == "/v1/fleet/enroll":
            return self._enroll(body)
        if headers.get("X-Agent-Token") != self.agent_token:
            return 401, {}, {"detail": "bad agent token"}
        parts = path.strip("/").split("/")
        if parts[:2] == ["v1", "fleet"] and len(parts) >= 4 and parts[2] == self.agent_id:
            route = "/".join(parts[3:])
            if route in ("heartbeat", "posture", "keys/rotate"):
                return self._signed(route, headers, body)
            if route == "inventory":
                self.inventory.append(json.loads(body))
                return 200, {}, {"ok": True}
        if parts[:3] == ["v1", "fleet", "actions"] and parts[-1] == "result":
            self.results.append((parts[3], json.loads(body)))
            return 200, {}, {"ok": True}
        return 404, {}, {"detail": "no route"}

    # -- enroll -------------------------------------------------------------- #
    def _enroll(self, body):
        d = json.loads(body)
        if d.get("token") != self.token or self.token_used:
            return 401, {}, {"detail": "invalid, expired or already-used enrollment token"}
        pub = b64u_decode(d["public_key_b64"])
        prefix = self.token.split("_")[1]
        msg = envelope.enroll_proof_message(prefix, d["hostname"])
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(b64u_decode(d["proof_b64"]), msg)
        except InvalidSignature:
            return 400, {}, {"detail": "invalid proof of possession"}
        self.token_used = True
        self.hostname = d["hostname"]
        kid = hashlib.sha256(pub).hexdigest()[:32]
        for k in self.keys.values():
            if k["status"] == "active":
                k["status"] = "revoked"
        self.keys[kid] = {"pub": pub, "status": "active", "last_seq": 0}
        out = {"agent_id": self.agent_id, "agent_token": self.agent_token, "key_id": kid,
               "server_time": "2026-11-25T00:00:00Z", "tenant_id": self.tenant_id}
        if self.omit_tenant:
            del out["tenant_id"]
        return 201, {}, out

    def new_token(self):
        self.token = "fet_0123456789cd_" + "r" * 32
        self.token_used = False
        return self.token

    # -- signed routes: contract section 2 checks, in order ------------------ #
    def _reject(self, code, reason, extra=None):
        self.rejected.append((code, reason))
        out = {"detail": reason}
        out.update(extra or {})
        return code, {}, out

    def _signed(self, route, headers, body):
        if headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        try:
            env = json.loads(body, object_pairs_hook=_no_dups)
        except ValueError:
            return self._reject(400, "bad json")
        needed = {"v", "alg", "kid", "agent_id", "tenant_id", "kind", "seq", "issued_at", "nonce",
                  "payload_type", "payload_sha256", "payload_len", "collectors", "payload_b64", "sig"}
        if not isinstance(env, dict) or set(env) != needed or env["v"] != 1:
            return self._reject(400, "bad fields")
        if self.legacy:
            return 403, {}, {"error": "re_enroll_required"}
        if env["tenant_id"] != self.tenant_id or env["agent_id"] != self.agent_id:
            return self._reject(403, "tenant mismatch")
        key = self.keys.get(env["kid"])
        if key is None or key["status"] != "active" or env["alg"] != "ed25519":
            return self._reject(401, "kid is not an active key")
        payload = b64u_decode(env["payload_b64"])
        if len(payload) != env["payload_len"] or hashlib.sha256(payload).hexdigest() != env["payload_sha256"]:
            return self._reject(400, "payload digest")
        header = dict((k, v) for k, v in env.items() if k not in ("payload_b64", "sig"))
        try:
            Ed25519PublicKey.from_public_bytes(key["pub"]).verify(
                b64u_decode(env["sig"]), PREFIX + envelope.canon(header))
        except InvalidSignature:
            return self._reject(401, "bad signature")
        import calendar
        issued = calendar.timegm(time.strptime(env["issued_at"], "%Y-%m-%dT%H:%M:%SZ"))
        if abs(self.now() - issued) > 600:
            return self._reject(422, "clock", {"server_now": int(self.now())})
        want = ("rotate" if route == "keys/rotate" else route)
        if env["kind"] != want:
            return self._reject(400, "kind/route mismatch")
        seq = env["seq"]
        if seq <= key["last_seq"]:
            if seq == key.get("seq_seen", {}).get("seq") and key["seq_seen"]["sha"] == env["payload_sha256"]:
                return 200, {}, {"ok": True, "idempotent": True, "pending_actions": []}
            return self._reject(409, "seq", {"expected_min": key["last_seq"] + 1})
        key["last_seq"] = seq
        key["seq_seen"] = {"seq": seq, "sha": env["payload_sha256"]}
        self.accepted.append((env["kind"], env))
        if env["kind"] == "rotate":
            p = json.loads(payload)
            new_pub = b64u_decode(p["new_public_key_b64"])
            msg = envelope.rotate_proof_message(env["agent_id"], env["kid"], p["new_key_id"])
            try:
                Ed25519PublicKey.from_public_bytes(new_pub).verify(b64u_decode(p["proof_b64"]), msg)
            except InvalidSignature:
                return self._reject(400, "bad rotate proof")
            key["status"] = "rotated"
            self.keys[p["new_key_id"]] = {"pub": new_pub, "status": "active", "last_seq": 0}
            return 200, {}, {"ok": True, "key_id": p["new_key_id"]}
        acts, self.pending_actions = self.pending_actions, []
        return 200, {}, {"id": self.agent_id, "status": "online", "last_seen": "now", "pending_actions": acts}

    def active_key(self):
        for kid, k in self.keys.items():
            if k["status"] == "active":
                return kid
        return None

    # -- a real socket for the end-to-end test ------------------------------- #
    def serve(self):
        fleet = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                status, hdrs, payload = fleet.handle(self.command, self.path, dict(self.headers.items()), body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _do

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.02), daemon=True).start()
        return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]
