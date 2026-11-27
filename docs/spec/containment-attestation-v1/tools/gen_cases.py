#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""End-to-end case generator for the containment attestation spec (v1).

Like gen_vectors.py this is a third, independent implementation written from the spec text. It uses only the
standard library and `cryptography`, imports nothing from the verifier or from any issuer (an AST test enforces
that) and reuses nothing but gen_vectors.py's reference primitives (PCJ, PAE, Merkle, the seeds). Every expectation in
a case is written by hand from the spec: the generator never asks a verifier what the answer should be.

    python gen_cases.py             write vectors/cases/**, vectors/test-roots.json and vectors/MANIFEST.json
    python gen_cases.py --check     regenerate in memory and fail on any difference (CI)
    python gen_cases.py --out DIR   write somewhere else (DIR plays the part of vectors/)

Everything is deterministic: no clock, no randomness. Keys derive from the public test seeds of spec/12.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_DIR = os.path.dirname(HERE)
DEFAULT_OUT = os.path.join(SPEC_DIR, "vectors")
SPEC_VERSION = "1.0"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


gv = _load("gen_vectors")
pcj, sha, b64 = gv.pcj, gv.sha, gv.b64

NOW = "2026-12-01T12:00:00Z"
DOMAIN = "example.com"
ESTATE = "e_3fq7m2xk5h6cnj4d2v5yb7wzta"
OTHER_ESTATE = "e_" + "b" * 26
WK = ".well-known/paddock"
TYPE_STATEMENT, TYPE_CERT, TYPE_REVOKED = gv.P_TYPE_STATEMENT, gv.P_TYPE_CERT, gv.P_TYPE_REVOKED
STMT_T = "https://in-toto.io/Statement/v1"
PRED_T = "https://paddock.dev/attestation/containment/v1"


# ====================================================================================== key material
class Key(object):
    def __init__(self, name):
        self.name = name
        self.sk = gv.key_for(name)
        self.pub = gv.pub_of(self.sk)
        self.kid = gv.kid_of(self.pub)
        self.fp = "sha256:" + sha(self.pub)

    def sign(self, msg):
        return self.sk.sign(msg)


KEYS = dict((n, Key(n)) for n in ("root-1", "root-2", "issuer-1", "revoker-1", "tenant-a", "tenant-b", "anchor-a", "attacker"))
IDENTITY_PUB = bytes([1]) + bytes(31)                       # the neutral point: a weak key
TWO_TORSION_PUB = bytes([0xEC]) + bytes([0xFF] * 30) + bytes([0x7F])   # (0, -1): order 2
ROOT_NB, ROOT_NA = "2026-01-01T00:00:00Z", "2036-01-01T00:00:00Z"
ISSUER_NB, ISSUER_NA = "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"
ESTATE_NB, ESTATE_NA = "2026-12-01T00:00:00Z", "2027-03-01T00:00:00Z"


def env_obj(ptype, payload, signer_kid, sig):
    return {"payload": b64(payload), "payloadType": ptype, "signatures": [{"keyid": signer_kid, "sig": b64(sig)}]}


def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def cert_env(pub, usage, issuer, nb, na, estate=None, serial=1, custody="hosted", alg="ed25519", kid=None, tamper=None):
    payload = {"_type": "https://paddock.dev/key-cert/v1", "alg": alg, "custody": custody, "issuer_kid": issuer.kid,
               "kid": kid or gv.kid_of(pub), "not_after": na, "not_before": nb, "public_key": b64(pub), "serial": serial, "usage": usage}
    if estate is not None:
        payload["estate"] = estate
    raw = pcj(payload)
    sig = issuer.sign(gv.pae(TYPE_CERT, raw))
    if tamper:
        payload = tamper(dict(payload))
        raw = pcj(payload)
    return env_obj(TYPE_CERT, raw, issuer.kid, sig)


def default_pki():
    r1, iss, rev = KEYS["root-1"], KEYS["issuer-1"], KEYS["revoker-1"]
    return {
        "issuer": cert_env(iss.pub, "issue-cert", r1, ISSUER_NB, ISSUER_NA, serial=1),
        "revoker": cert_env(rev.pub, "revoke", iss, ISSUER_NB, ISSUER_NA, serial=2),
        "attest": cert_env(KEYS["tenant-a"].pub, "attest", iss, ESTATE_NB, ESTATE_NA, ESTATE, 17),
        "anchor": cert_env(KEYS["anchor-a"].pub, "anchor", iss, ESTATE_NB, ESTATE_NA, ESTATE, 18),
    }


def keys_entry(key_pub, usage, cert, nb=ESTATE_NB, na=ESTATE_NA, custody="hosted", alg="ed25519", kid=None):
    e = {"kid": kid or gv.kid_of(key_pub), "usage": usage, "alg": alg, "public_key": b64(key_pub), "custody": custody,
         "not_before": nb, "not_after": na}
    if cert is not None:
        e["cert"] = cert
    return e


def default_keys_doc(pki=None):
    pki = pki or default_pki()
    return {"spec": "paddock-keys/v1", "estate": ESTATE, "issuers": [pki["issuer"]], "revoker": pki["revoker"],
            "keys": [keys_entry(KEYS["tenant-a"].pub, "attest", pki["attest"]), keys_entry(KEYS["anchor-a"].pub, "anchor", pki["anchor"])]}


def revoked_payload(**over):
    p = {"_type": "https://paddock.dev/revocation-list/v1", "estate": ESTATE, "seq": 42, "issued_at": "2026-12-01T06:00:00Z",
         "next_update": "2026-12-02T06:00:00Z", "revoked": [], "superseded": []}
    p.update(over)
    return p


def revoked_env(payload, signer="revoker-1", keyid=None):
    k = KEYS[signer]
    raw = pcj(payload)
    return env_obj(TYPE_REVOKED, raw, keyid or k.kid, k.sign(gv.pae(TYPE_REVOKED, raw)))


def roots_doc(extra=()):
    r = KEYS["root-1"]
    return [{"kid": r.kid, "public_key": b64(r.pub), "usage": "root", "not_before": ROOT_NB, "not_after": ROOT_NA}] + list(extra)


# ====================================================================================== statements
LIMITS_TEXT = open(os.path.join(SPEC_DIR, "registry", "limits-v1.txt"), "rb").read()
LIMITS_DIGEST = "sha256:" + sha(LIMITS_TEXT)
REGISTRY = json.load(open(os.path.join(SPEC_DIR, "registry", "std-registry.json")))
RULESET, RS = next(iter(REGISTRY["rulesets"].items()))
STD = RS["std"]
WORKED = gv.build_worked_example()
ANCHOR_DOC = WORKED["anchor_doc"]
ANCHOR_BYTES = pcj(ANCHOR_DOC)
ANCHOR_HEAD = ANCHOR_DOC["head"]
COMMIT_KEY = gv.COMMIT_KEY
EMPTY_ROOT = "sha256:" + gv.EMPTY.hex()

POLICY_LEAVES = [{"id": "std:no-internet-to-datastore", "digest": STD["std:no-internet-to-datastore"]["digest"], "enabled": True, "source": "std"},
                 {"id": "std:server-ssh-hardened", "digest": STD["std:server-ssh-hardened"]["digest"], "enabled": True, "source": "std"},
                 {"id": "std:guest-cannot-reach-pos", "digest": STD["std:guest-cannot-reach-pos"]["digest"], "enabled": True, "source": "std"}]
GRAPH_LEAVES = [{"t": "node", "id": "internet", "kind": "internet", "tags": []},
                {"t": "node", "id": "asset:11111111-1111-4111-8111-111111111111", "kind": "cloud_db", "class": "datastore", "tags": []},
                {"t": "edge", "src": "internet", "dst": "asset:22222222-2222-4222-8222-222222222222", "proto": "tcp", "ports": "443",
                 "basis": "configured", "source": "aws_sg"}]
BLIND_LEAVES = [{"inv": "std:no-internet-to-datastore", "node": "asset:33333333-3333-4333-8333-333333333333", "direction": "in",
                 "reason": "stale", "relevant": True}]


def base_statement():
    return copy.deepcopy(WORKED["statement"])


def mk_result(inv, verdict="HOLDS", **over):
    e = STD.get(inv)
    r = {"invariant": inv, "digest": e["digest"] if e else "sha256:" + sha(inv.encode("ascii")),
         "assertion": e["assertion"] if e else "unreachable", "verdict": verdict, "min_tier": "configured", "max_age_s": 86400,
         "coverage": {"universe": 42, "covered": 41, "required_bp": 9500, "estate_universe": 120, "estate_covered": 118},
         "blind_spots": {"root": EMPTY_ROOT, "size": 0, "truncated": False}, "selected": {"from": 1, "to": 4}, "exceptions": 0}
    if verdict == "HOLDS":
        r["tier"] = "configured"
        r["valid_until"] = "2026-12-02T08:40:00Z"
    elif verdict == "VIOLATED":
        r["violations"] = 2
    else:
        r["reason_codes"] = ["stale_or_missing_evidence"]
    r.update(over)
    return r


def set_counts(stmt, total=None, enabled_std=None, enabled_custom=None, versions=None):
    p = stmt["predicate"]["policy"]
    n = len(stmt["predicate"]["results"])
    p["disclosed"] = n
    for k, v in (("total", total), ("enabled_std", enabled_std), ("enabled_custom", enabled_custom), ("versions", versions)):
        if v is not None:
            p[k] = v


def render(stmt, signer="tenant-a", mode="pae", payload=None, keyid=None):
    """(payload bytes, envelope bytes) for a statement dict."""
    k = KEYS[signer]
    raw = payload if payload is not None else pcj(stmt)
    msg = {"pae": gv.pae(TYPE_STATEMENT, raw), "raw": raw, "b64text": b64(raw).encode("ascii")}[mode]
    return raw, compact(env_obj(TYPE_STATEMENT, raw, keyid or k.kid, k.sign(msg)))


def dns_fixture(records=None, label="r1", status="ok", ad=None, names=None):
    rec = WORKED["dns_txt"]
    answers = {}
    if status == "ok":
        answers["_paddock-attest." + DOMAIN] = {"status": "ok", "txt": records if records is not None else [rec]}
    elif status is not None:
        answers["_paddock-attest." + DOMAIN] = {"status": status}
    fx = {"resolver": label, "answers": answers}
    if ad is not None:
        fx["ad"] = ad
    return fx


def txt_for(key, fp=None):
    return "v=1; kid=%s; fp=%s" % (key.kid, fp or key.fp)


# ====================================================================================== the case model
class Bk(object):
    """Everything a case may change; ``build`` turns it into files."""

    def __init__(self):
        self.now = NOW
        self.stmt = base_statement()
        self.signer = "tenant-a"
        self.sign_mode = "pae"
        self.keyid = None
        self.payload = None
        self.env_hook = None
        self.pki = default_pki()
        self.keys_doc = default_keys_doc(self.pki)
        self.keys_bytes = None
        self.revoked_present = True
        self.revoked_payload = revoked_payload()
        self.revoked_signer = "revoker-1"
        self.revoked_keyid = None
        self.revoked_bytes = None
        self.bundle_domain = DOMAIN
        self.dns = [dns_fixture()]
        self.policy = None
        self.state = None
        self.args = []
        self.roots = "test"
        self.registry = "default"
        self.anchor = None
        self.history = {}                 # seq -> statement dict, rendered with the same signer
        self.write_current_numbered = False
        self.index = None                 # explicit attestation/index.json entries
        self.files_extra = {}             # path under the bundle root -> bytes
        self.files_drop = set()
        self.case_extra = {}              # path under the case dir -> bytes
        self.recipes = []
        self.target = {"kind": "dir", "path": WK}
        self.ship_anchor = True
        self.inputs = None
        self.post = []

    # -- statement helpers
    @property
    def pred(self):
        return self.stmt["predicate"]

    def result(self, i):
        return self.stmt["predicate"]["results"][i]

    def chain(self, seq, prev_stmt=None, history_seqs=None):
        """Make the statement seq ``seq`` whose predecessor is a statement (a copy of the base) at seq-1."""
        before = copy.deepcopy(self.stmt)
        before["predicate"]["seq"] = seq - 1
        if seq - 1 > 1:
            before["predicate"]["prev"] = "sha256:" + sha(b"an earlier statement")
        else:
            before["predicate"].pop("prev", None)
        if prev_stmt is not None:
            before = prev_stmt(before)
        self.history[seq - 1] = before
        self.pred["seq"] = seq
        self.pred["prev"] = "sha256:" + sha(render(before, self.signer)[0])
        self.write_current_numbered = True

    # -- rendering
    def build(self):
        files = {}
        raw, env = render(self.stmt, self.signer, self.sign_mode, self.payload, self.keyid)
        if self.env_hook is not None:
            env = self.env_hook(env, raw)
        files["attestation/latest.json"] = env
        seq = self.stmt["predicate"].get("seq", 1) if isinstance(self.stmt.get("predicate"), dict) else 1
        if self.write_current_numbered and isinstance(seq, int) and seq >= 1:
            files["attestation/%d.json" % seq] = env
        for s, st in sorted(self.history.items()):
            files["attestation/%d.json" % s] = render(st, self.signer)[1]
        if self.index is not None:
            files["attestation/index.json"] = compact(self.index)
        files["keys.json"] = self.keys_bytes if self.keys_bytes is not None else compact(self.keys_doc)
        if self.keys_bytes == b"":
            del files["keys.json"]
        if self.revoked_present:
            files["revoked.json"] = self.revoked_bytes if self.revoked_bytes is not None else compact(
                revoked_env(self.revoked_payload, self.revoked_signer, self.revoked_keyid))
        if self.bundle_domain is not None:
            files["bundle.json"] = compact({"spec": "paddock-attest-bundle/v1", "domain": self.bundle_domain, "generated_at": "2026-12-01T09:00:01Z",
                                            "head": {"seq": seq if isinstance(seq, int) and seq >= 1 else 1, "digest": "sha256:" + sha(raw)},
                                            "paths": ["attestation/latest.json", "keys.json", "revoked.json"]})
        if self.ship_anchor:
            files["anchors/%d.json" % ANCHOR_DOC["max_id"]] = ANCHOR_BYTES
        files.update(self.files_extra)
        for d in self.files_drop:
            files.pop(d, None)
        for fn in self.post:
            fn(files)
        return files

    def case_files(self):
        out = {}
        if self.roots not in ("test", "none"):
            out["roots.json"] = self.roots
        if self.registry != "default":
            out["registry.json"] = self.registry
        out.update(self.case_extra)
        return out


CASES = []


def C(cid, desc, refs, tags, exit_, codes=(), warnings=(), producer=False, profile=None, primary=None):
    """Register a case; the decorated function receives a fresh ``Bk`` and changes it."""
    def deco(fn):
        CASES.append(dict(id=cid, desc=desc, refs=list(refs), tags=list(tags), exit=exit_, codes=list(codes), warnings=list(warnings),
                          build=fn, producer=producer, profile=profile, primary=primary))
        return fn
    return deco


def noop(b):
    pass


# ====================================================================================== case helpers
def T(code):
    return code


def attest_window(b, nb=ESTATE_NB, na=ESTATE_NA):
    cert = cert_env(KEYS["tenant-a"].pub, "attest", KEYS["issuer-1"], nb, na, ESTATE, 17)
    b.pki["attest"] = cert
    b.keys_doc["keys"][0] = keys_entry(KEYS["tenant-a"].pub, "attest", cert, nb, na)


def issuer_window(b, nb=ISSUER_NB, na=ISSUER_NA):
    b.pki["issuer"] = cert_env(KEYS["issuer-1"].pub, "issue-cert", KEYS["root-1"], nb, na, serial=1)
    b.keys_doc["issuers"] = [b.pki["issuer"]]


def all_mode(b, verdicts=("HOLDS", "HOLDS", "HOLDS")):
    """Three std results in verdict-all mode, in id order: guest-cannot-reach-pos, no-internet-to-datastore, server-ssh-hardened."""
    ids = ["std:guest-cannot-reach-pos", "std:no-internet-to-datastore", "std:server-ssh-hardened"]
    out = []
    for inv, v in zip(ids, verdicts):
        extra = {}
        if inv == "std:server-ssh-hardened":
            extra = {"valid_until": "2026-12-01T14:50:00Z"} if v == "HOLDS" else {}
        out.append(mk_result(inv, v, **extra))
    b.pred["results"] = out
    b.pred["disclosure"] = {"verdicts": "all", "custom": False}
    b.pred["policy"].update({"total": 3, "enabled_std": 3, "enabled_custom": 0, "disclosed": 3, "versions": 3})


def custom_result(inv="acme:fully-secure", **over):
    r = mk_result(inv, **over)
    r["digest"] = "sha256:" + sha(inv.encode("ascii"))
    return r


def enable_custom(b, results):
    """Disclose custom results: they sort before the std ids (a-names) or after, by byte order."""
    res = b.pred["results"] + list(results)
    res.sort(key=lambda r: r["invariant"].encode("ascii"))
    b.pred["results"] = res
    b.pred["disclosure"] = {"verdicts": "holds_only", "custom": True}
    n_std = sum(1 for r in res if r["invariant"].startswith("std:"))
    n_c = len(res) - n_std
    b.pred["policy"].update({"total": max(b.pred["policy"]["total"], 3 + n_c), "enabled_std": max(3, n_std), "enabled_custom": n_c, "disclosed": len(res)})


def policy_json(**kw):
    p = {"policy_version": 1}
    p.update(kw)
    return p


def req(inv, **kw):
    e = {"invariant": inv, "verdict": "HOLDS"}
    e.update(kw)
    return e


def with_sig(sig):
    def hook(env, raw):
        d = json.loads(env.decode("ascii"))
        d["signatures"][0]["sig"] = b64(sig)
        return compact(d)
    return hook


def env_edit(fn):
    def hook(env, raw):
        d = json.loads(env.decode("ascii"))
        out = fn(d, raw)
        return out if isinstance(out, bytes) else compact(d)
    return hook


def ext_key(b, key_pub, name_cert_kid=None, serial=19, usage="attest", estate=ESTATE):
    """List an extra attest key (with a valid certificate) and name it in DNS."""
    cert = cert_env(key_pub, usage, KEYS["issuer-1"], ESTATE_NB, ESTATE_NA, estate, serial)
    b.keys_doc["keys"].append(keys_entry(key_pub, usage, cert))
    kid = gv.kid_of(key_pub)
    rec = "v=1; kid=%s; fp=sha256:%s" % (kid, sha(key_pub))
    b.dns[0]["answers"]["_paddock-attest." + DOMAIN]["txt"].append(rec)
    return kid


def merkle_proof(label, records, record):
    leaves, root = gv.m_tree(label, records, COMMIT_KEY)
    hs = [l[0] for l in leaves]
    idx = [l[3] for l in leaves].index(record)
    return {"v": 1, "tree": label, "size": len(leaves), "index": idx, "nonce": leaves[idx][1].hex(), "record": record,
            "path": [p.hex() for p in gv.m_path(hs, idx)]}


def put_proofs(b, **overrides):
    files = {"policy.json": merkle_proof("policy", POLICY_LEAVES, POLICY_LEAVES[0]),
             "graph.json": merkle_proof("graph", GRAPH_LEAVES, GRAPH_LEAVES[1]),
             "blind__std__no-internet-to-datastore.json": merkle_proof("blind", BLIND_LEAVES, BLIND_LEAVES[0])}
    files.update(overrides)
    for name, doc in files.items():
        b.case_extra["bundle/proofs/1/" + name] = compact(doc)
    b.args = ["--proofs-dir", "case/proofs"]


def make_anchor(at="2026-12-01T08:59:40Z", head=None, max_id=99120, signer="anchor-a", hash_alg="hmac-sha256"):
    doc = {"alg": "ed25519", "at": at, "estate": ESTATE, "hash_alg": hash_alg, "head": head or ANCHOR_HEAD, "kid": KEYS[signer].kid,
           "max_id": max_id, "v": 2}
    sig = KEYS[signer].sign(b"paddock-anchor/v2\n" + pcj(doc))
    full = dict(doc, sig=b64(sig))
    return full, pcj(full)


def set_anchor(b, doc, raw):
    b.pred["audit_anchor"] = {"max_id": doc["max_id"], "head": doc["head"], "hash_alg": doc["hash_alg"], "at": doc["at"],
                              "kid": doc["kid"], "digest": "sha256:" + sha(raw)}
    b.files_extra["anchors/%d.json" % doc["max_id"]] = raw


ANCHOR_PATH = WK + "/anchors/99120.json"
PLAIN = json.dumps(WORKED["statement"])      # an unsorted rendering for the non-canonical cases


def payload_edit(old, new, count=1):
    """Replace bytes in the canonical payload; the result is signed as it is."""
    def build(b):
        raw = pcj(b.stmt)
        assert old in raw, old
        b.payload = raw.replace(old, new, count)
    return build


# ====================================================================================== the corpus
# ---------------------------------------------------------------------------------------------- valid
@C("valid-minimal-holds", "The worked example of spec/C: two HOLDS results, two of three std invariants disclosed.",
   ["07 steps 0-10", "C"], ["valid", "wording"], 0, producer=True, profile="baseline")
def _(b):
    assert render(b.stmt)[0] == base64.b64decode(WORKED["payload_b64"])
    b.inputs = producer_inputs(b)


@C("valid-multi-invariant", "All six standard invariants disclosed and holding.", ["07 step 8"], ["valid"], 0)
def _(b):
    order = sorted(STD)
    res = []
    for inv in order:
        tier = "configured"
        res.append(mk_result(inv, tier=tier, selected={"to": 3}, valid_until="2026-12-01T14:50:00Z" if STD[inv]["assertion"] == "host-config"
                             else "2026-12-02T08:40:00Z"))
    b.pred["results"] = res
    b.pred["policy"].update({"total": 6, "enabled_std": 6, "enabled_custom": 0, "disclosed": 6, "versions": 6})


@C("valid-chain-seq2-with-history", "Statement 2 links to statement 1, which is in the bundle.", ["07 step 6"], ["valid", "chain"], 0)
def _(b):
    b.chain(2)


@C("valid-policy-json", "A JSON acceptance policy requiring two invariants.", ["08"], ["valid", "policy"], 0, profile="policy")
def _(b):
    b.policy = policy_json(require=[req("std:no-internet-to-datastore", min_tier="configured"), req("std:server-ssh-hardened")],
                           max_age="48h", min_coverage="0.95", name="insurer")


@C("valid-policy-yaml", "The same policy written in the YAML subset: the same outcome.", ["08 section 2"], ["valid", "policy"], 0, profile="policy")
def _(b):
    b.policy = {"yaml": "policy_version: 1\nname: insurer\nrequire:\n  - { invariant: std:no-internet-to-datastore, verdict: HOLDS, min_tier: configured }\n"
                        "  - { invariant: std:server-ssh-hardened, verdict: HOLDS }\nmax_age: 48h\nmin_coverage: 0.95\n"}


@C("valid-chunked-dns-txt", "The TXT record is split into several character strings.", ["05 section 6.2"], ["valid", "dns"], 0)
def _(b):
    rec = WORKED["dns_txt"]
    b.dns = [dns_fixture(records=[[rec[:40], rec[40:100], rec[100:]]])]


@C("valid-dns-rotation-two-records", "Two kids are published at once (rotation); the signing key is one of them.", ["05 section 4"], ["valid", "dns"], 0)
def _(b):
    b.dns = [dns_fixture(records=[WORKED["dns_txt"], txt_for(KEYS["tenant-b"])])]


@C("valid-dns-version-2-ignored", "A record with another version is ignored silently.", ["05 section 6.2"], ["valid", "dns"], 0)
def _(b):
    b.dns = [dns_fixture(records=["v=2; kid=whatever; fp=whatever", WORKED["dns_txt"]])]


@C("valid-two-resolvers-agree", "Two resolvers answer and agree; two must answer.", ["05 section 6.3"], ["valid", "dns"], 0)
def _(b):
    b.dns = [dns_fixture(label="r1"), dns_fixture(label="r2")]
    b.args = ["--dns-min-resolvers", "2"]


@C("valid-dnssec-required-asserted", "The policy requires DNSSEC and the resolvers assert it.", ["05 section 6.3"], ["valid", "dns", "policy"], 0, profile="policy")
def _(b):
    b.dns = [dns_fixture(label="r1", ad=True), dns_fixture(label="r2", ad=True)]
    b.policy = policy_json(trust={"dnssec": "required"})


@C("valid-revoked-superseded-before", "The key was retired after this statement was issued: accepted with a warning.", ["05 section 5"],
   ["valid", "lifecycle"], 0, warnings=["key.revoked_superseded"])
def _(b):
    b.revoked_payload["revoked"] = [{"kid": KEYS["tenant-a"].kid, "reason": "superseded", "revoked_at": "2026-12-01T10:00:00Z"}]


@C("valid-boundary-95pct", "19 of 20 against a floor of 0.95: exactly on the line.", ["03 section 3"], ["valid", "coverage"], 0)
def _(b):
    b.result(0)["coverage"].update({"universe": 20, "covered": 19, "required_bp": 9500})


@C("valid-dns-optional-offline", "No DNS is available and the policy makes the binding optional.", ["05 section 6.3"], ["valid", "dns", "policy"], 0,
   warnings=["dns.skipped_offline"], profile="policy")
def _(b):
    b.dns = []
    b.policy = policy_json(trust={"dns_binding": "optional"})


@C("valid-anchor-crosscheck", "An independent copy of the anchor equals the bundle's.", ["B section 2"], ["valid", "anchor"], 0)
def _(b):
    b.anchor = ANCHOR_PATH


@C("valid-anchor-optional-policy", "The policy asks for the anchor to be checked when present.", ["B section 3"], ["valid", "anchor", "policy"], 0, profile="policy")
def _(b):
    b.policy = policy_json(anchor="optional")


@C("valid-merkle-proofs", "Inclusion proofs for the policy, graph and blind-spot trees all verify.", ["04", "07 step 10"], ["valid", "merkle"], 0)
def _(b):
    put_proofs(b)


@C("valid-now-one-second-before-expiry", "One second before valid_until: still valid.", ["01 section 2.6"], ["valid", "time"], 0)
def _(b):
    b.now = "2026-12-02T08:59:59Z"


@C("valid-skew-within-300s", "The clock is exactly 300 seconds before issued_at: inside the skew allowance.", ["01 section 2.6"], ["valid", "time"], 0)
def _(b):
    b.now = "2026-12-01T08:55:00Z"


@C("valid-estate-subject-no-dns", "A statement about a paddock-estate subject has no domain to bind.", ["05 section 6.3"], ["valid", "dns"], 0,
   warnings=["dns.not_applicable"])
def _(b):
    name = "paddock-estate:" + ESTATE
    b.stmt["subject"] = [{"name": name, "digest": {"sha256": sha(name.encode("ascii"))}}]
    b.bundle_domain = ""
    b.dns = []


@C("valid-all-mode-complete", "Every enabled std invariant is disclosed, one of them as UNKNOWN.", ["02 section 3"], ["valid", "disclosure"], 0)
def _(b):
    all_mode(b, ("UNKNOWN", "HOLDS", "HOLDS"))


@C("valid-holds-only-partial-disclosure", "One of five enabled std invariants is shown; the counts say so.", ["09 W-POLICY"], ["valid", "disclosure", "wording"], 0)
def _(b):
    b.pred["results"] = b.pred["results"][:1]
    b.pred["policy"].update({"total": 7, "enabled_std": 5, "enabled_custom": 1, "disclosed": 1, "versions": 8})


@C("valid-256-results", "The largest legal statement: 256 results.", ["01 section 3"], ["valid", "limits"], 0)
def _(b):
    many_results(b, 256)


@C("huge-payload-within-limit", "256 results with the longest legal invariant ids: close to the largest statement a schema-valid payload reaches.",
   ["01 section 3"], ["valid", "limits"], 0)
def _(b):
    res = [custom_result(("acme:" + ("inv-%04d-" % i).ljust(64, "x"))) for i in range(256)]
    b.pred["results"] = res
    b.pred["disclosure"] = {"verdicts": "holds_only", "custom": True}
    b.pred["policy"].update({"total": 256, "enabled_std": 0, "enabled_custom": 256, "disclosed": 256, "versions": 256})


# ----------------------------------------------------------------------------------------------- time
@C("expired", "now is after valid_until.", ["07 step 5"], ["time"], 1, ["time.expired"])
def _(b):
    b.now = "2026-12-02T10:00:00Z"


@C("expired-at-boundary", "now equals valid_until: end-exclusive, so expired.", ["01 section 2.6"], ["time"], 1, ["time.expired"])
def _(b):
    b.now = "2026-12-02T09:00:00Z"


@C("issued-in-future", "now is 301 seconds before issued_at.", ["07 step 5"], ["time"], 1, ["time.not_yet_valid"])
def _(b):
    b.now = "2026-12-01T08:54:59Z"


@C("ttl-excessive", "valid_until is eight days after issued_at.", ["07 step 5"], ["time"], 1, ["time.ttl_excessive"])
def _(b):
    b.pred["valid_until"] = "2026-12-09T09:00:00Z"


@C("window-inverted", "valid_until is not after issued_at.", ["07 step 5"], ["time"], 1, ["time.window_invalid"])
def _(b):
    b.pred["valid_until"] = b.pred["issued_at"]
    b.now = "2026-12-01T08:58:00Z"


@C("snapshot-after-issue", "The snapshot is later than the statement.", ["07 step 5"], ["time"], 1, ["time.window_invalid"])
def _(b):
    b.pred["snapshot"]["at"] = "2026-12-01T09:00:10Z"


@C("snapshot-gap-over-900s", "The snapshot is more than 900 seconds older than the statement.", ["07 step 5"], ["time"], 1, ["time.window_invalid"])
def _(b):
    b.pred["snapshot"]["at"] = "2026-12-01T08:44:59Z"


@C("too-old-for-consumer", "The consumer allows six hours and the statement is seven hours old.", ["07 step 5"], ["time", "policy"], 1, ["time.too_old"],
   profile="policy")
def _(b):
    b.now = "2026-12-01T16:00:00Z"
    b.args = ["--max-age", "6h"]


@C("result-expired", "The statement is valid but a required result is past its own valid_until.", ["03 section 4"], ["time", "policy"], 1,
   ["invariant.expired"], profile="policy")
def _(b):
    b.now = "2026-12-01T15:00:00Z"
    b.policy = policy_json(require=[req("std:server-ssh-hardened")])


def _bad_time(value):
    def build(b):
        b.pred["issued_at"] = value
    return build


for _id, _v, _d in (("time-format-offset", "2026-12-01T09:00:00+00:00", "an offset"), ("time-format-fraction", "2026-12-01T09:00:00.5Z", "a fraction"),
                    ("time-format-feb30", "2026-02-30T09:00:00Z", "30 February"), ("time-format-leap-second", "2026-12-01T09:00:60Z", "a leap second"),
                    ("time-format-lowercase-z", "2026-12-01t09:00:00z", "lowercase letters")):
    C(_id, "issued_at with %s." % _d, ["01 section 1"], ["time", "strictness"], 1, ["schema.time_format"])(_bad_time(_v))


# ------------------------------------------------------------------------------------------ authenticity
@C("tampered-payload", "A digit of a coverage figure was changed after signing.", ["07 step 2"], ["authenticity"], 1, ["sig.invalid"])
def _(b):
    def hook(env, raw):
        assert b'"estate_universe":120' in raw
        d = json.loads(env.decode("ascii"))
        d["payload"] = b64(raw.replace(b'"estate_universe":120', b'"estate_universe":121', 1))
        return compact(d)
    b.env_hook = hook


@C("tampered-signature", "One bit of the signature was flipped.", ["07 step 2"], ["authenticity"], 1, ["sig.invalid"])
def _(b):
    def hook(env, raw):
        d = json.loads(env.decode("ascii"))
        sig = bytearray(base64.b64decode(d["signatures"][0]["sig"]))
        sig[0] ^= 1
        d["signatures"][0]["sig"] = b64(bytes(sig))
        return compact(d)
    b.env_hook = hook


@C("sig-wrong-length", "The signature decodes to 63 bytes.", ["01 section 2.5"], ["authenticity"], 1, ["sig.malformed"])
def _(b):
    def hook(env, raw):
        d = json.loads(env.decode("ascii"))
        d["signatures"][0]["sig"] = b64(base64.b64decode(d["signatures"][0]["sig"])[:63])
        return compact(d)
    b.env_hook = hook


@C("wrong-key", "The attacker signs and claims the tenant's key id.", ["07 step 2"], ["authenticity"], 1, ["sig.invalid"])
def _(b):
    b.signer = "attacker"
    b.keyid = KEYS["tenant-a"].kid


@C("unlisted-key", "The attacker signs with its own key id, which keys.json does not list.", ["07 step 2"], ["authenticity"], 1, ["key.unknown"])
def _(b):
    b.signer = "attacker"
    b.pred["kid"] = KEYS["attacker"].kid


def _weak(pub, sig):
    def build(b):
        kid = ext_key(b, pub)
        b.keyid = kid
        b.pred["kid"] = kid
        b.env_hook = with_sig(sig)
    return build


C("sig-s-plus-l", "S replaced by S + L: a malleable signature.", ["01 section 2.5"], ["authenticity", "ed25519"], 1, ["sig.noncanonical_s"])(
    lambda b: setattr(b, "env_hook", env_edit(lambda d, raw: d["signatures"][0].__setitem__("sig", b64(_s_plus_l(base64.b64decode(d["signatures"][0]["sig"])))))))


def _s_plus_l(sig):
    s = int.from_bytes(sig[32:], "little") + gv.L
    return sig[:32] + s.to_bytes(32, "little")


C("weak-key-identity", "The identity public key with the identity signature (accepted by some libraries for any message).", ["01 section 2.5"],
  ["authenticity", "ed25519"], 1, ["sig.weak_key"])(_weak(IDENTITY_PUB, IDENTITY_PUB + bytes(32)))
C("weak-key-2torsion", "A public key of order two.", ["01 section 2.5"], ["authenticity", "ed25519"], 1, ["sig.weak_key"])(
    _weak(TWO_TORSION_PUB, IDENTITY_PUB + bytes(32)))


@C("sig-over-raw-payload", "The signature covers the payload, not its pre-authentication encoding.", ["01 section 2.4"], ["authenticity", "dsse"], 1, ["sig.invalid"])
def _(b):
    b.sign_mode = "raw"


@C("sig-over-b64-text", "The signature covers the base64 text of the payload.", ["01 section 2.4"], ["authenticity", "dsse"], 1, ["sig.invalid"])
def _(b):
    b.sign_mode = "b64text"


@C("wrong-payload-type", "payloadType is application/json (validly signed over that type).", ["01 section 2.4"], ["authenticity", "dsse"], 1,
   ["schema.payload_type"])
def _(b):
    def hook(env, raw):
        k = KEYS["tenant-a"]
        return compact(env_obj("application/json", raw, k.kid, k.sign(gv.pae("application/json", raw))))
    b.env_hook = hook


@C("two-signatures", "Two signatures: version 1 requires exactly one.", ["02 section 1"], ["authenticity", "dsse"], 1, ["sig.count_invalid"])
def _(b):
    b.env_hook = env_edit(lambda d, raw: d["signatures"].append(dict(d["signatures"][0])))


@C("no-signature", "An empty signatures array.", ["02 section 1"], ["authenticity", "dsse"], 1, ["sig.count_invalid"])
def _(b):
    b.env_hook = env_edit(lambda d, raw: d.__setitem__("signatures", []))


@C("kid-fingerprint-mismatch", "keys.json lists the tenant's key id with the attacker's public key.", ["05 section 2"], ["authenticity", "trust"], 1,
   ["key.fingerprint_mismatch", "dns.mismatch"])
def _(b):
    k, att = KEYS["tenant-a"], KEYS["attacker"]
    cert = cert_env(att.pub, "attest", KEYS["issuer-1"], ESTATE_NB, ESTATE_NA, ESTATE, 17, kid=k.kid)
    b.keys_doc["keys"][0] = keys_entry(att.pub, "attest", cert, kid=k.kid)
    b.signer = "attacker"
    b.keyid = k.kid


@C("predicate-kid-differs-from-keyid", "predicate.kid names another key than the envelope keyid.", ["07 step 2"], ["authenticity"], 1, ["key.kid_mismatch"])
def _(b):
    b.pred["kid"] = KEYS["tenant-b"].kid


@C("signed-noncanonical-payload", "A pretty-printed payload that is validly signed.", ["01 section 2.1"], ["authenticity", "strictness"], 1,
   ["schema.payload_not_canonical"])
def _(b):
    b.payload = json.dumps(b.stmt, indent=2, sort_keys=True).encode("ascii")


# ---------------------------------------------------------------------------------------------- trust
@C("cert-missing", "The tenant key has no vendor certificate.", ["05 section 2"], ["trust"], 1, ["key.cert_missing"])
def _(b):
    b.keys_doc["keys"][0].pop("cert")


@C("cert-optional-missing", "The policy treats the vendor certificate as optional.", ["08 trust"], ["trust", "policy"], 0, warnings=["key.cert_missing"],
   profile="policy")
def _(b):
    b.keys_doc["keys"][0].pop("cert")
    b.policy = policy_json(trust={"vendor_cert": "optional"})


@C("cert-tampered", "The certificate payload was altered after signing.", ["05 section 2"], ["trust"], 1, ["key.cert_invalid"])
def _(b):
    cert = cert_env(KEYS["tenant-a"].pub, "attest", KEYS["issuer-1"], ESTATE_NB, ESTATE_NA, ESTATE, 17, tamper=lambda p: dict(p, serial=18))
    b.keys_doc["keys"][0]["cert"] = cert


@C("cert-wrong-root", "The issuer certificate is signed by a root that is not pinned.", ["05 section 1"], ["trust"], 1,
   ["key.root_unknown", "revocation.unverifiable"])
def _(b):
    b.keys_doc["issuers"] = [cert_env(KEYS["issuer-1"].pub, "issue-cert", KEYS["root-2"], ISSUER_NB, ISSUER_NA, serial=1)]


@C("cert-other-estate", "The certificate names another estate than the statement.", ["07 step 3"], ["trust"], 1, ["key.cert_subject_mismatch"])
def _(b):
    cert = cert_env(KEYS["tenant-a"].pub, "attest", KEYS["issuer-1"], ESTATE_NB, ESTATE_NA, OTHER_ESTATE, 17)
    b.keys_doc["keys"][0]["cert"] = cert


@C("cert-other-estate-consistent", "The whole key file is for another estate, consistently: only the statement's estate gives it away.", ["07 step 3"], ["trust"], 1,
   ["key.cert_subject_mismatch"])
def _(b):
    iss = KEYS["issuer-1"]
    b.pki["attest"] = cert_env(KEYS["tenant-a"].pub, "attest", iss, ESTATE_NB, ESTATE_NA, OTHER_ESTATE, 17)
    b.pki["anchor"] = cert_env(KEYS["anchor-a"].pub, "anchor", iss, ESTATE_NB, ESTATE_NA, OTHER_ESTATE, 18)
    b.keys_doc["estate"] = OTHER_ESTATE
    b.keys_doc["keys"][0] = keys_entry(KEYS["tenant-a"].pub, "attest", b.pki["attest"])
    b.keys_doc["keys"][1] = keys_entry(KEYS["anchor-a"].pub, "anchor", b.pki["anchor"])


@C("cert-wrong-usage", "An anchor key signs a statement.", ["05 section 2"], ["trust"], 1, ["key.cert_subject_mismatch"])
def _(b):
    a = KEYS["anchor-a"]
    b.signer = "anchor-a"
    b.pred["kid"] = a.kid
    b.dns[0]["answers"]["_paddock-attest." + DOMAIN]["txt"].append(txt_for(a))


@C("issuer-expired-at-issue", "The issuer certificate ended before the statement was issued.", ["05 section 2"], ["trust"], 1, ["issuer.outside_validity"])
def _(b):
    issuer_window(b, na="2026-12-01T08:00:00Z")


@C("issuer-revoked", "The release revokes the issuer that certified this key.", ["05 section 5"], ["trust", "lifecycle"], 1, ["issuer.revoked"])
def _(b):
    b.roots = compact(roots_doc([{"kid": KEYS["issuer-1"].kid, "usage": "issuer-revoked"}]))


@C("subject-domain-mismatch", "The bundle is for example.org but the statement names example.com.", ["07 step 3"], ["trust", "dns"], 1, ["dns.domain_mismatch"])
def _(b):
    b.bundle_domain = "example.org"


@C("no-trust-roots", "No roots are configured.", ["05 section 1"], ["trust"], 2, ["config.no_trust_roots"])
def _(b):
    b.roots = "none"


@C("key-window-ends-before-valid-until", "The key's certificate ends before the statement does.", ["05 section 2"], ["trust"], 1, ["key.outside_validity"])
def _(b):
    attest_window(b, na="2026-12-02T00:00:00Z")


# ------------------------------------------------------------------------------------------- lifecycle
@C("key-revoked-compromise", "A compromised key rejects every statement of that key.", ["05 section 5"], ["lifecycle"], 1, ["key.revoked"])
def _(b):
    b.revoked_payload["revoked"] = [{"kid": KEYS["tenant-a"].kid, "reason": "key_compromise", "revoked_at": "2026-12-01T10:00:00Z"}]


@C("key-compromise-future-revoked-at", "A compromise entry whose claimed time is far in the future still rejects.", ["05 section 5"], ["lifecycle"], 1, ["key.revoked"])
def _(b):
    b.revoked_payload["revoked"] = [{"kid": KEYS["tenant-a"].kid, "reason": "key_compromise", "revoked_at": "2030-01-01T00:00:00Z"}]


@C("key-revoked-superseded-after", "A retired key and a statement issued after the retirement.", ["05 section 5"], ["lifecycle"], 1, ["key.revoked"])
def _(b):
    b.revoked_payload["revoked"] = [{"kid": KEYS["tenant-a"].kid, "reason": "superseded", "revoked_at": "2026-12-01T08:00:00Z"}]


@C("key-revoked-listed-twice", "The list names the signing kid twice, a retirement after issued_at and a compromise: the compromise wins in either order.",
   ["05 section 5"], ["lifecycle"], 1, ["key.revoked"])
def _(b):
    kid = KEYS["tenant-a"].kid
    b.revoked_payload["revoked"] = [{"kid": kid, "reason": "superseded", "revoked_at": "2026-12-01T11:00:00Z"},
                                    {"kid": kid, "reason": "key_compromise", "revoked_at": "2026-12-01T11:30:00Z"}]


@C("key-revoked-listed-twice-reversed", "The same two entries in the other order: the outcome does not depend on the order.", ["05 section 5"],
   ["lifecycle"], 1, ["key.revoked"])
def _(b):
    kid = KEYS["tenant-a"].kid
    b.revoked_payload["revoked"] = [{"kid": kid, "reason": "key_compromise", "revoked_at": "2026-12-01T11:30:00Z"},
                                    {"kid": kid, "reason": "superseded", "revoked_at": "2026-12-01T11:00:00Z"}]


@C("key-not-yet-valid", "The certificate starts after the statement was issued.", ["05 section 2"], ["lifecycle"], 1, ["key.outside_validity"])
def _(b):
    attest_window(b, nb="2026-12-01T10:00:00Z")


@C("key-expired", "The certificate ended exactly at issued_at (end-exclusive).", ["05 section 2"], ["lifecycle"], 1, ["key.outside_validity"])
def _(b):
    attest_window(b, na="2026-12-01T09:00:00Z")


@C("revocation-missing", "The bundle has no revocation list.", ["05 section 5"], ["lifecycle", "revocation"], 2, ["revocation.missing"])
def _(b):
    b.revoked_present = False


@C("revocation-stale", "The list is older than next_update plus 48 hours.", ["05 section 5"], ["lifecycle", "revocation"], 2, ["revocation.stale"])
def _(b):
    b.revoked_payload.update({"issued_at": "2026-11-27T06:00:00Z", "next_update": "2026-11-28T06:00:00Z"})


@C("revocation-bad-signature", "The list is signed by a key that is not the revoker.", ["05 section 5"], ["lifecycle", "revocation"], 2,
   ["revocation.unverifiable"])
def _(b):
    b.revoked_signer = "attacker"
    b.revoked_keyid = KEYS["revoker-1"].kid


@C("revocation-wrong-estate", "A list for another estate says nothing about this one.", ["05 section 5"], ["lifecycle", "revocation"], 2,
   ["revocation.unverifiable"])
def _(b):
    b.revoked_payload["estate"] = OTHER_ESTATE


@C("revocation-best-effort-warn", "revocation: best_effort turns a missing list into a warning.", ["08 trust"], ["lifecycle", "revocation", "policy"], 0,
   warnings=["revocation.missing"], profile="policy")
def _(b):
    b.revoked_present = False
    b.policy = policy_json(trust={"revocation": "best_effort"})


@C("supersession-min-seq", "The list says no statement below seq 2 stands: the older HOLDS is rejected.", ["05 section 5"], ["lifecycle", "revocation"], 1,
   ["chain.superseded"])
def _(b):
    b.revoked_payload["superseded"] = [{"subject": "dns:" + DOMAIN, "min_seq": 2, "at": "2026-12-01T10:00:00Z"}]


# ------------------------------------------------------------------------------------------------ DNS
def _dns_rec(b, records, **kw):
    b.dns = [dns_fixture(records=records, **kw)]


@C("dns-mismatch", "A record names the right key id with a different fingerprint tail.", ["05 section 6.3"], ["dns"], 1, ["dns.mismatch"])
def _(b):
    k = KEYS["tenant-a"]
    _dns_rec(b, ["v=1; kid=%s; fp=sha256:%s%s" % (k.kid, k.kid, "0" * 32)])


@C("dns-nxdomain", "The name does not exist.", ["05 section 6.3"], ["dns"], 1, ["dns.no_binding"])
def _(b):
    b.dns = [dns_fixture(status=None)]


@C("dns-servfail", "The resolver answers SERVFAIL.", ["05 section 6.3"], ["dns"], 2, ["dns.lookup_failed"])
def _(b):
    b.dns = [dns_fixture(status="servfail")]


@C("dns-resolvers-disagree", "One resolver has the record and the other says it does not exist.", ["05 section 6.3"], ["dns"], 2, ["dns.resolvers_disagree"])
def _(b):
    b.dns = [dns_fixture(label="r1"), dns_fixture(label="r2", status=None)]


@C("dns-one-resolver-only", "Two resolvers are asked, one times out, two must answer.", ["05 section 6.3"], ["dns"], 2, ["dns.insufficient_resolvers"])
def _(b):
    b.dns = [dns_fixture(label="r1"), dns_fixture(label="r2", status="timeout")]
    b.args = ["--dns-min-resolvers", "2"]


@C("dns-offline", "No resolver is available offline.", ["05 section 6.3"], ["dns"], 2, ["dns.skipped_offline"])
def _(b):
    b.dns = []


@C("dns-record-malformed-only", "The only record is malformed: ignored with a warning, so no binding.", ["05 section 6.2"], ["dns"], 1, ["dns.no_binding"],
   warnings=["dns.record_ignored"])
def _(b):
    _dns_rec(b, ["v=1; kid=%s" % KEYS["tenant-a"].kid])


@C("dns-duplicate-field", "kid appears twice: the record is malformed.", ["05 section 6.2"], ["dns"], 1, ["dns.no_binding"], warnings=["dns.record_ignored"])
def _(b):
    k = KEYS["tenant-a"]
    _dns_rec(b, ["v=1; kid=%s; kid=%s; fp=%s" % (k.kid, k.kid, k.fp)])


@C("dns-uppercase-key", "An uppercase tag is not a tag: the record is malformed.", ["05 section 6.2"], ["dns"], 1, ["dns.no_binding"],
   warnings=["dns.record_ignored"])
def _(b):
    k = KEYS["tenant-a"]
    _dns_rec(b, ["V=1; kid=%s; fp=%s" % (k.kid, k.fp)])


@C("dns-same-kid-two-fps", "The same key id with two fingerprints.", ["05 section 6.3"], ["dns"], 1, ["dns.record_conflict"])
def _(b):
    k = KEYS["tenant-a"]
    _dns_rec(b, [WORKED["dns_txt"], "v=1; kid=%s; fp=sha256:%s%s" % (k.kid, k.kid, "0" * 32)])


@C("dns-too-many-records", "Nine binding records under the name.", ["05 section 6.2"], ["dns"], 1, ["dns.too_many_records"])
def _(b):
    _dns_rec(b, [WORKED["dns_txt"]] * 9)


@C("dnssec-required-unproven", "The policy requires DNSSEC and no resolver asserts it.", ["05 section 6.3"], ["dns", "policy"], 2, ["dns.dnssec_unproven"],
   profile="policy")
def _(b):
    b.policy = policy_json(trust={"dnssec": "required"})


@C("dns-foreign-kid-only", "The domain names another key only.", ["05 section 6.3"], ["dns"], 1, ["dns.no_binding"])
def _(b):
    _dns_rec(b, [txt_for(KEYS["tenant-b"])])


@C("estate-subject-policy-requires-dns", "A policy that requires DNS rejects a subject with no domain.", ["05 section 6.3"], ["dns", "policy"], 1,
   ["dns.not_applicable"], profile="policy", primary="dns.not_applicable")
def _(b):
    name = "paddock-estate:" + ESTATE
    b.stmt["subject"] = [{"name": name, "digest": {"sha256": sha(name.encode("ascii"))}}]
    b.bundle_domain = ""
    b.dns = []
    b.policy = policy_json()


# ------------------------------------------------------------------------------ disclosure, commitments
@C("cherry-pick-counts-visible", "holds_only with two of three std invariants disclosed: accepted, with the counts printed.", ["09 W-POLICY"],
   ["disclosure", "wording"], 0)
def _(b):
    assert b.pred["policy"]["disclosed"] == 2 and b.pred["policy"]["enabled_std"] == 3


@C("all-mode-missing-result", "verdicts=all but an enabled std invariant is not listed.", ["07 step 7"], ["disclosure"], 1, ["disclosure.inconsistent"])
def _(b):
    b.pred["disclosure"] = {"verdicts": "all", "custom": False}


@C("all-mode-custom-hidden", "verdicts=all and custom=true but an enabled custom invariant is not listed.", ["07 step 7"], ["disclosure"], 1,
   ["disclosure.inconsistent"])
def _(b):
    b.pred["disclosure"] = {"verdicts": "all", "custom": True}
    b.pred["policy"].update({"total": 4, "enabled_std": 3, "enabled_custom": 1})


@C("policy-shrank", "The declared policy has fewer invariants than in the previous statement.", ["07 step 6"], ["disclosure", "chain"], 1, ["policy.shrank"])
def _(b):
    b.chain(2)
    b.pred["policy"].update({"total": 2, "enabled_std": 2})


@C("counts-inconsistent", "disclosed does not equal the number of results.", ["02 section 3"], ["disclosure", "schema"], 1, ["schema.counts_inconsistent"])
def _(b):
    b.pred["policy"]["disclosed"] = 3


@C("counts-total-below-enabled", "More enabled invariants than declared ones.", ["02 section 3"], ["disclosure", "schema"], 1, ["schema.counts_inconsistent"])
def _(b):
    b.pred["policy"]["total"] = 2


@C("custom-id-without-flag", "A custom invariant is disclosed although custom disclosure is off.", ["07 step 7"], ["disclosure"], 1, ["disclosure.inconsistent"])
def _(b):
    enable_custom(b, [custom_result("acme:thing")])
    b.pred["disclosure"]["custom"] = False


@C("std-digest-weakened", "A std result carries a digest other than the registry's.", ["05 section 7"], ["disclosure"], 1, ["std.digest_mismatch"])
def _(b):
    b.result(0)["digest"] = "sha256:" + "00" * 32


@C("std-id-unknown", "A std: id that the ruleset does not define.", ["05 section 7"], ["disclosure"], 1, ["std.id_unknown"])
def _(b):
    b.pred["results"].append(mk_result("std:zzz-new", digest="sha256:" + "11" * 32))
    b.pred["policy"].update({"total": 4, "enabled_std": 4, "disclosed": 3})


@C("ruleset-unknown", "The engine's ruleset is not in this verifier's registry.", ["05 section 7"], ["disclosure"], 2, ["engine.ruleset_unknown"])
def _(b):
    b.pred["engine"]["ruleset"] = "sha256:" + "11" * 32


@C("engine-advisory", "The engine version has a known defect advisory.", ["05 section 7"], ["disclosure"], 1, ["engine.advisory"])
def _(b):
    reg = copy.deepcopy(REGISTRY)
    reg["advisories"] = [{"id": "PA-ADV-0001", "engine": "0.3.0", "effect": "reject", "summary": "false HOLDS defect"}]
    b.registry = compact(reg)


@C("engine-advisory-warn", "The same advisory marked warn.", ["05 section 7"], ["disclosure"], 0, warnings=["engine.advisory"])
def _(b):
    reg = copy.deepcopy(REGISTRY)
    reg["advisories"] = [{"id": "PA-ADV-0002", "engine": "0.3.0", "effect": "warn", "summary": "advisory"}]
    b.registry = compact(reg)


@C("limits-unknown-id", "The limits text id is not one this verifier knows.", ["09 section 6"], ["disclosure"], 1, ["limits.unknown"])
def _(b):
    b.pred["limits"]["id"] = "paddock-limits/2"


@C("limits-digest-mismatch", "The limits digest differs from the pinned text.", ["09 section 6"], ["disclosure"], 1, ["limits.digest_mismatch"])
def _(b):
    b.pred["limits"]["digest"] = "sha256:" + "22" * 32


@C("policy-disclosure-complete-fails", "The consumer requires complete disclosure and the issuer disclosed two of three.", ["08"], ["disclosure", "policy"], 1,
   ["policy.disclosure_incomplete"], profile="policy")
def _(b):
    b.policy = policy_json(disclosure="complete")


@C("merkle-proof-invalid", "A policy proof whose path was altered.", ["04"], ["merkle"], 1, ["merkle.proof_invalid"])
def _(b):
    p = merkle_proof("policy", POLICY_LEAVES, POLICY_LEAVES[0])
    p["path"][0] = "ff" * 32
    put_proofs(b, **{"policy.json": p})


@C("merkle-proof-cross-tree", "A graph leaf offered as a policy leaf.", ["04"], ["merkle"], 1, ["merkle.proof_invalid"])
def _(b):
    p = merkle_proof("graph", GRAPH_LEAVES, GRAPH_LEAVES[0])
    p["tree"] = "policy"
    put_proofs(b, **{"policy.json": p})


@C("merkle-proof-wrong-size", "A proof for a tree of another size than the statement commits to.", ["04"], ["merkle"], 1, ["merkle.proof_invalid"])
def _(b):
    p = merkle_proof("policy", POLICY_LEAVES, POLICY_LEAVES[0])
    p["size"] = 4
    put_proofs(b, **{"policy.json": p})


@C("merkle-proof-missing", "Proofs were requested but none exist for this sequence number.", ["07 step 10"], ["merkle"], 2, ["merkle.proof_missing"])
def _(b):
    b.case_extra["bundle/proofs/7/policy.json"] = compact(merkle_proof("policy", POLICY_LEAVES, POLICY_LEAVES[0]))
    b.args = ["--proofs-dir", "case/proofs"]


# --------------------------------------------------------------------------------------------- chain
def _state(seq, digest=None, anchor=None):
    e = {"seq": seq, "digest": digest or "sha256:" + sha(b"a statement seen before")}
    if anchor:
        e["anchor"] = anchor
    return {"state_version": 1, "subjects": {"dns:" + DOMAIN: e}}


@C("rollback-seq-regression", "The local state has seen seq 12; this is seq 10.", ["07 step 6"], ["chain"], 1, ["chain.seq_rollback"])
def _(b):
    b.chain(10)
    b.state = _state(12)


@C("fork-same-seq", "The local state saw another statement under the same sequence number.", ["07 step 6"], ["chain"], 1, ["chain.fork"])
def _(b):
    b.state = _state(1)


@C("state-continuity", "A newer statement whose prev is not the one the state saw.", ["07 step 6"], ["chain"], 1, ["chain.prev_mismatch"])
def _(b):
    b.chain(2)
    b.state = _state(1)


@C("prev-mismatch", "prev is not the hash of the previous statement in the bundle.", ["07 step 6"], ["chain"], 1, ["chain.prev_mismatch"])
def _(b):
    b.chain(2)
    b.pred["prev"] = "sha256:" + "ab" * 32


@C("seq-gap", "Statement 3 links to statement 1: statement 2 was withheld.", ["07 step 6"], ["chain"], 1, ["chain.seq_gap"])
def _(b):
    b.chain(2)
    first = b.history.pop(1)
    b.history[1] = first
    b.pred["seq"] = 3
    b.write_current_numbered = True
    digest = "sha256:" + sha(render(first)[0])
    b.index = [{"seq": 1, "statement_digest": digest, "issued_at": first["predicate"]["issued_at"], "valid_until": first["predicate"]["valid_until"],
                "kid": KEYS["tenant-a"].kid}]


@C("history-missing-optional", "Seq 2 but statement 1 is not in the bundle: a warning.", ["07 step 6"], ["chain"], 0, warnings=["chain.history_missing"])
def _(b):
    b.pred["seq"] = 2
    b.pred["prev"] = "sha256:" + sha(b"the statement that is not here")


@C("history-missing-required", "The same, with a policy that requires history.", ["07 step 6"], ["chain", "policy"], 2, ["chain.history_missing"], profile="policy")
def _(b):
    b.pred["seq"] = 2
    b.pred["prev"] = "sha256:" + sha(b"the statement that is not here")
    b.policy = policy_json(history="required")


@C("latest-vs-seq-differ", "latest.json differs byte for byte from the numbered statement.", ["06"], ["chain"], 1, ["chain.latest_mismatch"])
def _(b):
    b.chain(2)

    def post(files):
        files["attestation/2.json"] = json.dumps(json.loads(files["attestation/2.json"].decode("ascii")), indent=1, sort_keys=True).encode("ascii")
    b.post.append(post)


@C("anchor-max-id-regressed", "The anchored audit position is lower than in the previous statement.", ["07 step 6"], ["chain", "anchor"], 1,
   ["anchor.max_id_regressed"])
def _(b):
    def older(before):
        before["predicate"]["audit_anchor"]["max_id"] = 99200
        return before
    b.chain(2, prev_stmt=older)


@C("state-unreadable", "The state file is not a state document.", ["07 section 6"], ["chain"], 2, ["chain.state_unreadable"])
def _(b):
    b.state = {"state_version": 99}


@C("digest-changed-warning", "A custom invariant's definition changed since the previous statement.", ["07 step 6"], ["chain"], 0, warnings=["digest.changed"])
def _(b):
    enable_custom(b, [custom_result("acme:thing")])

    def older(before):
        for r in before["predicate"]["results"]:
            if r["invariant"] == "acme:thing":
                r["digest"] = "sha256:" + "99" * 32
        return before
    b.chain(2, prev_stmt=older)


@C("require-latest-not-latest", "A newer statement exists and the policy requires the latest.", ["08"], ["chain", "policy"], 1, ["chain.not_latest"], profile="policy")
def _(b):
    b.chain(2)
    b.target = {"kind": "file", "path": WK + "/attestation/1.json"}
    b.policy = policy_json(require_latest=True)


# ------------------------------------------------------------------------------ coverage, tier, results
@C("coverage-below-threshold", "36 of 40 is 90 percent; the baseline asks for 95.", ["03 section 3"], ["coverage"], 1, ["coverage.below_threshold"])
def _(b):
    b.result(0)["coverage"].update({"universe": 40, "covered": 36, "required_bp": 9000})


@C("coverage-18-of-20", "18 of 20 against 95 percent.", ["03 section 3"], ["coverage"], 1, ["coverage.below_threshold"])
def _(b):
    b.result(0)["coverage"].update({"universe": 20, "covered": 18, "required_bp": 9000})


@C("coverage-just-below-threshold", "9499 of 10000 is 94.99 percent: below 95, however it is rounded for display.", ["03 section 3"], ["coverage"], 1,
   ["coverage.below_threshold"])
def _(b):
    b.result(0)["coverage"].update({"universe": 10000, "covered": 9499, "required_bp": 9400})


@C("coverage-exactly-at-threshold-large", "9500 of 10000 is exactly 95 percent: accepted.", ["03 section 3"], ["coverage"], 0)
def _(b):
    b.result(0)["coverage"].update({"universe": 10000, "covered": 9500, "required_bp": 9500})


@C("coverage-universe-empty", "A HOLDS over an empty universe is vacuous.", ["03 section 3"], ["coverage"], 1, ["result.universe_empty"])
def _(b):
    b.result(0)["coverage"].update({"universe": 0, "covered": 0})


@C("coverage-covered-gt-universe", "More covered than the universe.", ["03 section 3"], ["coverage"], 1, ["result.coverage_inconsistent"])
def _(b):
    b.result(0)["coverage"].update({"universe": 42, "covered": 50})


@C("holds-below-own-floor", "39 of 42 does not reach the floor the statement itself applied (9500).", ["03 section 3"], ["coverage"], 1,
   ["result.coverage_inconsistent"])
def _(b):
    b.result(0)["coverage"].update({"universe": 42, "covered": 39})


@C("tier-declared-on-holds", "A HOLDS with the declared tier.", ["03 section 2"], ["tier"], 1, ["result.tier_invalid"])
def _(b):
    b.result(0)["tier"] = "declared"


@C("tier-tested-in-v1", "The tested tier is not valid in a v1 statement.", ["03 section 2"], ["tier"], 1, ["result.tier_invalid"])
def _(b):
    b.result(0)["tier"] = "tested"


@C("tier-above-cap", "A host-config result claiming the observed tier.", ["03 section 2"], ["tier"], 1, ["result.tier_above_cap"])
def _(b):
    b.result(1)["tier"] = "observed"


@C("tier-below-min", "The result's tier is below the invariant's own minimum.", ["03 section 2"], ["tier"], 1, ["result.tier_below_min"])
def _(b):
    b.result(0)["min_tier"] = "observed"


@C("tier-missing-on-holds", "A HOLDS without a tier.", ["02 section 4"], ["tier", "schema"], 1, ["schema.result_inconsistent"])
def _(b):
    b.result(0).pop("tier")


@C("selected-to-zero", "The invariant selects nothing: vacuous.", ["03 section 3"], ["results"], 1, ["result.selected_empty"])
def _(b):
    b.result(0)["selected"]["to"] = 0


@C("result-valid-until-before-issue", "A result whose validity is not after the issue time.", ["03 section 4"], ["results"], 1, ["result.valid_until_invalid"])
def _(b):
    b.result(1)["valid_until"] = "2026-12-01T09:00:00Z"
    b.now = "2026-12-01T08:58:00Z"


@C("boundary-dominant-warning", "Boundary labels cover more than half of the estate.", ["03 section 3"], ["results"], 0, warnings=["result.boundary_dominant"])
def _(b):
    b.result(0)["selected"]["stop_at"] = 70


@C("boundary-dominant-policy-limit", "The policy limits the boundary share to 25 percent.", ["08"], ["results", "policy"], 1, ["result.boundary_dominant"],
   profile="policy", primary="result.boundary_dominant")
def _(b):
    b.result(0)["selected"]["stop_at"] = 40
    b.policy = policy_json(require=[req("std:no-internet-to-datastore")], max_stop_at_share="0.25")


@C("required-missing", "The policy requires an invariant that is not in the attestation.", ["08"], ["policy"], 1, ["invariant.missing"], profile="policy")
def _(b):
    b.policy = policy_json(require=[req("std:public-ports-allowlist")])


@C("required-violated", "A required invariant is violated.", ["08"], ["policy"], 1, ["invariant.verdict_violated"], profile="policy")
def _(b):
    all_mode(b, ("HOLDS", "VIOLATED", "HOLDS"))
    b.policy = policy_json(require=[req("std:no-internet-to-datastore")])


@C("required-unknown", "A required invariant is undetermined.", ["08"], ["policy"], 1, ["invariant.verdict_unknown"], profile="policy")
def _(b):
    all_mode(b, ("HOLDS", "UNKNOWN", "HOLDS"))
    b.policy = policy_json(require=[req("std:no-internet-to-datastore")])


@C("unrequired-violation-default-reject", "A violated invariant nobody asked about still rejects.", ["03 section 1"], ["policy"], 1,
   ["invariant.unrequired_violation"])
def _(b):
    all_mode(b, ("VIOLATED", "HOLDS", "HOLDS"))


@C("unrequired-violation-warn", "violations: warn turns it into a warning.", ["08"], ["policy"], 0, warnings=["invariant.unrequired_violation"], profile="policy")
def _(b):
    all_mode(b, ("VIOLATED", "HOLDS", "HOLDS"))
    b.policy = policy_json(violations="warn")


@C("digest-pin-mismatch", "The policy pins another digest than the statement shows.", ["08"], ["policy"], 1, ["invariant.digest_mismatch"], profile="policy")
def _(b):
    b.policy = policy_json(require=[req("std:no-internet-to-datastore", digest="sha256:" + "ab" * 32)])


@C("exceptions-over-limit", "Three declared exceptions against a limit of one.", ["08"], ["policy"], 1, ["invariant.exceptions_over_limit"], profile="policy")
def _(b):
    b.result(0)["exceptions"] = 3
    b.policy = policy_json(require=[req("std:no-internet-to-datastore")], max_exceptions=1)


@C("tier-below-required", "The consumer requires the observed tier and the evidence is configured.", ["08"], ["policy"], 1, ["invariant.tier_below_required"],
   profile="policy")
def _(b):
    b.policy = policy_json(require=[req("std:no-internet-to-datastore", min_tier="observed")])


@C("required-age-exceeded", "The consumer wants evidence at most an hour old; the snapshot is three hours old.", ["08"], ["policy"], 1, ["invariant.age_exceeded"],
   profile="policy")
def _(b):
    b.policy = policy_json(require=[req("std:no-internet-to-datastore", max_age="1h")])


@C("required-coverage-threshold", "The consumer's own threshold for one invariant is stricter than the statement's floor.", ["08"], ["policy"], 1,
   ["coverage.below_threshold"], profile="policy")
def _(b):
    b.policy = policy_json(require=[req("std:no-internet-to-datastore", min_coverage="0.99")])


@C("holds-with-violations-field", "A HOLDS that also carries a violations count.", ["02 section 4"], ["results", "schema"], 1, ["schema.result_inconsistent"])
def _(b):
    b.result(0)["violations"] = 1


@C("violated-without-count", "A VIOLATED result without violations.", ["02 section 4"], ["results", "schema"], 1, ["schema.result_inconsistent"])
def _(b):
    all_mode(b, ("VIOLATED", "HOLDS", "HOLDS"))
    b.result(0).pop("violations")


@C("unknown-without-reason-codes", "An UNKNOWN result without reason codes.", ["02 section 4"], ["results", "schema"], 1, ["schema.result_inconsistent"])
def _(b):
    all_mode(b, ("UNKNOWN", "HOLDS", "HOLDS"))
    b.result(0).pop("reason_codes")


@C("verdict-expired-literal", "EXPIRED is derived, never issued.", ["03 section 1"], ["results", "schema"], 1, ["schema.enum_unknown"])
def _(b):
    b.result(0)["verdict"] = "EXPIRED"


@C("result-duplicate", "The same invariant twice.", ["02 section 3"], ["results", "schema"], 1, ["schema.result_duplicate"])
def _(b):
    b.pred["results"].insert(0, copy.deepcopy(b.result(0)))
    b.pred["policy"]["disclosed"] = 3


@C("result-unsorted", "Results are not in byte order.", ["02 section 3"], ["results", "schema"], 1, ["schema.result_unsorted"])
def _(b):
    b.pred["results"].reverse()


# ------------------------------------------------------------------------- versioning and strictness
@C("unknown-predicate-type", "A statement of a newer predicate type: authentic but not interpretable.", ["10"], ["strictness"], 2,
   ["predicate.unsupported_version"])
def _(b):
    b.stmt["predicateType"] = "https://paddock.dev/attestation/containment/v2"


@C("unknown-predicate-type-forged", "The same, but forged: the signature reports the reject.", ["07 section 2"], ["strictness", "authenticity"], 1,
   ["predicate.unsupported_version", "sig.invalid"])
def _(b):
    b.stmt["predicateType"] = "https://paddock.dev/attestation/containment/v2"
    b.signer = "attacker"
    b.keyid = KEYS["tenant-a"].kid


@C("unknown-key-in-predicate", "An unknown predicate field.", ["02 section 3"], ["strictness"], 1, ["schema.field_unknown"])
def _(b):
    b.pred["note"] = "hello"


@C("unknown-key-in-result", "An unknown result field.", ["02 section 4"], ["strictness"], 1, ["schema.field_unknown"])
def _(b):
    b.result(0)["note"] = "hello"


@C("unknown-verdict-value", "A verdict that is not HOLDS, VIOLATED or UNKNOWN.", ["02 section 4"], ["strictness"], 1, ["schema.enum_unknown"])
def _(b):
    b.result(0)["verdict"] = "MAYBE"


@C("unknown-tier-value", "A tier that is not in the vocabulary.", ["02 section 4"], ["strictness"], 1, ["schema.enum_unknown"])
def _(b):
    b.result(0)["tier"] = "platinum"


@C("unknown-reason-code", "An UNKNOWN reason code outside the enumeration.", ["02 section 4"], ["strictness"], 1, ["schema.enum_unknown"])
def _(b):
    all_mode(b, ("UNKNOWN", "HOLDS", "HOLDS"))
    b.result(0)["reason_codes"] = ["not-a-code"]


@C("predicate-has-null", "A null value in the payload (signed as it is).", ["01 section 2.1"], ["strictness"], 1, ["input.not_json"])
def _(b):
    payload_edit(b'"exceptions":0', b'"exceptions":null')(b)


@C("envelope-extra-key", "The envelope has a key besides the three.", ["02 section 1"], ["strictness", "dsse"], 1, ["schema.envelope_invalid"])
def _(b):
    b.env_hook = env_edit(lambda d, raw: d.__setitem__("extra", 1))


@C("statement-wrong-type", "_type is not the in-toto statement type.", ["02 section 2"], ["strictness"], 1, ["schema.statement_invalid"])
def _(b):
    b.stmt["_type"] = "https://in-toto.io/Statement/v0.1"


@C("subject-digest-wrong", "The subject digest is not the hash of the name.", ["02 section 2"], ["strictness"], 1, ["schema.subject_invalid"])
def _(b):
    b.stmt["subject"][0]["digest"]["sha256"] = "0" * 64


@C("digest-uppercase-hex", "A digest written in uppercase hex.", ["01 section 1"], ["strictness"], 1, ["schema.digest_format"])
def _(b):
    b.pred["scope"]["digest"] = "sha256:" + b.pred["scope"]["digest"][7:].upper()


@C("seq2-without-prev", "seq 2 without prev.", ["02 section 3"], ["strictness", "chain"], 1, ["schema.seq_prev_invalid"])
def _(b):
    b.pred["seq"] = 2


@C("seq1-with-prev", "seq 1 with prev.", ["02 section 3"], ["strictness", "chain"], 1, ["schema.seq_prev_invalid"])
def _(b):
    b.pred["prev"] = "sha256:" + "ab" * 32


@C("alg-unsupported", "The key's algorithm is not Ed25519: unverifiable, never a fallback.", ["01 section 2.5"], ["strictness", "ed25519"], 2,
   ["sig.alg_unsupported"])
def _(b):
    k = KEYS["tenant-a"]
    cert = cert_env(k.pub, "attest", KEYS["issuer-1"], ESTATE_NB, ESTATE_NA, ESTATE, 17, alg="ecdsa-p256-sha256")
    b.keys_doc["keys"][0] = keys_entry(k.pub, "attest", cert, alg="ecdsa-p256-sha256")


@C("keys-missing", "The bundle has no keys.json.", ["07 step 2"], ["strictness", "trust"], 2, ["keys.missing"])
def _(b):
    b.keys_bytes = b""


@C("keys-invalid", "keys.json has the wrong spec value.", ["05 section 3"], ["strictness", "trust"], 1, ["keys.invalid"])
def _(b):
    b.keys_doc["spec"] = "paddock-keys/v2"


@C("not-found", "The directory holds no attestation.", ["07 step 0"], ["strictness"], 2, ["input.not_found"])
def _(b):
    b.files_drop.add("attestation/latest.json")


@C("latest-is-a-directory", "attestation/latest.json exists but is a directory: present, yet not readable as a file.", ["07 step 0"], ["strictness"], 2,
   ["input.unreadable"])
def _(b):
    b.files_drop.add("attestation/latest.json")
    b.files_extra["attestation/latest.json/README"] = b"this is a directory, not an envelope\n"


# ---------------------------------------------------------------------------------------- encoding, JSON
@C("dup-keys-payload", "A duplicate key at depth 1 of the payload.", ["01 section 2.1"], ["encoding"], 1, ["input.duplicate_key"])
def _(b):
    b.payload = pcj(b.stmt)[:-1] + b',"_type":"https://in-toto.io/Statement/v1"}'


@C("dup-keys-payload-deep", "A duplicate key at depth 5 of the payload.", ["01 section 2.1"], ["encoding"], 1, ["input.duplicate_key"])
def _(b):
    raw = pcj(b.stmt)
    marker = b'"graph":{'
    assert marker in raw
    b.payload = raw.replace(marker, marker + b'"size":3,', 1)


@C("dup-keys-envelope", "A duplicate key in the envelope.", ["01 section 2.1"], ["encoding"], 1, ["input.duplicate_key"])
def _(b):
    b.env_hook = lambda env, raw: env.replace(b'{"payload"', b'{"payloadType":"x","payload"', 1)


@C("dup-keys-keysjson", "A duplicate key in keys.json.", ["01 section 2.1"], ["encoding"], 1, ["input.duplicate_key"])
def _(b):
    b.keys_bytes = compact(b.keys_doc)[:-1] + b',"spec":"paddock-keys/v1"}'


@C("noncanonical-key-order", "Keys in insertion order instead of byte order (validly signed).", ["01 section 2.1"], ["encoding"], 1,
   ["schema.payload_not_canonical"])
def _(b):
    b.payload = json.dumps(b.stmt, separators=(",", ":")).encode("ascii")
    assert b.payload != pcj(b.stmt)


def _num(token):
    def build(b):
        payload_edit(b'"seq":1', b'"seq":' + token)(b)
    return build


for _id, _tok, _code, _d in (("float-1.0", b"1.0", "input.number_invalid", "1.0"), ("float-exponent", b"1e2", "input.number_invalid", "1e2"),
                             ("int-2^53+1", b"9007199254740993", "input.number_invalid", "2^53 + 1"),
                             ("int-negative-zero", b"-0", "input.number_invalid", "-0"), ("int-leading-zero", b"01", "input.number_invalid", "01"),
                             ("nan-literal", b"NaN", "input.number_invalid", "NaN"), ("bool-as-int", b"true", "schema.field_invalid", "true")):
    C(_id, "seq is %s." % _d, ["01 section 2.1"], ["encoding"], 1, [_code])(_num(_tok))


@C("string-escape-u0041", "A string with a \\u escape (validly signed): not canonical.", ["01 section 2.1"], ["encoding"], 1, ["schema.payload_not_canonical"])
def _(b):
    payload_edit(b'"paddock-assurance"', b'"paddock-\\u0061ssurance"')(b)


@C("string-with-backslash", "A string containing an escaped backslash.", ["01 section 2.1"], ["encoding"], 1, ["schema.payload_not_canonical"])
def _(b):
    payload_edit(b'"version":"0.3.0"', b'"version":"0\\\\3"')(b)


@C("non-ascii-utf8", "A raw UTF-8 byte in the payload.", ["01 section 2.1"], ["encoding"], 1, ["input.not_ascii"])
def _(b):
    payload_edit(b'"paddock-assurance"', b'"paddock-assurance\xc3\xa9"')(b)


@C("bom-prefix", "A byte order mark before the payload.", ["01 section 2.1"], ["encoding"], 1, ["input.not_ascii"])
def _(b):
    b.payload = b"\xef\xbb\xbf" + pcj(b.stmt)


@C("trailing-newline-in-payload", "A newline after the payload (validly signed).", ["01 section 2.1"], ["encoding"], 1, ["schema.payload_not_canonical"])
def _(b):
    b.payload = pcj(b.stmt) + b"\n"


@C("trailing-garbage", "Bytes after the payload's closing brace.", ["01 section 2.1"], ["encoding"], 1, ["input.not_json"])
def _(b):
    b.payload = pcj(b.stmt) + b"x"


@C("json-depth-bomb", "A payload nested ten thousand levels deep.", ["01 section 3"], ["encoding", "limits"], 1, ["input.depth_exceeded"])
def _(b):
    b.payload = b"[" * 10000 + b"]" * 10000


def _b64_edit(fn):
    def build(b):
        def hook(env, raw):
            d = json.loads(env.decode("ascii"))
            d["payload"] = fn(d["payload"])
            return compact(d)
        b.env_hook = hook
    return build


def _urlsafe(p):
    assert "+" in p or "/" in p
    return p.replace("+", "-").replace("/", "_")


def _bits(p):
    assert p.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    i = alphabet.index(p[-3])
    assert i % 4 == 0
    return p[:-3] + alphabet[i + 1] + "=="


def _urlsafe_case(b):
    b.payload = pcj(b.stmt) + b" >>>>>>???"           # the base64 of these bytes contains + and /; the payload is never parsed
    _b64_edit(_urlsafe)(b)


C("b64-urlsafe-alphabet", "The payload uses the URL-safe base64 alphabet.", ["01 section 2.2"], ["encoding"], 1, ["schema.base64_invalid"])(_urlsafe_case)
C("b64-no-padding", "The payload's base64 has no padding.", ["01 section 2.2"], ["encoding"], 1, ["schema.base64_invalid"])(_b64_edit(lambda p: p.rstrip("=")))
C("b64-whitespace", "A line break inside the payload's base64.", ["01 section 2.2"], ["encoding"], 1, ["schema.base64_invalid"])(
    _b64_edit(lambda p: p[:100] + "\n" + p[100:]))
C("b64-trailing-bits", "Non-zero trailing bits in the last base64 character.", ["01 section 2.2"], ["encoding"], 1, ["schema.base64_invalid"])(_b64_edit(_bits))


@C("huge-envelope", "An envelope padded to 600000 bytes by the runner.", ["01 section 3"], ["encoding", "limits"], 1, ["input.too_large"])
def _(b):
    b.recipes = [{"op": "pad_file", "file": WK + "/attestation/latest.json", "bytes": 600000}]


@C("huge-results-array", "257 results.", ["01 section 3"], ["encoding", "limits"], 1, ["schema.limit_exceeded"])
def _(b):
    many_results(b, 257)


@C("long-string", "A string longer than 512 bytes.", ["01 section 3"], ["encoding", "limits"], 1, ["schema.limit_exceeded"])
def _(b):
    b.pred["engine"]["version"] = "1" * 600


def many_results(b, n):
    res = [custom_result("acme:inv-%04d" % i) for i in range(n)]
    b.pred["results"] = res
    b.pred["disclosure"] = {"verdicts": "holds_only", "custom": True}
    b.pred["policy"].update({"total": n, "enabled_std": 0, "enabled_custom": n, "disclosed": n, "versions": n})


# ------------------------------------------------------------------------------------------------ anchor
@C("anchor-required-field-absent", "The policy requires an anchor and the statement has none.", ["B section 3"], ["anchor", "policy"], 1,
   ["anchor.unavailable"], profile="policy", primary="anchor.unavailable")
def _(b):
    b.pred.pop("audit_anchor")
    b.policy = policy_json(anchor="required")


@C("anchor-doc-missing-optional", "The anchor document is not in the bundle and anchors are optional.", ["B section 3"], ["anchor", "policy"], 0,
   warnings=["anchor.unavailable"], profile="policy")
def _(b):
    b.ship_anchor = False
    b.policy = policy_json(anchor="optional")


@C("anchor-doc-missing-required", "The anchor document is not in the bundle and the policy requires it.", ["B section 3"], ["anchor", "policy"], 2,
   ["anchor.unavailable"], profile="policy")
def _(b):
    b.ship_anchor = False
    b.policy = policy_json(anchor="required")


@C("anchor-not-ed25519", "A version 1 anchor (HMAC only) is offered.", ["B section 3"], ["anchor", "policy"], 1, ["anchor.not_ed25519"], profile="policy")
def _(b):
    legacy = {"hash_alg": "hmac-sha256", "head": ANCHOR_HEAD, "kid": "audit-key-1", "max_id": 99120, "sig": "0" * 64, "tenant_id": "x", "ts": "2026-12-01T08:59:40Z", "v": 1}
    b.files_extra["anchors/99120.json"] = pcj(legacy)
    b.policy = policy_json(anchor="optional")


@C("anchor-bad-signature", "The anchor signature does not verify.", ["B section 1"], ["anchor", "policy"], 1, ["anchor.invalid"], profile="policy")
def _(b):
    doc, raw = make_anchor()
    doc = dict(doc, sig=b64(bytes(64)))
    raw = pcj(doc)
    set_anchor(b, doc, raw)
    b.policy = policy_json(anchor="optional")


@C("anchor-wrong-key", "The anchor is signed by a key that is not an anchor key of this estate.", ["B section 1"], ["anchor", "policy"], 1, ["anchor.invalid"],
   profile="policy")
def _(b):
    doc, raw = make_anchor(signer="attacker")
    set_anchor(b, doc, raw)
    b.policy = policy_json(anchor="optional")


@C("anchor-mismatch", "The statement claims another chain head than the anchor shows.", ["B section 3"], ["anchor", "policy"], 1, ["anchor.mismatch"],
   profile="policy")
def _(b):
    b.pred["audit_anchor"]["head"] = "cd" * 32
    b.policy = policy_json(anchor="optional")


@C("anchor-too-old", "The anchor is three hours older than the statement.", ["B section 2"], ["anchor", "policy"], 1, ["anchor.too_old"], profile="policy")
def _(b):
    doc, raw = make_anchor(at="2026-12-01T06:00:00Z")
    set_anchor(b, doc, raw)
    b.policy = policy_json(anchor="optional")


@C("anchor-independent-copy-differs", "The auditor's copy of the anchor is not the bundle's.", ["B section 2"], ["anchor"], 1, ["anchor.mismatch"])
def _(b):
    doc, raw = make_anchor(head="ef" * 32)
    b.files_extra["anchor-copy.json"] = raw
    b.anchor = WK + "/anchor-copy.json"


# ---------------------------------------------------------------------------------------------- wording
@C("human-wording", "The exact HOLDS line and the footer are pinned by the wording tests (this is the worked example).", ["09"], ["wording"], 0)
def _(b):
    pass


@C("hostile-custom-id", "A custom invariant id that contains a forbidden word is printed only in code style.", ["09 section 5"], ["wording"], 0)
def _(b):
    enable_custom(b, [custom_result("acme:fully-secure")])


# ====================================================================================== producer inputs
def producer_inputs(b):
    """What an issuer is given to reproduce valid-minimal-holds byte for byte (spec/12 section 1)."""
    res_a, res_b = b.result(0), b.result(1)

    def engine_result(r, reasons, blind, holds_until, hosts=None):
        out = {"invariant": r["invariant"], "digest": r["digest"], "severity": "high", "assertion": r["assertion"], "verdict": "HOLDS",
               "reasons": reasons, "evaluated_at": "2026-12-01T08:57:12.250000Z", "valid_until": holds_until, "evidence_tier": r["tier"],
               "coverage": {"universe": 120, "covered": 118, "ratio": 0.9833, "required": 0.95, "relevant_universe": r["coverage"]["universe"],
                            "relevant_covered": r["coverage"]["covered"], "relevant_ratio": round(r["coverage"]["covered"] / r["coverage"]["universe"], 4)},
               "violation_count": 0, "violating_targets": [], "violating_truncated": False, "unproven_targets": [], "witnesses": [],
               "blind_spots": blind, "exceptions_used": [], "expired_exceptions": [], "confirmation": "not_run", "boundaries_reached": []}
        if hosts:
            out["hosts"] = hosts
            out["passing_targets"] = []
            out["passing_truncated"] = False
        return out

    res_a_engine = engine_result(res_a, [], [{"node": BLIND_LEAVES[0]["node"], "reason": "stale", "relevant": True, "direction": "in"}],
                                 "2026-12-02T08:40:00.987654Z")
    res_b_engine = engine_result(res_b, [], [], "2026-12-01T14:50:00.5Z", hosts={"selected": 3, "holds": 3, "violated": 0, "unknown": 0})
    res_b_engine["coverage"].update({"required": 1.0, "relevant_ratio": 1.0})
    return {
        "commit_key_hex": COMMIT_KEY.hex(), "key_seed_hex": gv.seed_for("tenant-a").hex(), "anchor_seed_hex": gv.seed_for("anchor-a").hex(),
        "estate": ESTATE, "subject": "dns:" + DOMAIN, "seq": 1, "prev": None, "issued_at": b.pred["issued_at"], "valid_until": b.pred["valid_until"],
        "snapshot_at": b.pred["snapshot"]["at"], "graph_records": GRAPH_LEAVES, "scope_document": {"entries": [{"kind": "domain", "value": DOMAIN}], "v": 1},
        "scope_counts": {"unproven": 0, "private": 0}, "policy_rows": POLICY_LEAVES, "policy_versions": 3,
        "disclosure": b.pred["disclosure"], "engine": b.pred["engine"], "limits": b.pred["limits"],
        "selected": {res_a["invariant"]: res_a["selected"], res_b["invariant"]: res_b["selected"]},
        "engine_results": [res_a_engine, res_b_engine], "anchor": ANCHOR_DOC,
        "note": "engine_results are in the shape of Result.to_dict(); blind_spots are the full in-memory lists; "
                "graph_records are the committed leaf records (after the exclusion rule) and policy_rows the leaf records of every declared invariant"}


# ====================================================================================== output
def case_json(c, b, files_prefix=""):
    exit_ = c["exit"]
    decision = {0: "accepted", 1: "rejected", 2: "unverifiable"}[exit_]
    profile = c["profile"] or ("policy" if (b.policy is not None or any(a in b.args for a in ("--max-age", "--min-coverage", "--require", "--history"))) else "baseline")
    primary = c["primary"]
    if primary is None and c["codes"]:
        want = "R" if exit_ == 1 else "U"
        primary = next((code for code in c["codes"] if CLASSES[code] == want), None)
        assert primary is not None, "%s: exit %d but the codes %s have no class %s" % (c["id"], exit_, c["codes"], want)
    dns = None
    if b.dns:
        dns = b.dns[0] if len(b.dns) == 1 else {"resolvers": b.dns}
    doc = {"id": c["id"], "description": c["desc"], "spec_refs": c["refs"], "tags": sorted(set(c["tags"])), "producer": c["producer"], "now": b.now,
           "target": b.target, "args": b.args, "policy": b.policy, "dns": dns, "state": b.state, "anchor": b.anchor,
           "roots": b.roots if b.roots in ("test", "none") else "roots.json",
           "registry": "default" if b.registry == "default" else "registry.json", "recipes": b.recipes,
           "expect": {"exit": exit_, "decision": decision, "codes": c["codes"], "warnings": c["warnings"], "primary": primary, "profile": profile,
                      "forbidden_terms": True}}
    if b.inputs is not None:
        doc["inputs"] = b.inputs
    return doc


def parse_classes():
    path = os.path.join(SPEC_DIR, "spec", "A-reason-codes.md")
    out = {}
    for line in open(path, "r", encoding="ascii"):
        m = re.match(r"\| (\S+) \| `([a-z_]+\.[a-z0-9_]+)` \| ([RUWX]) \|", line)
        if m:
            out[m.group(2)] = m.group(3)
    assert len(out) > 100, len(out)
    return out


CLASSES = parse_classes()


def generate():
    """{relative path under vectors/: bytes} for every case, the test roots and the manifest."""
    files = {}
    ids = set()
    covered = set()
    for c in CASES:
        assert c["id"] not in ids, c["id"]
        ids.add(c["id"])
        assert re.match(r"^[a-z0-9][a-z0-9.^+-]{0,63}$", c["id"]), c["id"]
        b = Bk()
        c["build"](b)
        for code in c["codes"] + c["warnings"]:
            assert code in CLASSES, (c["id"], code)
            covered.add(code)
        base = "cases/%s/" % c["id"]
        files[base + "case.json"] = (json.dumps(case_json(c, b), sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")
        for rel, data in sorted(b.build().items()):
            files[base + "bundle/" + WK + "/" + rel] = data
        for rel, data in sorted(b.case_files().items()):
            files[base + rel] = data
    files["test-roots.json"] = (json.dumps(roots_doc(), sort_keys=True, indent=2) + "\n").encode("ascii")
    prim = gv.generate()
    manifest = {"spec_version": SPEC_VERSION, "generator": ["tools/gen_vectors.py", "tools/gen_cases.py"], "cases": len(CASES),
                "codes_covered": sorted(covered), "codes_not_expressible_by_the_runner": sorted(set(CLASSES) - covered),
                "files": dict(sorted([("primitives/" + n, sha(d)) for n, d in prim.items()] + [(k, sha(v)) for k, v in files.items()]))}
    files["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="compare with the committed files, write nothing")
    args = ap.parse_args(argv)
    files = generate()
    if args.check:
        bad = []
        for rel, data in files.items():
            p = os.path.join(args.out, rel)
            if not os.path.exists(p):
                bad.append("missing " + rel)
            elif open(p, "rb").read() != data:
                bad.append("differs " + rel)
        have = set()
        for sub in ("cases",):
            for dirpath, _d, names in os.walk(os.path.join(args.out, sub)):
                for n in names:
                    have.add(os.path.relpath(os.path.join(dirpath, n), args.out).replace(os.sep, "/"))
        bad += ["unexpected " + e for e in sorted(have - set(files))]
        if bad:
            sys.stderr.write("cases are stale: %s\n" % ", ".join(bad[:20]))
            return 1
        print("cases are up to date (%d cases, %d files)" % (len(CASES), len(files)))
        return 0
    cases_dir = os.path.join(args.out, "cases")
    if os.path.isdir(cases_dir):
        import shutil
        shutil.rmtree(cases_dir)
    for rel, data in files.items():
        p = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
    print("wrote %d cases (%d files) to %s" % (len(CASES), len(files), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
