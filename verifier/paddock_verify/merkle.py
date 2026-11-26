# SPDX-License-Identifier: Apache-2.0
"""Blinded Merkle commitments (spec/04-merkle.md): RFC 6962 trees, RFC 9162 inclusion proofs.

* ``leaf_json``  = PCJ of the record (which always carries ``"tree"``: ``graph``, ``policy`` or ``blind``).
* ``nonce``      = HMAC-SHA256(commit_key, b"paddock/leaf-nonce/v1\\0" || SHA256(leaf_json)).
* ``leaf_hash``  = SHA256(0x00 || nonce || leaf_json);  ``node_hash`` = SHA256(0x01 || left || right).
* leaves are sorted by leaf hash (a set commitment) and identical leaves collapse to one.
* the empty tree has the root SHA256("").
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, List, NamedTuple, Optional, Sequence

from . import canon
from .jsonstrict import JsonError

CODE = "merkle.proof_invalid"
TREES = ("graph", "policy", "blind")
NONCE_CONTEXT = b"paddock/leaf-nonce/v1\x00"
EMPTY_ROOT = hashlib.sha256(b"").digest()
MAX_TREE_SIZE = 2 ** 40
MAX_PATH = 64
MAX_LEAF_DEPTH = 16           # containers, counting the record object itself

_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ROOT = re.compile(r"sha256:([0-9a-f]{64})\Z", re.ASCII)


class MerkleError(JsonError):
    """A proof that does not verify (code ``merkle.proof_invalid``)."""

    def __init__(self, message: str = "") -> None:
        super().__init__(CODE, message)


def leaf_nonce(commit_key: bytes, leaf_json: bytes) -> bytes:
    return hmac.new(bytes(commit_key), NONCE_CONTEXT + hashlib.sha256(leaf_json).digest(), hashlib.sha256).digest()


def leaf_hash(nonce: bytes, leaf_json: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + bytes(nonce) + bytes(leaf_json)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + bytes(left) + bytes(right)).digest()


def root(leaf_hashes: Sequence[bytes]) -> bytes:
    """Root over the hashes in the given order (RFC 6962 shape: split at the largest power of two below n)."""
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_ROOT
    stack = []  # type: List[List[Any]]    # [height, hash]; perfect subtrees of decreasing size
    for h in leaf_hashes:
        stack.append([0, bytes(h)])
        while len(stack) >= 2 and stack[-1][0] == stack[-2][0]:
            right = stack.pop()
            left = stack.pop()
            stack.append([right[0] + 1, node_hash(left[1], right[1])])
    acc = stack.pop()[1]
    while stack:
        acc = node_hash(stack.pop()[1], acc)
    return acc


def root_str(leaf_hashes: Sequence[bytes]) -> str:
    return "sha256:" + root(leaf_hashes).hex()


def _split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def inclusion_path(leaf_hashes: Sequence[bytes], index: int) -> List[bytes]:
    """RFC 6962 section 2.1.1 PATH(index, D[n]) over already hashed leaves, in the order to be walked."""
    n = len(leaf_hashes)
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < n:
        raise ValueError("index out of range")
    hs = list(leaf_hashes)
    path = []  # type: List[bytes]
    lo, hi = 0, n
    # iterative PATH: record the sibling subtree hash at every split, then reverse (leaf-to-root order)
    while hi - lo > 1:
        k = _split(hi - lo)
        if index - lo < k:
            path.append(root(hs[lo + k:hi]))
            hi = lo + k
        else:
            path.append(root(hs[lo:lo + k]))
            lo = lo + k
    path.reverse()
    return path


def verify_inclusion(leaf: bytes, index: int, size: int, path: Sequence[bytes], expected_root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2, with no per-hop direction flags."""
    try:
        if isinstance(index, bool) or isinstance(size, bool) or not isinstance(index, int) or not isinstance(size, int):
            return False
        if size < 1 or index < 0 or index >= size or len(path) > MAX_PATH:
            return False
        if len(leaf) != 32 or len(expected_root) != 32 or any(len(p) != 32 for p in path):
            return False
        fn, sn, r = index, size - 1, bytes(leaf)
        for p in path:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = node_hash(p, r)
                if not fn & 1:
                    while not fn & 1 and fn != 0:
                        fn >>= 1
                        sn >>= 1
            else:
                r = node_hash(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and hmac.compare_digest(r, bytes(expected_root))
    except TypeError:
        return False


class LeafEncodingError(ValueError):
    """A graph value that PCJ cannot hold and that has no defined lossless replacement (``graph_unencodable``).

    The issuer fails closed on it: no statement is issued and the previous one lapses. A lossy encoding is never used.
    """


def _pcj_string(value: str) -> bool:
    return all(0x20 <= ord(ch) <= 0x7E and ch not in '"\\' for ch in value)


def encode_leaf_value(value: Any, _depth: int = 0) -> Any:
    """Prepare a graph-tree record value for PCJ (spec/04-merkle.md section 3.3).

    A key whose value is ``None`` is omitted; a string outside the PCJ charset is replaced by
    ``{"$h": "sha256:<hex of its UTF-8 bytes>"}``; booleans, integers within 0..2^53-1 and PCJ strings pass; anything
    else (a float, a negative or huge integer, a non-string or out-of-charset key, ``None`` inside a list, nesting
    deeper than 16 containers) raises ``LeafEncodingError``.
    """
    if value is True or value is False:
        return value
    if isinstance(value, int):
        if not 0 <= value <= 2 ** 53 - 1:
            raise LeafEncodingError("integer outside 0..2^53-1")
        return value
    if isinstance(value, str):
        if _pcj_string(value):
            return value
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError:
            raise LeafEncodingError("a string that is not valid Unicode") from None
        return {"$h": "sha256:" + hashlib.sha256(raw).hexdigest()}
    if isinstance(value, (list, dict)) and _depth >= MAX_LEAF_DEPTH:
        raise LeafEncodingError("nesting too deep")
    if isinstance(value, list):
        return [encode_leaf_value(x, _depth + 1) for x in value]
    if isinstance(value, dict):
        out = {}  # type: Dict[str, Any]
        for k, x in value.items():
            if not isinstance(k, str) or k == "" or not _pcj_string(k):
                raise LeafEncodingError("a key outside the PCJ charset")
            if x is not None:
                out[k] = encode_leaf_value(x, _depth + 1)
        return out
    raise LeafEncodingError("type %s cannot be committed" % type(value).__name__)


class Leaf(NamedTuple):
    record: Dict[str, Any]
    leaf_json: bytes
    nonce: bytes
    leaf_hash: bytes


class Tree:
    """A built tree: sorted de-duplicated leaves, the root and proof generation."""

    def __init__(self, label: str, leaves: List[Leaf]) -> None:
        self.label = label
        self.leaves = leaves
        self._hashes = [leaf.leaf_hash for leaf in leaves]
        self.root = root(self._hashes)

    @property
    def size(self) -> int:
        return len(self.leaves)

    @property
    def root_str(self) -> str:
        return "sha256:" + self.root.hex()

    def proof(self, index: int) -> Dict[str, Any]:
        """The inclusion-proof file of spec/04-merkle.md (private data: it carries the record and the nonce)."""
        leaf = self.leaves[index]
        return {"v": 1, "tree": self.label, "size": self.size, "index": index, "nonce": leaf.nonce.hex(),
                "record": dict(leaf.record), "path": [p.hex() for p in inclusion_path(self._hashes, index)]}


def build_tree(label: str, records: Sequence[Dict[str, Any]], commit_key: bytes) -> Tree:
    if label not in TREES:
        raise ValueError("unknown tree label %r" % (label,))
    if not isinstance(commit_key, (bytes, bytearray)) or len(commit_key) != 32:
        raise ValueError("commit_key is 32 bytes")
    unique = {}  # type: Dict[bytes, Leaf]
    for rec in records:
        if not isinstance(rec, dict) or "tree" in rec:
            raise ValueError("a record is an object without a 'tree' key")
        lj = canon.dumps(dict(rec, tree=label))
        if lj not in unique:
            nonce = leaf_nonce(commit_key, lj)
            unique[lj] = Leaf(rec, lj, nonce, leaf_hash(nonce, lj))
    leaves = sorted(unique.values(), key=lambda leaf: leaf.leaf_hash)
    return Tree(label, leaves)


def verify_proof(proof: Any, expected_root: str, expected_tree: Optional[str] = None, expected_size: Optional[int] = None) -> None:
    """Check an inclusion-proof file against a root such as ``sha256:<hex>``; raise ``MerkleError`` otherwise.

    The tree label is part of the hashed leaf, so a leaf of the graph tree cannot be passed off as a policy leaf.
    Only the right-most leaf's path commits to the tree size, so a consumer that knows the size it expects (the
    ``blind_spots.size``, ``snapshot.graph.size`` or ``policy.total`` of the statement) MUST pass ``expected_size``.
    """
    if not isinstance(expected_root, str) or not _ROOT.match(expected_root):
        raise MerkleError("the root is sha256:<64 lowercase hex>")
    if not isinstance(proof, dict) or set(proof) != {"v", "tree", "size", "index", "nonce", "record", "path"}:
        raise MerkleError("a proof has exactly v, tree, size, index, nonce, record and path")
    v, tree, size, index = proof["v"], proof["tree"], proof["size"], proof["index"]
    if type(v) is not int or v != 1 or tree not in TREES or (expected_tree is not None and tree != expected_tree):
        raise MerkleError("unsupported version or wrong tree")
    if expected_size is not None and (type(expected_size) is not int or expected_size < 1 or size != expected_size):
        raise MerkleError("the proof is for a tree of a different size")
    for x in (size, index):
        if isinstance(x, bool) or not isinstance(x, int):
            raise MerkleError("size and index are integers")
    if not 1 <= size <= MAX_TREE_SIZE or not 0 <= index < size:
        raise MerkleError("size or index out of range")
    nonce, record, path = proof["nonce"], proof["record"], proof["path"]
    if not isinstance(nonce, str) or not _HEX64.match(nonce):
        raise MerkleError("the nonce is 64 lowercase hex characters")
    if not isinstance(record, dict) or "tree" in record:
        raise MerkleError("the record is an object without a 'tree' key")
    if not isinstance(path, list) or len(path) > MAX_PATH or not all(isinstance(p, str) and _HEX64.match(p) for p in path):
        raise MerkleError("the path is a list of 64-hex hashes")
    try:
        lj = canon.dumps(dict(record, tree=tree))
    except canon.CanonError:
        raise MerkleError("the record cannot be encoded") from None
    lh = leaf_hash(bytes.fromhex(nonce), lj)
    if not verify_inclusion(lh, index, size, [bytes.fromhex(p) for p in path], bytes.fromhex(expected_root[7:])):
        raise MerkleError("the path does not lead to the root")
