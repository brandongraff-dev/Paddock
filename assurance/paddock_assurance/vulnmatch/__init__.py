"""Vulnerability matching for the KEV invariant (P2.1 section A, contract 1.6).

Pure library: no I/O, no clock except the ``now`` argument. ``vercmp`` orders dpkg and rpm versions,
``model`` holds the validated inputs, ``scopes`` the closed distro/kernel maps, ``match`` turns one host's
package list into a :class:`MatchResult` whose ``to_data()`` is the ``kev`` fact's data, and ``leaf``
decides ``host.kev.exploited_unpatched(N)`` over that data at evaluation time.
"""
from .leaf import LeafResult, describe_worst, evaluate_leaf
from .match import (CAP_NO_FIX, CAP_OPEN, CAP_UNKNOWN, FixIndex, MatchResult, NoFixItem, OpenItem, UnknownItem,
                    match_host)
from .model import (Evidence, Fix, HostInput, HostMeta, KernelInfo, KevEntry, KevSnapshot, ModelError, OsInfo, Row,
                    ScopeInfo, SnapshotRef, kev_ids_sha, parse_rows)
from .scopes import ScopeResolution, check_identity, resolve_scope
from .vercmp import VersionError, cmp_for, dpkg_cmp, rpm_cmp

__all__ = [
    "CAP_NO_FIX", "CAP_OPEN", "CAP_UNKNOWN", "Evidence", "Fix", "FixIndex", "HostInput", "HostMeta", "KernelInfo",
    "KevEntry", "KevSnapshot", "LeafResult", "MatchResult", "ModelError", "NoFixItem", "OpenItem", "OsInfo", "Row",
    "ScopeInfo", "ScopeResolution", "SnapshotRef", "UnknownItem", "VersionError", "check_identity", "cmp_for",
    "describe_worst", "dpkg_cmp", "evaluate_leaf", "kev_ids_sha", "match_host", "parse_rows", "resolve_scope", "rpm_cmp",
]
