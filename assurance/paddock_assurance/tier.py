"""Evidence tiers, ordered: declared < configured < observed < tested."""
from __future__ import annotations

from enum import Enum


class Tier(str, Enum):
    """How strong the evidence behind a fact is. Ordered: declared < configured < observed < tested."""

    declared = "declared"      # the tenant says it should be so
    configured = "configured"  # a config says it is so (SG rule, firewall ruleset, sshd -T)
    observed = "observed"      # traffic or an outside scan saw it
    tested = "tested"          # a scope-proven active test confirmed it

    @property
    def rank(self) -> int:
        return _RANK[self.value]


_RANK = {"declared": 0, "configured": 1, "observed": 2, "tested": 3}
