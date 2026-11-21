"""Subscription state -> entitlements. Pure functions, no I/O.

State machine (hosted edition, billing on):

====================  =====================================================
subscription state    effective access
====================  =====================================================
no row, inside trial  Team (``trialing``, local trial anchored on signup)
no row, trial over    Community limits (``trial_expired``)
``trialing``/``active``  the plan's edition
``past_due``          the plan's edition until ``grace_until`` (dunning),
                      then Community limits (``payment_failed``)
``canceled``/``unpaid``/``incomplete``/``incomplete_expired``/``paused``
                      Community limits
====================  =====================================================

"Community limits" never delete anything: data stays and stays readable.
What is refused is *growth* past the Community allowance (see ``gate.py``),
and paid features answer 402. ``read_only`` is True while the tenant is
downgraded *and* currently over a Community limit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import licensing
from .config import BillingSettings, community_limits, plans, settings as default_settings

# Allowance for webhook delivery lag: Stripe moves a subscription out of
# `trialing` / `active` itself, so we only cut access this long AFTER the date
# the data says it should have changed.
WEBHOOK_LAG_SLACK = timedelta(hours=24)

_PAID_STATES = {"active", "trialing"}
_DEAD_STATES = {"canceled", "unpaid", "incomplete", "incomplete_expired", "paused"}


@dataclass(frozen=True)
class Subscription:
    """The slice of ``billing_subscriptions`` entitlement logic needs."""
    status: str
    plan: str | None = None
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    cancel_at_period_end: bool = False
    current_period_end: datetime | None = None
    trial_end: datetime | None = None
    payment_failed_at: datetime | None = None
    grace_until: datetime | None = None

    @classmethod
    def from_row(cls, row: Any) -> "Subscription":
        return cls(**{f: row[f] for f in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Entitlements:
    edition: str = "community"
    status: str = "community"          # trialing | active | past_due | trial_expired | payment_failed | canceled | community
    source: str = "default"            # default | trial | subscription | license
    plan: str | None = None
    features: frozenset[str] = field(default_factory=frozenset)
    seats: int | None = None
    sites: int | None = None
    assets: int | None = None
    trial_ends_at: datetime | None = None
    grace_ends_at: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    downgraded: bool = False           # on Community limits because billing says so
    dunning: bool = False              # payment failing but still inside the grace period
    has_customer: bool = False

    def has(self, feature: str) -> bool:
        return feature in self.features

    def limit(self, dimension: str) -> int | None:
        return {"seats": self.seats, "sites": self.sites, "assets": self.assets}[dimension]

    def trial_days_left(self, now: datetime | None = None) -> int | None:
        if self.trial_ends_at is None or self.status != "trialing":
            return None
        now = now or datetime.now(timezone.utc)
        secs = (self.trial_ends_at - now).total_seconds()
        return max(0, int(-(-secs // 86400)))  # ceil: "1 day left" until it ends

    def as_dict(self, now: datetime | None = None) -> dict[str, Any]:
        return {
            "edition": self.edition,
            "status": self.status,
            "source": self.source,
            "plan": self.plan,
            "features": sorted(self.features),
            "limits": {"seats": self.seats, "sites": self.sites, "assets": self.assets},
            "trial_ends_at": self.trial_ends_at,
            "trial_days_left": self.trial_days_left(now),
            "grace_ends_at": self.grace_ends_at,
            "current_period_end": self.current_period_end,
            "cancel_at_period_end": self.cancel_at_period_end,
            "downgraded": self.downgraded,
            "dunning": self.dunning,
            "has_customer": self.has_customer,
        }


def _community(status: str, *, cfg: BillingSettings, **kw: Any) -> Entitlements:
    lim = community_limits(cfg)
    kw.pop("plan", None)  # a downgraded tenant has no active plan
    return Entitlements(
        edition="community", status=status, source="subscription", plan=None, features=frozenset(),
        seats=lim["seats"], sites=lim["sites"], assets=lim["assets"], downgraded=True, **kw,
    )


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def trial_end_for(tenant_created_at: datetime | None, cfg: BillingSettings | None = None) -> datetime | None:
    """End of the signup trial: ``tenants.created_at`` + ``BILLING_TRIAL_DAYS``."""
    c = cfg or default_settings
    created = _as_utc(tenant_created_at)
    if created is None or c.billing_trial_days <= 0:
        return None
    return created + timedelta(days=c.billing_trial_days)


def compute_entitlements(
    sub: Subscription | None,
    tenant_created_at: datetime | None,
    now: datetime | None = None,
    cfg: BillingSettings | None = None,
) -> Entitlements:
    c = cfg or default_settings
    now = now or datetime.now(timezone.utc)
    catalogue = plans(c)

    # --- never subscribed: the signup trial of Team, then Community -------- #
    if sub is None:
        end = trial_end_for(tenant_created_at, c)
        if end is not None and now < end:
            team = catalogue["team"]
            return Entitlements(
                edition="team", status="trialing", source="trial", plan="team",
                features=licensing.edition_features("team"),
                seats=team.seats, sites=team.sites, assets=team.assets, trial_ends_at=end,
            )
        return _community("trial_expired", cfg=c, trial_ends_at=end)

    plan = catalogue.get(sub.plan or "")
    customer = bool(sub.stripe_customer_id)
    period_end = _as_utc(sub.current_period_end)
    common = dict(
        plan=sub.plan, current_period_end=period_end, cancel_at_period_end=sub.cancel_at_period_end,
        has_customer=customer,
    )

    def entitled(status: str, **extra: Any) -> Entitlements:
        assert plan is not None
        return Entitlements(
            edition=plan.edition, status=status, source="subscription",
            features=licensing.edition_features(plan.edition),
            seats=plan.seats, sites=plan.sites, assets=plan.assets, **common, **extra,
        )

    if plan is None or sub.status in _DEAD_STATES:
        status = "canceled" if sub.status in {"canceled", "incomplete_expired"} else (
            "payment_failed" if sub.status == "unpaid" else "community")
        return _community(status, cfg=c, **common)

    if sub.status == "trialing":
        end = _as_utc(sub.trial_end)
        if end is not None and now >= end + WEBHOOK_LAG_SLACK:
            return _community("trial_expired", cfg=c, trial_ends_at=end, **common)
        return entitled("trialing", trial_ends_at=end)

    if sub.status == "past_due":
        grace = _as_utc(sub.grace_until)
        if grace is None:
            failed = _as_utc(sub.payment_failed_at)
            grace = failed + timedelta(days=c.billing_grace_days) if failed else None
        if grace is not None and now < grace:
            return entitled("past_due", grace_ends_at=grace, dunning=True)
        return _community("payment_failed", cfg=c, grace_ends_at=grace, **common)

    # active
    if sub.cancel_at_period_end and period_end is not None and now >= period_end + WEBHOOK_LAG_SLACK:
        # The `customer.subscription.deleted` webhook never arrived; do not
        # keep paid access forever on a subscription that ended.
        return _community("canceled", cfg=c, **common)
    return entitled("active")


def merge_with_license(ent: Entitlements, lic: licensing.License) -> Entitlements:
    """Best of billing and a signed license file (a hosted tenant normally has
    no license; this keeps an operator-installed key honoured)."""
    rank = licensing._EDITION_RANK
    if lic.status not in {"active", "grace"} or rank.get(lic.edition, 0) <= rank.get(ent.edition, 0):
        return ent
    return Entitlements(
        edition=lic.edition, status="active", source="license", plan=None, features=lic.features,
        seats=lic.seats, sites=lic.sites, assets=lic.assets,
        has_customer=ent.has_customer,
    )
