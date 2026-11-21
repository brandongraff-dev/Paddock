"""Stripe billing, trials/dunning and feature gating for the hosted edition.

See docs/BILLING.md. Billing is off unless ``STRIPE_SECRET_KEY`` is set;
self-hosted installs keep using signed license files (``app/licensing.py``).

* :mod:`.config`       -- environment settings, plan catalogue
* :mod:`.stripe`       -- httpx REST client + webhook signature verification
* :mod:`.entitlements` -- pure subscription-state -> entitlements
* :mod:`.events`       -- webhook events -> state (idempotent, ordered)
* :mod:`.service`      -- resolve a tenant's entitlements (cached)
* :mod:`.gate`         -- ``require_paid`` / ``require_quota`` (HTTP 402)
* :mod:`.metering`     -- meter events to Stripe, from the scheduler
* :mod:`.router`       -- ``/v1/billing*``;  :mod:`.status` -- ``/status``
"""
