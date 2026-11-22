"""Growth features built on PASSIVE data only.

* ``domains``    -- public-domain validation (no IPs, no internal names).
* ``engine``     -- the passive assessment (DNS + certificate transparency).
* ``abuse``      -- rate limits, daily cap, CAPTCHA hook for public endpoints.
* ``exposure``   -- the free public exposure report (queue, cache, leads).
* ``trust``      -- shareable trust / posture pages.
* ``suppliers``  -- scheduled third-party assessments + events.

Nothing in this package sends a packet to a target: DNS answers come from a
recursive resolver and certificate data from CT logs. See docs/GROWTH.md.
"""
