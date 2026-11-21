"""Verified findings: find -> prove it's real -> fix -> prove it's fixed.

* ``service``  -- orchestration: scope/proof gate, ledger, queueing, applying
  results, prove-fixed, sweep. (schema 026)
* ``router``   -- HTTP API (verify / history / bulk / worker callback).
* ``models``   -- request/response models.

The safe checks themselves run in the active worker
(``workers/active/app/modules/safe_checks``); nothing here touches a target.
See docs/VERIFICATION.md.
"""
