"""Provable containment, P3: signed attestations (docs/ASSURANCE_P3.md).

Layout (each module is owned by the work package named in section 10 of the contract):

  config.py          AttestSettings (env prefix PADDOCK_ATTEST_)                 P3.2
  crypto.py          KEK sealing (AES-256-GCM, HKDF per tenant/kind/kid) and the
                     only SQL on the sealed-secrets table, besides backend_local P3.2
  backend.py         the KeyBackend interface, KeyHandle, errors                 P3.2
  backend_local.py   LocalAesGcmBackend (hosted custody)                        P3.2
  estate.py          estate bootstrap: estate id and the blinding commit_key     P3.2
  wiring.py          router / loop discovery hook used by main.py                P3.2

Importing this package stays cheap and side-effect free: no module here opens a connection, reads a key or starts a
task at import time (``scripts/export_openapi.py`` imports ``app.main``).
"""
