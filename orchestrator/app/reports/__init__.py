"""Reporting: executive report, weekly digest and compliance evidence packs.

- ``metrics``    -- the data layer: every number a report needs, for a window.
- ``digest``     -- weekly digest built per workspace, emitted as ``report.digest``.
- ``compliance`` -- control catalogues (``controls/*.json``) mapped to evidence.
- ``render``     -- self-contained HTML (Jinja2) and PDF (WeasyPrint).
- ``router``     -- ``/v1/reports/*``.

See docs/REPORTS.md.
"""
