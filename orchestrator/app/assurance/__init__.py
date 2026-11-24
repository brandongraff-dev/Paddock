"""Provable containment, P1: persistent reach graph, builders, evaluation runner.

Layout (see docs/ASSURANCE_P1.md for the contract each module implements):

  refs.py            node-reference helpers (shared vocabulary)
  types.py           builder input/output dataclasses (shared contract)
  builders/*.py      PURE functions: stored rows in, nodes/edges/coverage out. No DB, no clock.
  loaders.py         tenant-scoped SQL that fetches the rows the builders need
  store.py           persists a BuildOutput (replace-by-source diff, graph_version bump)
  graph_loader.py    tables -> paddock_assurance ReachGraph document
  runner.py          per-tenant evaluate loop, lease, run ledger
  findings_sync.py   verdicts -> findings (open / refresh / close / reopen)

The pure evaluator lives in the sibling package ``paddock_assurance`` (repo-root /assurance).
Import it lazily (inside functions) so modules that only describe routes still import where
the library is not installed (e.g. the OpenAPI export job).
"""
