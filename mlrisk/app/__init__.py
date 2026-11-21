"""palantir-asm mlrisk service.

An adaptive ML layer over the platform's OWN data:

  * a RISK RANKER that learns from analyst triage decisions (ticket / finding
    status) to prioritize open findings, with a transparent heuristic prior for
    the cold-start case, and
  * an ANOMALY DETECTOR that flags statistical outliers in the attack surface
    (hosts, assets, change velocity).

It ranks and surfaces; humans decide. It produces no offensive tooling and
makes no external calls. Every score is explainable (per-feature contributions)
and the cold-start state is always surfaced.
"""

__version__ = "0.1.0"
