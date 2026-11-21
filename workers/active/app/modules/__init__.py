"""Probe modules.

Each module:
* takes a scope_guard, politeness limiter and an orchestrator client
* scope-checks the target before touching it
* writes audit rows via orchestrator.outbound_log
* returns (assets, edges, findings) as dicts ready for bulk upsert
"""
