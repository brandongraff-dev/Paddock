"""Provable containment (P0): invariants, a directed reach graph, counterexample search.

Pure library: no network, no database, no clock except what the caller passes in.
Pipeline: ``parse_invariant`` -> ``compile_invariant`` -> ``evaluate(plan, graph, now)``.
"""
from .compile import CompileError, Plan, PlanKind, compile_invariant, compile_text
from .evaluate import Result, Verdict, evaluate
from .graph import GraphError, ReachGraph
from .model import Invariant, Tier
from .parse import ParseError, parse_invariant

__version__ = "0.1.0"

__all__ = [
    "CompileError", "GraphError", "Invariant", "ParseError", "Plan", "PlanKind", "ReachGraph",
    "Result", "Tier", "Verdict", "compile_invariant", "compile_text", "evaluate",
    "parse_invariant",
]
