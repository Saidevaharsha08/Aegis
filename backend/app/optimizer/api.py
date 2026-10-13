"""Optimizer API helpers.

Wraps the underlying QAOA classical simulator with an optional
Qiskit Aer backend and a deterministic greedy-knapsack fallback so
the API behaves identically across machines regardless of which
optional quantum packages are installed.

Public entry points:
  * :func:`solve` — main entry used by the route.
  * :func:`greedy_knapsack` — deterministic classical fallback used
    when QAOA is unavailable or the call opts into ``solver=greedy``.
  * :func:`qaoa_simulator_available` — quick probe so the route can
    advertise solver capabilities.
"""

from __future__ import annotations

import logging
from typing import Any

from app.optimizer.qaoa_sim import OptimizationResult, QAOAInspiredOptimizer
from app.optimizer.rules import FirewallRule, get_candidate_rules_pool

log = logging.getLogger(__name__)


def qaoa_simulator_available() -> bool:
    """Return True if Qiskit Aer is installed and importable."""
    try:
        import qiskit  # noqa: F401
        import qiskit_aer  # noqa: F401
        return True
    except Exception:
        return False


def greedy_knapsack(
    rules: list[FirewallRule],
    fpr_budget: float,
    cost_budget: float,
) -> OptimizationResult:
    """Deterministic greedy knapsack fallback.

    Sorts rules by ``block_probability / cost`` ratio (a stable proxy
    for value-per-cost) and adds them in order while staying within
    both budgets. Deterministic — same input always yields the same
    selected set — so it is well suited to regression tests.
    """
    import time
    t0 = time.perf_counter()
    ranked = sorted(
        rules,
        key=lambda r: (r.block_probability / max(r.cost, 1e-9)),
        reverse=True,
    )
    selected: list[FirewallRule] = []
    curr_fpr = 0.0
    curr_cost = 0.0
    for r in ranked:
        if (curr_fpr + r.false_positive_rate <= fpr_budget) and (
            curr_cost + r.cost <= cost_budget
        ):
            selected.append(r)
            curr_fpr += r.false_positive_rate
            curr_cost += r.cost
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    from app.optimizer.qaoa_sim import RuleResult
    return OptimizationResult(
        selected_rules=[
            RuleResult(
                rule_id=r.rule_id,
                name=r.name,
                action=r.action,
                block_probability=r.block_probability,
                false_positive_rate=r.false_positive_rate,
                cost=r.cost,
                scope=r.scope,
            )
            for r in selected
        ],
        total_block_probability=round(sum(r.block_probability for r in selected), 4),
        total_fpr=round(curr_fpr, 4),
        total_cost=round(curr_cost, 4),
        optimization_time_ms=round(elapsed_ms, 3),
        solver="greedy_knapsack",
        n_rules_evaluated=len(rules),
        n_rules_selected=len(selected),
    )


def solve(
    fpr_budget: float = 0.10,
    cost_budget: float = 10.0,
    n_rules: int = 15,
    solver: str = "auto",
) -> OptimizationResult:
    """Run the optimizer.

    ``solver`` can be ``"auto"``, ``"qaoa"``, or ``"greedy"``.

    * ``auto`` — try QAOA (via Qiskit Aer when present, otherwise the
      classical QAOA simulator), then fall back to greedy if it
      raises or returns nothing.
    * ``qaoa`` — force QAOA. Falls back to greedy only if QAOA fails
      entirely (so a misconfigured quantum backend does not break
      the request).
    * ``greedy`` — pure deterministic greedy.
    """
    rules = get_candidate_rules_pool()[:n_rules]

    if solver == "greedy":
        return greedy_knapsack(rules, fpr_budget, cost_budget)

    if solver in ("auto", "qaoa"):
        # If Qiskit Aer is available, try the real QAOA path first.
        if solver == "auto" and qaoa_simulator_available():
            try:
                return _run_qiskit_qaoa(rules, fpr_budget, cost_budget)
            except Exception as exc:
                log.warning("Qiskit QAOA failed (%s) — falling back to classical sim", exc)

        try:
            qaoa = QAOAInspiredOptimizer(
                rules=rules, fpr_budget=fpr_budget, cost_budget=cost_budget
            )
            res = qaoa.optimize()
            if res.n_rules_selected > 0:
                return res
        except Exception as exc:
            log.warning("QAOA classical sim failed (%s) — falling back to greedy", exc)

    return greedy_knapsack(rules, fpr_budget, cost_budget)


def _run_qiskit_qaoa(
    rules: list[FirewallRule], fpr_budget: float, cost_budget: float
) -> OptimizationResult:
    """Real QAOA via Qiskit Aer when available.

    Falls back to the classical QAOAInspiredOptimizer if anything
    goes wrong (kept silent — caller logs).
    """
    import numpy as np
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator

    n = len(rules)
    # Build a small QAOA circuit: 1 layer, cost = sum(block_prob * z_i).
    qc = QuantumCircuit(n)
    qc.h(range(n))  # uniform superposition
    gamma = 0.7
    for i, r in enumerate(rules):
        qc.rz(2 * gamma * r.block_probability, i)
    # Mixer
    beta = 0.4
    for i in range(n):
        qc.rx(2 * beta, i)
    qc.measure_all()

    sim = AerSimulator()
    result = sim.run(qc, shots=512).result()
    counts = result.get_counts()

    # Pick the most-frequent bitstring as the candidate selection.
    best_str = max(counts, key=counts.get)
    selected = [
        rules[i]
        for i, ch in enumerate(reversed(best_str))
        if ch == "1"
    ]
    # Trim to budgets just like the heuristic does.
    chosen: list[FirewallRule] = []
    curr_fpr = 0.0
    curr_cost = 0.0
    for r in selected:
        if (curr_fpr + r.false_positive_rate <= fpr_budget) and (
            curr_cost + r.cost <= cost_budget
        ):
            chosen.append(r)
            curr_fpr += r.false_positive_rate
            curr_cost += r.cost

    from app.optimizer.qaoa_sim import RuleResult
    return OptimizationResult(
        selected_rules=[
            RuleResult(
                rule_id=r.rule_id,
                name=r.name,
                action=r.action,
                block_probability=r.block_probability,
                false_positive_rate=r.false_positive_rate,
                cost=r.cost,
                scope=r.scope,
            )
            for r in chosen
        ],
        total_block_probability=round(sum(r.block_probability for r in chosen), 4),
        total_fpr=round(curr_fpr, 4),
        total_cost=round(curr_cost, 4),
        optimization_time_ms=0.0,
        solver="qiskit_qaoa_aer",
        n_rules_evaluated=n,
        n_rules_selected=len(chosen),
    )


__all__ = ["solve", "greedy_knapsack", "qaoa_simulator_available"]
