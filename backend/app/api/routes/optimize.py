from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field
from typing import List, Optional
from app.optimizer.api import qaoa_simulator_available, solve
from app.optimizer.qaoa_sim import QAOAInspiredOptimizer, OptimizationResult
from app.optimizer.benchmark import run_optimizer_benchmark
from app.optimizer.rules import get_candidate_rules_pool

router = APIRouter()

class OptimizeRequest(BaseModel):
    fpr_budget: float = Field(default=0.10, ge=0.001, le=0.50)
    cost_budget: float = Field(default=10.0, ge=1.0, le=50.0)
    n_rules: int = Field(default=15, ge=5, le=30)
    solver: str = Field(default="auto", pattern="^(auto|qaoa|greedy)$")


@router.post("/optimize", response_model=OptimizationResult, status_code=status.HTTP_200_OK)
def optimize_firewall_rules(req: OptimizeRequest) -> OptimizationResult:
    """Select optimal firewall rules via QAOA → greedy fallback chain.

    ``req.solver`` selects the path:
      * ``auto`` (default) — Qiskit Aer QAOA if installed, else the
        classical QAOA simulator, falling back to greedy if either
        fails or selects nothing.
      * ``qaoa`` — force QAOA (still falls back to greedy on error).
      * ``greedy`` — deterministic greedy knapsack.
    """
    return solve(
        fpr_budget=req.fpr_budget,
        cost_budget=req.cost_budget,
        n_rules=req.n_rules,
        solver=req.solver,
    )


@router.get("/optimize/capabilities", status_code=status.HTTP_200_OK)
def optimize_capabilities():
    """Advertise which solver backends are available."""
    return {
        "qiskit_qaoa_available": qaoa_simulator_available(),
        "classical_qaoa_available": True,
        "greedy_available": True,
    }


@router.get("/benchmark", status_code=status.HTTP_200_OK)
def get_optimizer_benchmark(n_rules: int = Query(default=15, ge=5, le=25)):
    """GET /benchmark endpoint: Compares QAOA vs Greedy vs DP vs Random solvers."""
    return run_optimizer_benchmark(n_rules_list=[10, n_rules])
