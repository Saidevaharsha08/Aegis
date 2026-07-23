from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field
from typing import List, Optional
from app.optimizer.qaoa_sim import QAOAInspiredOptimizer, OptimizationResult
from app.optimizer.benchmark import run_optimizer_benchmark
from app.optimizer.rules import get_candidate_rules_pool

router = APIRouter()

class OptimizeRequest(BaseModel):
    fpr_budget: float = Field(default=0.10, ge=0.001, le=0.50)
    cost_budget: float = Field(default=10.0, ge=1.0, le=50.0)
    n_rules: int = Field(default=15, ge=5, le=30)

@router.post("/optimize", response_model=OptimizationResult, status_code=status.HTTP_200_OK)
def optimize_firewall_rules(req: OptimizeRequest) -> OptimizationResult:
    """
    POST /optimize endpoint: Selects optimal subset of firewall rules via QAOA classical simulation.
    """
    rules = get_candidate_rules_pool()[:req.n_rules]
    optimizer = QAOAInspiredOptimizer(rules=rules, fpr_budget=req.fpr_budget, cost_budget=req.cost_budget)
    return optimizer.optimize()

@router.get("/benchmark", status_code=status.HTTP_200_OK)
def get_optimizer_benchmark(n_rules: int = Query(default=15, ge=5, le=25)):
    """
    GET /benchmark endpoint: Compares QAOA vs Greedy vs DP vs Random solvers.
    """
    return run_optimizer_benchmark(n_rules_list=[10, n_rules])
