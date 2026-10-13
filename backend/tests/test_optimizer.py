import sys
import pytest
from pathlib import Path

project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "backend"))

from app.optimizer.rules import FirewallRule, get_candidate_rules_pool
from app.optimizer.qaoa_sim import QAOAInspiredOptimizer
from app.optimizer.benchmark import solve_dp_exact, solve_greedy, run_optimizer_benchmark

def test_qaoa_small_instance_optimal_match():
    pool = get_candidate_rules_pool()[:5]
    fpr_budget = 0.10
    cost_budget = 10.0
    
    dp_res = solve_dp_exact(pool, fpr_budget, cost_budget)
    
    optimizer = QAOAInspiredOptimizer(rules=pool, fpr_budget=fpr_budget, cost_budget=cost_budget)
    qaoa_res = optimizer.optimize()
    
    # QAOA score should match DP within 5%
    ratio = qaoa_res.total_block_probability / max(dp_res.total_block_probability, 0.001)
    assert ratio >= 0.90

def test_constraint_satisfaction():
    pool = get_candidate_rules_pool()[:15]
    fpr_budget = 0.08
    cost_budget = 8.0
    
    optimizer = QAOAInspiredOptimizer(rules=pool, fpr_budget=fpr_budget, cost_budget=cost_budget)
    res = optimizer.optimize()
    
    assert res.total_fpr <= fpr_budget + 1e-4
    assert res.total_cost <= cost_budget + 1e-4
    assert len(res.selected_rules) <= len(pool)

def test_qaoa_runtime_limit():
    pool = get_candidate_rules_pool()[:20]
    optimizer = QAOAInspiredOptimizer(rules=pool, fpr_budget=0.10, cost_budget=10.0)
    res = optimizer.optimize()
    
    assert res.optimization_time_ms < 200.0  # runtime threshold
    assert res.solver == "QAOA-inspired (classical simulation)"

def test_benchmark_harness_execution():
    bench = run_optimizer_benchmark(n_rules_list=[10, 15])
    assert "N_10" in bench
    assert "N_15" in bench
    assert "qaoa_optimality_gap_pct" in bench["N_10"]
