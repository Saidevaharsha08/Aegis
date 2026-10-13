import time
import numpy as np
from typing import List, Dict, Any
from app.optimizer.rules import FirewallRule, get_candidate_rules_pool
from app.optimizer.qaoa_sim import QAOAInspiredOptimizer, OptimizationResult

def solve_greedy(rules: List[FirewallRule], fpr_budget: float, cost_budget: float) -> OptimizationResult:
    """Greedy baseline solver: Sort rules by efficiency ratio (block_prob / fpr)."""
    t0 = time.perf_counter()
    # Efficiency ratio
    sorted_rules = sorted(rules, key=lambda r: r.block_probability / (r.false_positive_rate + 1e-4), reverse=True)
    
    selected = []
    tot_fpr = 0.0
    tot_cost = 0.0
    
    for r in sorted_rules:
        if (tot_fpr + r.false_positive_rate <= fpr_budget) and (tot_cost + r.cost <= cost_budget):
            selected.append(r)
            tot_fpr += r.false_positive_rate
            tot_cost += r.cost
            
    t1 = time.perf_counter()
    return OptimizationResult(
        selected_rules=[r.__dict__ for r in selected],
        total_block_probability=round(sum(r.block_probability for r in selected), 4),
        total_fpr=round(tot_fpr, 4),
        total_cost=round(tot_cost, 4),
        optimization_time_ms=round((t1 - t0) * 1000.0, 3),
        solver="Greedy (Baseline)",
        n_rules_evaluated=len(rules),
        n_rules_selected=len(selected)
    )

def solve_dp_exact(rules: List[FirewallRule], fpr_budget: float, cost_budget: float) -> OptimizationResult:
    """Exact solution via 0-1 Knapsack Dynamic Programming (discretized scaling)."""
    t0 = time.perf_counter()
    
    # Discretize budgets to integer values for DP table
    scale_fpr = 1000
    scale_cost = 10
    
    max_w_fpr = int(fpr_budget * scale_fpr)
    max_w_cost = int(cost_budget * scale_cost)
    n = len(rules)
    
    dp = np.zeros((n + 1, max_w_fpr + 1, max_w_cost + 1))
    
    for i in range(1, n + 1):
        r = rules[i - 1]
        w_f = int(r.false_positive_rate * scale_fpr)
        w_c = int(r.cost * scale_cost)
        v = r.block_probability
        
        for f in range(max_w_fpr + 1):
            for c in range(max_w_cost + 1):
                if w_f <= f and w_c <= c:
                    dp[i, f, c] = max(dp[i - 1, f, c], dp[i - 1, f - w_f, c - w_c] + v)
                else:
                    dp[i, f, c] = dp[i - 1, f, c]
                    
    # Backtrack to find selected subset
    curr_f, curr_c = max_w_fpr, max_w_cost
    selected = []
    for i in range(n, 0, -1):
        if dp[i, curr_f, curr_c] != dp[i - 1, curr_f, curr_c]:
            r = rules[i - 1]
            selected.append(r)
            w_f = int(r.false_positive_rate * scale_fpr)
            w_c = int(r.cost * scale_cost)
            curr_f -= w_f
            curr_c -= w_c
            
    t1 = time.perf_counter()
    return OptimizationResult(
        selected_rules=[r.__dict__ for r in selected],
        total_block_probability=round(sum(r.block_probability for r in selected), 4),
        total_fpr=round(sum(r.false_positive_rate for r in selected), 4),
        total_cost=round(sum(r.cost for r in selected), 4),
        optimization_time_ms=round((t1 - t0) * 1000.0, 3),
        solver="Exact DP (Optimal)",
        n_rules_evaluated=n,
        n_rules_selected=len(selected)
    )

def solve_random_sampling(rules: List[FirewallRule], fpr_budget: float, cost_budget: float, n_samples: int = 100) -> OptimizationResult:
    """Random sampling baseline solver."""
    t0 = time.perf_counter()
    best_selected = []
    best_score = -1.0
    
    np.random.seed(42)
    for _ in range(n_samples):
        subset = [r for r in rules if np.random.rand() > 0.5]
        tot_fpr = sum(r.false_positive_rate for r in subset)
        tot_cost = sum(r.cost for r in subset)
        score = sum(r.block_probability for r in subset)
        
        if tot_fpr <= fpr_budget and tot_cost <= cost_budget and score > best_score:
            best_score = score
            best_selected = subset
            
    t1 = time.perf_counter()
    return OptimizationResult(
        selected_rules=[r.__dict__ for r in best_selected],
        total_block_probability=round(best_score if best_score > 0 else 0.0, 4),
        total_fpr=round(sum(r.false_positive_rate for r in best_selected), 4),
        total_cost=round(sum(r.cost for r in best_selected), 4),
        optimization_time_ms=round((t1 - t0) * 1000.0, 3),
        solver="Random Sampling",
        n_rules_evaluated=len(rules),
        n_rules_selected=len(best_selected)
    )

def run_optimizer_benchmark(n_rules_list: List[int] = [10, 15, 20, 25]) -> Dict[str, Any]:
    """
    Runs full empirical benchmark comparing QAOA-inspired, Greedy, DP, and Random Sampling solvers.
    """
    pool = get_candidate_rules_pool()
    fpr_budget = 0.10
    cost_budget = 10.0
    
    results = {}
    
    print("\n" + "="*80)
    print("       QUANTUM-INSPIRED FIREWALL RULE OPTIMIZER BENCHMARK SUMMARY")
    print("="*80)
    print(f" {'N':<4} | {'Solver':<24} | {'Block Prob':<12} | {'FPR':<8} | {'Runtime (ms)':<14} | {'Gap vs DP'}")
    print("-" * 80)
    
    for n in n_rules_list:
        sub_rules = pool[:n]
        
        # 1. Exact DP
        res_dp = solve_dp_exact(sub_rules, fpr_budget, cost_budget)
        optimal_score = max(res_dp.total_block_probability, 0.001)
        
        # 2. Greedy
        res_greedy = solve_greedy(sub_rules, fpr_budget, cost_budget)
        greedy_gap = ((optimal_score - res_greedy.total_block_probability) / optimal_score) * 100.0
        
        # 3. Random
        res_rand = solve_random_sampling(sub_rules, fpr_budget, cost_budget)
        rand_gap = ((optimal_score - res_rand.total_block_probability) / optimal_score) * 100.0
        
        # 4. QAOA-Inspired
        qaoa_solver = QAOAInspiredOptimizer(rules=sub_rules, fpr_budget=fpr_budget, cost_budget=cost_budget)
        res_qaoa = qaoa_solver.optimize()
        qaoa_gap = max(0.0, ((optimal_score - res_qaoa.total_block_probability) / optimal_score) * 100.0)
        
        results[f"N_{n}"] = {
            "DP_Exact": res_dp.model_dump(),
            "QAOA_Inspired": res_qaoa.model_dump(),
            "Greedy": res_greedy.model_dump(),
            "Random_Sampling": res_rand.model_dump(),
            "qaoa_optimality_gap_pct": round(qaoa_gap, 2)
        }
        
        for res, gap_str in [(res_dp, "0.0%"), (res_qaoa, f"{qaoa_gap:.1f}%"), (res_greedy, f"{greedy_gap:.1f}%"), (res_rand, f"{rand_gap:.1f}%")]:
            print(f" {n:<4} | {res.solver:<24} | {res.total_block_probability:<12.4f} | {res.total_fpr:<8.4f} | {res.optimization_time_ms:<14.2f} | {gap_str}")
        print("-" * 80)
        
    print("="*80 + "\n")
    return results

if __name__ == "__main__":
    run_optimizer_benchmark(n_rules_list=[10, 15, 20])
