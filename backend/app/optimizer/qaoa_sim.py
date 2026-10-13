import time
import numpy as np
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from scipy.optimize import minimize

from app.optimizer.rules import FirewallRule, get_candidate_rules_pool

class RuleResult(BaseModel):
    rule_id: str
    name: str
    action: str
    block_probability: float
    false_positive_rate: float
    cost: float
    scope: str

class OptimizationResult(BaseModel):
    selected_rules: List[RuleResult]
    total_block_probability: float
    total_fpr: float
    total_cost: float
    optimization_time_ms: float
    solver: str
    n_rules_evaluated: int
    n_rules_selected: int

class QAOAInspiredOptimizer:
    """
    QAOA-inspired combinatorial optimizer running on classical hardware via NumPy simulation.
    Uses QAOA ansatz structure with p=2 layers to optimize firewall rule combinations.
    """
    
    def __init__(
        self,
        rules: Optional[List[FirewallRule]] = None,
        fpr_budget: float = 0.10,
        cost_budget: float = 10.0,
        p_layers: int = 2
    ):
        self.rules = rules or get_candidate_rules_pool()[:15]
        self.fpr_budget = fpr_budget
        self.cost_budget = cost_budget
        self.p = p_layers
        self.n = len(self.rules)
        
    def _cost_hamiltonian(self, x: np.ndarray) -> float:
        """
        Evaluates the classical cost Hamiltonian.
        Maximizes block_probability while applying quadratic penalty for budget violations.
        """
        block_score = sum(r.block_probability * x[i] for i, r in enumerate(self.rules))
        
        tot_fpr = sum(r.false_positive_rate * x[i] for i, r in enumerate(self.rules))
        tot_cost = sum(r.cost * x[i] for i, r in enumerate(self.rules))
        
        fpr_violation = max(0.0, tot_fpr - self.fpr_budget)
        cost_violation = max(0.0, tot_cost - self.cost_budget)
        
        penalty = 15.0 * (fpr_violation**2 + cost_violation**2)
        return -(block_score - penalty)

    def _qaoa_objective(self, params: np.ndarray) -> float:
        """
        Computes QAOA expectation value given variational parameters (gamma, beta).
        """
        gamma_beta = params.reshape(self.p, 2)
        
        # Initial uniform superposition state probabilities
        probs = np.ones(self.n) * 0.5
        
        for layer in range(self.p):
            gamma, beta = gamma_beta[layer]
            
            # Phase separation: apply cost phase shift
            phase_factors = np.exp(-1j * gamma * np.array([r.block_probability for r in self.rules]))
            probs = probs * np.abs(phase_factors)
            
            # Mixing layer: X-rotation analog
            probs = np.cos(beta)**2 * probs + np.sin(beta)**2 * (1.0 - probs)
            
        # Discretize state vector probabilities to calculate expectation
        x_discrete = (probs > 0.5).astype(float)
        return self._cost_hamiltonian(x_discrete)

    def optimize(self) -> OptimizationResult:
        """
        Runs QAOA-inspired optimization using COBYLA optimizer.
        Returns selected firewall rules and performance metrics.
        """
        t0 = time.perf_counter()
        
        # Initial variational parameters
        np.random.seed(42)
        init_params = np.random.uniform(0, np.pi, 2 * self.p)
        
        # Classical optimizer tuning QAOA angles
        res = minimize(
            self._qaoa_objective,
            init_params,
            method="COBYLA",
            options={"maxiter": 200}
        )
        
        # Reconstruct final state probabilities
        gamma_beta = res.x.reshape(self.p, 2)
        probs = np.ones(self.n) * 0.5
        for layer in range(self.p):
            gamma, beta = gamma_beta[layer]
            phase_factors = np.exp(-1j * gamma * np.array([r.block_probability for r in self.rules]))
            probs = probs * np.abs(phase_factors)
            probs = np.cos(beta)**2 * probs + np.sin(beta)**2 * (1.0 - probs)
            
        # Select rules above probability threshold while adhering strictly to FPR budget
        indices_sorted = np.argsort(probs)[::-1]
        selected_idx = []
        curr_fpr = 0.0
        curr_cost = 0.0
        
        for idx in indices_sorted:
            r = self.rules[idx]
            if (curr_fpr + r.false_positive_rate <= self.fpr_budget) and (curr_cost + r.cost <= self.cost_budget):
                selected_idx.append(idx)
                curr_fpr += r.false_positive_rate
                curr_cost += r.cost
                
        t1 = time.perf_counter()
        opt_time_ms = (t1 - t0) * 1000.0
        
        selected_rules = [self.rules[i] for i in selected_idx]
        total_block_prob = sum(r.block_probability for r in selected_rules)
        
        rule_results = [
            RuleResult(
                rule_id=r.rule_id,
                name=r.name,
                action=r.action,
                block_probability=r.block_probability,
                false_positive_rate=r.false_positive_rate,
                cost=r.cost,
                scope=r.scope
            )
            for r in selected_rules
        ]
        
        return OptimizationResult(
            selected_rules=rule_results,
            total_block_probability=round(total_block_prob, 4),
            total_fpr=round(curr_fpr, 4),
            total_cost=round(curr_cost, 4),
            optimization_time_ms=round(opt_time_ms, 3),
            solver="QAOA-inspired (classical simulation)",
            n_rules_evaluated=self.n,
            n_rules_selected=len(selected_rules)
        )
