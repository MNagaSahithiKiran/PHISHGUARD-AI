"""
PhishGuard AI - Probability-Level Fusion Engine
Implements mathematically grounded probability-level fusion strategies:
1. Uniform Average Fusion: P_mean = 1/K sum(P_k)
2. Empirical Weighted Fusion: Weights learned strictly on validation set via Brier score minimization.
   CRITICAL RULE: No arbitrary hardcoded weights (e.g. 40/30/30).
3. Bayesian Independent Evidence Fusion: Combines log-odds under conditional independence.
"""

from typing import List, Dict, Any, Optional
import numpy as np
from scipy.optimize import minimize


class SimpleProbabilityFusion:
    def __init__(self, method: str = "mean", weights: Optional[List[float]] = None):
        self.method = method  # "mean", "weighted", "bayes"
        self.weights = np.array(weights) if weights is not None else None

    def fit_weights(self, prob_matrix: np.ndarray, y_true: np.ndarray):
        """
        Fits optimal non-negative weights summing to 1 by minimizing Brier score on validation data.
        prob_matrix: shape (N, K)
        """
        K = prob_matrix.shape[1]

        def brier_objective(w):
            w_norm = np.maximum(w, 0)
            if np.sum(w_norm) == 0:
                w_norm = np.ones(K) / K
            else:
                w_norm = w_norm / np.sum(w_norm)
            p_pred = np.dot(prob_matrix, w_norm)
            return np.mean((p_pred - y_true) ** 2)

        init_w = np.ones(K) / K
        bounds = [(0.0, 1.0) for _ in range(K)]
        constraints = {"type": "eq", "fun": lambda w: np.sum(w) - 1.0}

        res = minimize(brier_objective, init_w, method="SLSQP", bounds=bounds, constraints=constraints)
        if res.success:
            self.weights = res.x / np.sum(res.x)
        else:
            self.weights = init_w
        return self.weights

    def predict_probability(self, probabilities: List[float], mask: Optional[List[bool]] = None) -> float:
        """
        probabilities: list of base model probabilities for active modalities.
        mask: boolean flags indicating which modalities are available.
        """
        probs = np.array(probabilities, dtype=float)
        if len(probs) == 0:
            return 0.5  # Maximum uncertainty

        # Filter out NaN or missing
        valid_idx = ~np.isnan(probs)
        if not np.any(valid_idx):
            return 0.5

        active_probs = probs[valid_idx]

        if self.method == "mean":
            return float(np.mean(active_probs))

        elif self.method == "weighted":
            if self.weights is not None and len(self.weights) == len(probs):
                active_weights = self.weights[valid_idx]
                if np.sum(active_weights) > 0:
                    w_norm = active_weights / np.sum(active_weights)
                    return float(np.dot(active_probs, w_norm))
            return float(np.mean(active_probs))

        elif self.method == "bayes":
            # Log-odds Bayesian combination: L(y=1) = L_0 + sum(L_k - L_0)
            eps = 1e-4
            clipped = np.clip(active_probs, eps, 1.0 - eps)
            log_odds = np.log(clipped / (1.0 - clipped))
            # Average log-odds formulation avoids overconfident saturation
            avg_log_odds = np.mean(log_odds)
            return float(1.0 / (1.0 + np.exp(-avg_log_odds)))

        else:
            return float(np.mean(active_probs))
