"""
PhishGuard AI - Evidence-Enhanced Multi-Modal Meta-Classifier
Implements Strategy C: Combines continuous base model probabilities with
verifiable structured security indicators (external form action, login forms, centered card).
Provides auditable feature importance coefficients for IEEE research defense.
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression


EVIDENCE_FEATURE_NAMES = [
    "p_url",
    "p_website",
    "p_visual",
    "has_external_password_form",
    "has_centered_card",
    "security_header_score",
    "whitespace_ratio",
    "edge_density",
]


class EvidenceEnhancedFusionModel:
    def __init__(self, C: float = 0.5, random_state: int = 42):
        self.C = C
        self.random_state = random_state
        self.clf = LogisticRegression(C=self.C, solver="lbfgs", max_iter=500, random_state=self.random_state)
        self.feature_names = list(EVIDENCE_FEATURE_NAMES)
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        """
        X: shape (N, 8) matching EVIDENCE_FEATURE_NAMES
        y: binary labels (0, 1)
        """
        self.clf.fit(X, y)
        self.is_fitted = True
        return self

    def predict_probability(self, feature_vector: np.ndarray) -> float:
        """
        feature_vector: 1D array of length 8 matching EVIDENCE_FEATURE_NAMES
        """
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted.")
        x = np.array(feature_vector).reshape(1, -1)
        return float(self.clf.predict_proba(x)[0, 1])

    def get_feature_importances(self) -> List[Dict[str, Any]]:
        """Returns sorted feature impact coefficients for explainability."""
        if not self.is_fitted:
            return []
        coefs = self.clf.coef_[0]
        results = []
        for name, c in zip(self.feature_names, coefs):
            direction = "increases_phishing_risk" if c > 0 else "increases_legitimate_confidence"
            results.append({
                "feature": name,
                "coefficient": round(float(c), 4),
                "magnitude": round(float(abs(c)), 4),
                "effect": direction,
            })
        results.sort(key=lambda item: item["magnitude"], reverse=True)
        return results
