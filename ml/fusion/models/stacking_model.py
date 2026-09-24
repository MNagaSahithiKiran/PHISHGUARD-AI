"""
PhishGuard AI - Stacking Meta-Classifier Engine
Implements cross-modality probability stacking with dynamic missing-modality routing:
- Full 3-Modality Stacking: [p_url, p_website, p_visual] -> P(phishing)
- URL + Website Fallback: [p_url, p_website] -> P(phishing)
- URL + Visual Fallback: [p_url, p_visual] -> P(phishing)
- URL Only Fallback: [p_url] -> P(phishing)
Trained using regularized Logistic Regression with cross-validated parameter selection.
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression


class StackingFusionModel:
    def __init__(self, C: float = 1.0, random_state: int = 42):
        self.C = C
        self.random_state = random_state
        self.sub_models: Dict[str, LogisticRegression] = {}
        self.feature_names = ["p_url", "p_website", "p_visual"]

    def fit(self, X: np.ndarray, y: np.ndarray):
        """
        X: shape (N, 3) where columns are [p_url, p_website, p_visual]
        y: binary ground truth labels (0 or 1)
        Trains full model and all fallback sub-models.
        """
        # 1. Full 3-modality model
        clf_full = LogisticRegression(C=self.C, solver="lbfgs", random_state=self.random_state)
        clf_full.fit(X, y)
        self.sub_models["full"] = clf_full

        # 2. URL + Website model (columns 0, 1)
        clf_uw = LogisticRegression(C=self.C, solver="lbfgs", random_state=self.random_state)
        clf_uw.fit(X[:, [0, 1]], y)
        self.sub_models["url_website"] = clf_uw

        # 3. URL + Visual model (columns 0, 2)
        clf_uv = LogisticRegression(C=self.C, solver="lbfgs", random_state=self.random_state)
        clf_uv.fit(X[:, [0, 2]], y)
        self.sub_models["url_visual"] = clf_uv

        # 4. URL Only model (column 0)
        clf_u = LogisticRegression(C=self.C, solver="lbfgs", random_state=self.random_state)
        clf_u.fit(X[:, [0]], y)
        self.sub_models["url_only"] = clf_u

        return self

    def predict_probability(
        self,
        p_url: Optional[float] = None,
        p_website: Optional[float] = None,
        p_visual: Optional[float] = None,
    ) -> Tuple[float, str, List[str]]:
        """
        Dynamically detects available modalities, routes to the corresponding sub-model,
        and returns (fused_probability, routing_mode, modalities_used).
        """
        has_u = p_url is not None and not np.isnan(p_url)
        has_w = p_website is not None and not np.isnan(p_website)
        has_v = p_visual is not None and not np.isnan(p_visual)

        if has_u and has_w and has_v:
            x = np.array([[p_url, p_website, p_visual]])
            prob = float(self.sub_models["full"].predict_proba(x)[0, 1])
            return prob, "full_multimodal_stacking", ["url", "website", "visual"]

        elif has_u and has_w:
            x = np.array([[p_url, p_website]])
            prob = float(self.sub_models["url_website"].predict_proba(x)[0, 1])
            return prob, "url_website_stacking_fallback", ["url", "website"]

        elif has_u and has_v:
            x = np.array([[p_url, p_visual]])
            prob = float(self.sub_models["url_visual"].predict_proba(x)[0, 1])
            return prob, "url_visual_stacking_fallback", ["url", "visual"]

        elif has_u:
            x = np.array([[p_url]])
            prob = float(self.sub_models["url_only"].predict_proba(x)[0, 1])
            return prob, "url_only_stacking_fallback", ["url"]

        elif has_w and has_v:
            # Equal weight fallback if URL is somehow unavailable
            prob = 0.5 * (p_website + p_visual)
            return prob, "website_visual_heuristic_fallback", ["website", "visual"]

        elif has_w:
            return float(p_website), "website_only_fallback", ["website"]

        elif has_v:
            return float(p_visual), "visual_only_fallback", ["visual"]

        else:
            return 0.5, "zero_modality_uncertainty", []

    def get_coefficients(self) -> Dict[str, Any]:
        """Returns learned weights of the full stacking model."""
        if "full" not in self.sub_models:
            return {}
        clf = self.sub_models["full"]
        coefs = clf.coef_[0].tolist()
        return {
            "p_url_weight": round(coefs[0], 4),
            "p_website_weight": round(coefs[1], 4),
            "p_visual_weight": round(coefs[2], 4),
            "intercept": round(float(clf.intercept_[0]), 4),
        }
