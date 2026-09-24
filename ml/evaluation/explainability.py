"""
PhishGuard AI - Explainable AI (XAI) Subsystem.
Integrates SHAP (SHapley Additive exPlanations) for transparent local feature attribution.
Research Rule: SHAP indicates statistical feature association within the model, not causality.
"""

from typing import Dict, Any, List
import numpy as np
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    shap = None
    SHAP_AVAILABLE = False

DISCLAIMER = (
    "Research Notice: SHAP attributions quantify the mathematical contribution of each "
    "feature toward the model's output log-odds. They do not constitute causal proof."
)


class ExplainabilityEngine:
    def __init__(self, model: Any, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.explainer = None
        self._init_explainer()

    def _init_explainer(self):
        if not SHAP_AVAILABLE or shap is None:
            self.explainer = None
            return
        try:
            # Tree models (RandomForest, XGBoost, DecisionTree)
            if hasattr(self.model, "estimators_") or "XGB" in type(self.model).__name__:
                self.explainer = shap.TreeExplainer(self.model)
            else:
                self.explainer = shap.LinearExplainer(self.model, np.zeros((1, len(self.feature_names))))
        except Exception as e:
            # Fallback to general Explainer
            try:
                self.explainer = shap.Explainer(self.model)
            except Exception:
                self.explainer = None

    def explain_instance(self, feature_values: Dict[str, float], top_k: int = 10) -> Dict[str, Any]:
        """
        Computes local feature contribution values for a single prediction instance.
        """
        ordered_vals = np.array([[feature_values.get(name, 0.0) for name in self.feature_names]])

        if self.explainer is None:
            return {
                "top_features": [],
                "disclaimer": DISCLAIMER,
                "status": "SHAP explainer initialization unavailable for this model architecture."
            }

        try:
            shap_values = self.explainer.shap_values(ordered_vals)
            # Handle binary classification output format differences in SHAP versions
            if isinstance(shap_values, list) and len(shap_values) == 2:
                # Class 1 (phishing)
                vals = shap_values[1][0]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
                vals = shap_values[0, :, 1]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 2:
                vals = shap_values[0]
            else:
                vals = np.array(shap_values).flatten()

            contributions = []
            for name, val, contrib in zip(self.feature_names, ordered_vals[0], vals):
                contributions.append({
                    "feature": name,
                    "value": round(float(val), 4),
                    "contribution": round(float(contrib), 4),
                    "direction": "phishing" if contrib > 0 else "legitimate"
                })

            # Sort by absolute contribution descending
            contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)

            return {
                "top_features": contributions[:top_k],
                "all_contributions": contributions,
                "disclaimer": DISCLAIMER,
                "status": "success"
            }
        except Exception as e:
            return {
                "top_features": [],
                "disclaimer": DISCLAIMER,
                "status": f"Explanation computation error: {str(e)}"
            }
