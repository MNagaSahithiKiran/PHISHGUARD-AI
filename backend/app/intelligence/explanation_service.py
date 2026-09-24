"""
PhishGuard AI - Explanation Service
Wraps MultiModalExplainer to produce structured explanations for the Intelligence API and UI.
"""

from typing import Dict, Any, List, Optional
from ml.fusion.evaluation.explain_fusion import MultiModalExplainer


class ExplanationService:
    @staticmethod
    def generate_explanation(
        classification: str,
        calibrated_probability: float,
        modalities_used: List[str],
        missing_modalities: List[str],
        base_models: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        feature_attributions: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        return MultiModalExplainer.explain(
            classification=classification,
            calibrated_probability=calibrated_probability,
            modalities_used=modalities_used,
            missing_modalities=missing_modalities,
            base_models=base_models,
            evidence_items=evidence_items,
            feature_attributions=feature_attributions,
        )
