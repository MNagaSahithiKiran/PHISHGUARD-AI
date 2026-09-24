"""
PhishGuard AI - Unified Model Registry
Centrally manages and audits deployment versions, artifact paths, and operational status
of all base models, vision neural networks, calibrators, and multi-modal fusion engines.
CRITICAL COMPLIANCE: Never silently load arbitrary 'latest' files without version pinning.
"""

from typing import Dict, Any, Optional
from pathlib import Path

ARTIFACTS_ROOT = Path(__file__).resolve().parent.parent.parent.parent / "ml"


class ModelRegistry:
    REGISTRY = {
        "URL_MODEL": {
            "name": "RandomForest_URLLexical",
            "version": "random_forest_v1",
            "feature_version": "2.0.0",
            "feature_dimension": 34,
            "artifact_path": str(ARTIFACTS_ROOT / "models_artifacts" / "random_forest_best.joblib"),
            "status": "active",
        },
        "WEBSITE_MODEL": {
            "name": "DOM_Form_HeuristicAnalyzer",
            "version": "heuristic_dom_v1",
            "feature_version": "1.0.0",
            "feature_dimension": 48,
            "artifact_path": None,
            "status": "active",
        },
        "VISUAL_MODEL": {
            "name": "PhishMobileNetV2_Transfer",
            "version": "mobilenet_v2_v1",
            "preprocessing_version": "1.0.0",
            "input_shape": [1, 3, 224, 224],
            "artifact_path": str(ARTIFACTS_ROOT / "vision" / "models_artifacts" / "transfer_mobilenet_best.pt"),
            "status": "active",
        },
        "FUSION_MODEL": {
            "name": "Stacking_LogisticRegression_MetaClassifier",
            "version": "stacking_fusion_v1",
            "calibration_method": "platt",
            "calibration_version": "platt_v1",
            "decision_policy_version": "1.0.0",
            "artifact_path": str(ARTIFACTS_ROOT / "fusion" / "artifacts" / "stacking_fusion_best.joblib"),
            "calibrator_path": str(ARTIFACTS_ROOT / "fusion" / "artifacts" / "probability_calibrator_best.joblib"),
            "policy_path": str(ARTIFACTS_ROOT / "fusion" / "artifacts" / "decision_policy.json"),
            "status": "active",
        },
    }

    @classmethod
    def get_model_metadata(cls, model_key: str) -> Dict[str, Any]:
        return cls.REGISTRY.get(model_key.upper(), {"status": "not_registered"})

    @classmethod
    def get_all_models(cls) -> Dict[str, Any]:
        result = {}
        for k, v in cls.REGISTRY.items():
            path_exists = False
            if v.get("artifact_path"):
                path_exists = Path(v["artifact_path"]).exists()
            elif k == "WEBSITE_MODEL":
                path_exists = True

            result[k] = {
                **v,
                "artifact_exists": path_exists,
            }
        return result
