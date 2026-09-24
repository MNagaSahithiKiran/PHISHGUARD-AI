import time
from typing import Dict, Any, Optional
from fastapi import HTTPException, status

from app.core.security import validate_and_sanitize_url
from app.core.logging import logger
from app.ml.model_loader import model_loader
from ml.evaluation.explainability import ExplainabilityEngine


class PredictionService:
    _explainer: Optional[ExplainabilityEngine] = None

    @classmethod
    def _get_explainer(cls) -> Optional[ExplainabilityEngine]:
        if cls._explainer is None and model_loader.is_loaded:
            cls._explainer = ExplainabilityEngine(
                model=model_loader.model,
                feature_names=model_loader.preprocessor.feature_names
            )
        return cls._explainer

    @classmethod
    def predict_url(cls, raw_url: str, explain: bool = True) -> Dict[str, Any]:
        """
        Executes end-to-end ML prediction for a target URL.
        1. Enforces SSRF and syntax validation.
        2. Extracts 34 deterministic features.
        3. Scales features via serialized pipeline.
        4. Queries genuine trained model.
        5. Computes SHAP explanation if requested.
        """
        # Step 1: Ensure models are active
        if not model_loader.is_loaded:
            model_loader.reload()
            if not model_loader.is_loaded:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="AI Prediction Service Unavailable: Model weights and preprocessor artifacts not loaded."
                )

        # Step 2: Validate URL syntax and SSRF protection
        sanitized = validate_and_sanitize_url(raw_url)
        normalized_url = sanitized["normalized_url"]

        # Step 3: Feature Extraction
        start_time = time.time()
        pipeline = model_loader.preprocessor
        feature_dict = pipeline.extract_dict(normalized_url)

        from app.intelligence.reproducibility import compute_url_feature_hash
        import numpy as np

        feature_hash = compute_url_feature_hash(feature_dict)

        # Input Validation: Feature Count & Sanity
        expected_count = len(pipeline.feature_names)
        actual_count = len(feature_dict)
        if actual_count != expected_count:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Feature extraction dimension mismatch: Expected {expected_count}, got {actual_count}."
            )

        X_scaled = pipeline.transform([feature_dict])

        # Validate no NaN or Inf values
        if np.isnan(X_scaled).any() or np.isinf(X_scaled).any():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Invalid numerical features detected: NaN or Infinite values encountered."
            )

        # Step 4: Model Inference
        model = model_loader.model
        label_pred = int(model.predict(X_scaled)[0])

        # Real model probability
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_scaled)[0]
            phishing_prob = float(probs[1])
            # Confidence is the probability of the predicted class
            confidence = round(float(probs[label_pred]) * 100, 2)
        else:
            phishing_prob = 1.0 if label_pred == 1 else 0.0
            confidence = 100.0

        inference_time_ms = round((time.time() - start_time) * 1000, 3)
        prediction_str = "phishing" if label_pred == 1 else "legitimate"

        # Step 5: Optional SHAP Explainability
        top_explanations = None
        if explain:
            explainer = cls._get_explainer()
            if explainer:
                exp_res = explainer.explain_instance(feature_dict, top_k=5)
                top_explanations = exp_res.get("top_features", [])

        model_name = model_loader.metadata.get("selected_model", "Unknown Model")
        feature_ver = model_loader.metadata.get("feature_version", "2.0.0")

        return {
            "prediction": prediction_str,
            "label": label_pred,
            "probability": round(phishing_prob, 4),
            "confidence": confidence,
            "model_version": f"{model_name.lower().replace(' ', '_')}_v1",
            "feature_version": feature_ver,
            "preprocessing_version": "2.0.0",
            "feature_hash": feature_hash,
            "model_artifact_hash": getattr(model_loader, "model_hash", None),
            "raw_features": feature_dict,
            "inference_time_ms": inference_time_ms,
            "top_explanations": top_explanations,
        }

