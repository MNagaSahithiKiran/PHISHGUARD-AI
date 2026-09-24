"""
PhishGuard AI - Multi-Modal Intelligence Fusion Service
The central orchestration brain of PhishGuard AI:
1. Enforces SSRF and safety boundaries.
2. Ingests URL lexical, Website DOM/HTTP, and Visual screenshot signals.
3. Dynamically handles missing modalities with validated fallback routing.
4. Executes Stacking meta-classification and Platt probability calibration.
5. Applies empirical decision policy and computes 0–100 risk score.
6. Synthesizes auditable multi-modal evidence and SHAP/Grad-CAM explanations.
"""

import time
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

from app.core.security import validate_and_sanitize_url
from app.analyzers.safety.ssrf_guard import SSRFGuard, SSRFSecurityException
from app.ml.prediction_service import PredictionService
from app.services.website_analysis_service import WebsiteAnalysisService
from app.vision.screenshot_service import ScreenshotService
from app.vision.visual_prediction_service import VisualPredictionService
from app.intelligence.model_registry import ModelRegistry
from app.intelligence.evidence_fusion_service import EvidenceFusionService
from app.intelligence.decision_service import DecisionService
from app.intelligence.risk_engine import RiskEngine
from app.intelligence.explanation_service import ExplanationService
from app.services.reputation.reputation_service import ReputationService
from app.intelligence.decision_policy import DecisionPolicyEngine, POLICY_VERSION

from ml.fusion.models.fusion_factory import create_fusion_model
from ml.fusion.calibration.probability_calibration import ProbabilityCalibrator

logger = logging.getLogger("phishguard.intelligence.fusion")

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "ml" / "fusion" / "artifacts"


class MultiModalFusionService:
    _instance: Optional["MultiModalFusionService"] = None

    def __init__(self):
        self.stacking_model = None
        self.calibrator = None
        self._load_models()

    @classmethod
    def get_instance(cls) -> "MultiModalFusionService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_models(self):
        stack_path = ARTIFACTS_DIR / "stacking_fusion_best.joblib"
        cal_path = ARTIFACTS_DIR / "probability_calibrator_best.joblib"

        if stack_path.exists():
            try:
                self.stacking_model = create_fusion_model("stacking", checkpoint_path=stack_path)
                logger.info("Loaded stacking fusion model.")
            except Exception as e:
                logger.error(f"Failed to load stacking model: {e}")

        if cal_path.exists():
            try:
                self.calibrator = ProbabilityCalibrator.load(cal_path)
                logger.info("Loaded probability calibrator.")
            except Exception as e:
                logger.error(f"Failed to load calibrator: {e}")

    async def analyze_target(
        self,
        raw_url: str,
        scan_id: Optional[str] = None,
        include_visual: bool = True,
        previous_snapshot_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end multi-modal intelligence assessment.
        """
        start_time = time.perf_counter()

        # 1. URL Validation & Pre-check SSRF
        sanitized = validate_and_sanitize_url(raw_url)
        normalized_url = sanitized["normalized_url"]
        domain = sanitized["domain"]
        SSRFGuard.validate_target_url(normalized_url)

        modalities_used: List[str] = []
        missing_modalities: List[str] = []

        models_output: Dict[str, Any] = {}
        website_evidence: List[Dict[str, Any]] = []
        visual_evidence: List[Dict[str, Any]] = []
        url_threats: List[Dict[str, Any]] = []

        p_url: Optional[float] = None
        p_website: Optional[float] = None
        p_visual: Optional[float] = None
        screenshot_url: Optional[str] = None
        heatmap_url: Optional[str] = None

        # 2. Modality 1: URL Intelligence Model
        try:
            url_res = PredictionService.predict_url(normalized_url, explain=True)
            raw_url_p = url_res.get("probability")
            p_url = float(raw_url_p) if raw_url_p is not None else None
            if p_url is not None:
                modalities_used.append("url")
            else:
                missing_modalities.append("url")
            models_output["url"] = {
                "model_name": ModelRegistry.REGISTRY["URL_MODEL"]["name"],
                "model_version": url_res.get("model_version", "1.0.0"),
                "prediction": url_res.get("prediction"),
                "probability": p_url,
                "confidence": url_res.get("confidence"),
                "latency_ms": url_res.get("inference_time_ms", 0.0),
                "status": "available" if p_url is not None else "failed",
            }
        except Exception as e:
            logger.warning(f"URL prediction error: {e}")
            missing_modalities.append("url")
            models_output["url"] = {"status": "failed", "error": str(e)}

        # 3. Modality 2: Website / DOM Intelligence Engine
        try:
            web_res = await WebsiteAnalysisService.analyze_url(
                raw_url=normalized_url,
                capture_screenshot=False,
            )
            http_err = web_res.get("http", {}).get("error")
            website_evidence = web_res.get("evidence", [])

            if http_err:
                p_website = None
                missing_modalities.append("website")
                models_output["website"] = {
                    "model_name": ModelRegistry.REGISTRY["WEBSITE_MODEL"]["name"],
                    "model_version": ModelRegistry.REGISTRY["WEBSITE_MODEL"]["version"],
                    "prediction": None,
                    "probability": None,
                    "status": "failed",
                    "error": http_err,
                }
            else:
                # Derive website model probability from form / header analysis
                forms = web_res.get("forms", {})
                headers = web_res.get("headers", {})
                links = web_res.get("links", {})

                has_ext_pw = 1 if forms.get("external_action_count", 0) > 0 and forms.get("has_password_field") else 0
                has_pw = 1 if forms.get("has_password_field") else 0
                sec_score = float(headers.get("security_header_score", 0.0))
                ext_link_ratio = float(links.get("external_link_ratio", 0.0))

                logit = -2.2
                if has_ext_pw:
                    logit += 3.5
                if has_pw:
                    logit += 1.2
                    if sec_score < 0.2:
                        logit += 1.0
                if ext_link_ratio > 0.8:
                    logit += 1.5
                logit -= sec_score * 1.5

                p_website = round(float(1.0 / (1.0 + (2.71828 ** (-logit)))), 4)
                modalities_used.append("website")

                models_output["website"] = {
                    "model_name": ModelRegistry.REGISTRY["WEBSITE_MODEL"]["name"],
                    "model_version": ModelRegistry.REGISTRY["WEBSITE_MODEL"]["version"],
                    "prediction": "phishing" if p_website >= 0.5 else "legitimate",
                    "probability": p_website,
                    "dom_depth": web_res.get("dom", {}).get("dom_depth"),
                    "total_forms": forms.get("total_forms"),
                    "security_header_score": sec_score,
                    "status": "available",
                }
        except Exception as e:
            logger.warning(f"Website analysis error: {e}")
            missing_modalities.append("website")
            models_output["website"] = {"status": "failed", "error": str(e)}

        # 4. Modality 3: Visual Intelligence (Playwright + MobileNetV2)
        if include_visual:
            try:
                shot_res = await ScreenshotService.capture_target_screenshot(
                    target_url=normalized_url,
                    scan_id=scan_id,
                )
                screenshot_url = shot_res.get("relative_url")

                vis_service = VisualPredictionService.get_instance()
                if vis_service.is_ready():
                    vis_res = vis_service.analyze_image(shot_res["file_path"], generate_heatmap=True)
                    raw_vis_p = vis_res.get("phishing_probability")
                    p_visual = float(raw_vis_p) if raw_vis_p is not None else None
                    heatmap_url = vis_res.get("heatmap_url")
                    visual_evidence = vis_res.get("evidence", [])
                    if p_visual is not None:
                        modalities_used.append("visual")
                    else:
                        missing_modalities.append("visual")

                    models_output["visual"] = {
                        "model_name": vis_res.get("model_name"),
                        "model_version": vis_res.get("model_version"),
                        "prediction": vis_res.get("prediction"),
                        "probability": p_visual,
                        "confidence_score": vis_res.get("confidence_score"),
                        "screenshot_url": screenshot_url,
                        "heatmap_url": heatmap_url,
                        "latency_ms": vis_res.get("inference_latency_ms"),
                        "status": "available" if p_visual is not None else "failed",
                    }
                else:
                    missing_modalities.append("visual")
                    models_output["visual"] = {"status": "not_available", "message": "Vision model not loaded"}
            except Exception as e:
                logger.warning(f"Visual capture error: {e}")
                missing_modalities.append("visual")
                models_output["visual"] = {"status": "failed", "error": str(e)}
        else:
            missing_modalities.append("visual")
            models_output["visual"] = {"status": "not_available", "message": "Visual analysis omitted by request"}

        # 5. Query External Threat Intelligence & Reputation Subsystem
        reputation_summary = await ReputationService.get_instance().check_reputation(
            url=normalized_url,
            domain=domain,
        )

        # 6. Execute Multi-Modal Stacking Fusion with Zero Fake Fallbacks
        raw_fusion_prob = None
        routing_mode = "unavailable"

        active = [p for p in (p_url, p_website, p_visual) if p is not None]

        if self.stacking_model is not None and active:
            raw_fusion_prob, routing_mode, _ = self.stacking_model.predict_probability(
                p_url=p_url,
                p_website=p_website,
                p_visual=p_visual,
            )
        elif active:
            raw_fusion_prob = float(sum(active) / len(active))
            routing_mode = f"dynamic_active_{len(active)}"

        # 7. Apply Probability Calibration (Platt Scaling)
        if raw_fusion_prob is not None:
            if self.calibrator is not None and self.calibrator.is_fitted:
                calibrated_prob = self.calibrator.calibrate(raw_fusion_prob)
            else:
                calibrated_prob = round(float(raw_fusion_prob), 4)
        else:
            calibrated_prob = None

        # 8. Apply Centralized Empirical Decision Policy Engine
        lexical_signals = {
            "entropy": url_res.get("entropy", 0.0) if 'url_res' in locals() else 0.0,
            "is_ip_address": url_res.get("is_ip_address", False) if 'url_res' in locals() else False,
            "brand_spoof_detected": url_res.get("brand_spoof_detected", False) if 'url_res' in locals() else False,
        }
        decision_eval = DecisionPolicyEngine.evaluate(
            calibrated_probability=calibrated_prob,
            modalities_used=modalities_used,
            missing_modalities=missing_modalities,
            dom_signals=web_res if 'web_res' in locals() else {},
            lexical_signals=lexical_signals,
            reputation_summary=reputation_summary.model_dump(),
        )

        classification = decision_eval["classification"]
        risk_info = {"risk_score": decision_eval["risk_score"], "risk_level": decision_eval["risk_level"]}
        reason_codes = decision_eval["reason_codes"]
        reason_details = decision_eval["reason_details"]
        decision_policy_version = decision_eval["decision_policy_version"]

        # 9. Fuse Evidence Items
        fused_evidence = EvidenceFusionService.fuse_evidence(
            website_evidence=website_evidence,
            visual_evidence=visual_evidence,
            url_threat_indicators=url_threats,
        )

        # 10. Generate Multi-Modal Explainability
        explanation = ExplanationService.generate_explanation(
            classification=classification,
            calibrated_probability=calibrated_prob if calibrated_prob is not None else 0.0,
            modalities_used=modalities_used,
            missing_modalities=missing_modalities,
            base_models=models_output,
            evidence_items=fused_evidence,
        )

        total_ms = round((time.perf_counter() - start_time) * 1000, 2)

        models_output["fusion"] = {
            "model_name": ModelRegistry.REGISTRY["FUSION_MODEL"]["name"],
            "model_version": ModelRegistry.REGISTRY["FUSION_MODEL"]["version"],
            "routing_mode": routing_mode,
            "raw_fusion_probability": round(float(raw_fusion_prob), 4) if raw_fusion_prob is not None else None,
            "calibrated_probability": calibrated_prob,
            "calibration_method": "platt_scaling",
            "decision_policy_version": decision_policy_version,
            "status": "completed" if raw_fusion_prob is not None else "partial",
        }

        # 11. Compute Reproducibility Fingerprints
        from app.intelligence.reproducibility import (
            compute_model_input_hash,
            compute_prediction_hash,
            detect_live_content_change,
        )

        url_feat_hash = models_output.get("url", {}).get("feature_hash") or (url_res.get("feature_hash", "") if 'url_res' in locals() else "")
        dom_snap_hash = web_res.get("dom_snapshot_hash", "") if 'web_res' in locals() else ""
        shot_hash = shot_res.get("screenshot_hash", "") if include_visual and 'shot_res' in locals() else ""

        model_in_hash = compute_model_input_hash({
            "p_url": p_url,
            "p_website": p_website,
            "p_visual": p_visual,
            "routing_mode": routing_mode,
        })

        pred_hash = compute_prediction_hash({
            "classification": classification,
            "phishing_probability": calibrated_prob,
            "risk_score": risk_info["risk_score"],
            "decision_policy_version": decision_policy_version,
        })

        # Check for live content change against previous snapshot if provided
        live_changed, change_notice = detect_live_content_change(dom_snap_hash, previous_snapshot_hash)

        reproducibility_payload = {
            "canonical_url": normalized_url,
            "url_feature_hash": url_feat_hash,
            "dom_snapshot_hash": dom_snap_hash,
            "screenshot_hash": shot_hash,
            "model_input_hash": model_in_hash,
            "prediction_hash": pred_hash,
            "model_versions": {
                "url": models_output.get("url", {}).get("model_version"),
                "website": models_output.get("website", {}).get("model_version"),
                "visual": models_output.get("visual", {}).get("model_version"),
                "fusion": models_output.get("fusion", {}).get("model_version"),
            },
            "feature_versions": {
                "url": "2.0.0",
                "website": "1.0.0",
                "preprocessing": "2.0.0",
            },
            "decision_policy_version": decision_policy_version,
            "thresholds": {
                "legitimate_upper_threshold": 0.25,
                "phishing_lower_threshold": 0.65,
            },
            "live_content_changed": live_changed,
            "content_change_notice": change_notice,
        }

        final_url = web_res.get("http", {}).get("final_url", normalized_url) if 'web_res' in locals() and isinstance(web_res, dict) else normalized_url
        canonical_url = (web_res.get("html", {}).get("meta_tags", {}).get("canonical") if 'web_res' in locals() and isinstance(web_res, dict) else None) or normalized_url
        redirect_chain = web_res.get("redirects", {}).get("hops", []) if 'web_res' in locals() and isinstance(web_res, dict) else []

        return {
            "scan_id": scan_id,
            "url": raw_url,
            "original_url": raw_url,
            "normalized_url": normalized_url,
            "final_url": final_url,
            "canonical_url": canonical_url,
            "redirect_chain": redirect_chain,
            "domain": domain,
            "status": "completed",
            "classification": classification,
            "phishing_probability": calibrated_prob,
            "risk_score": risk_info["risk_score"],
            "risk_level": risk_info["risk_level"],
            "modalities_used": modalities_used,
            "missing_modalities": missing_modalities,
            "models": models_output,
            "evidence": fused_evidence,
            "explanation": explanation,
            "performance": {
                "total_analysis_ms": total_ms,
            },
            "screenshot_url": screenshot_url,
            "heatmap_url": heatmap_url,
            "reproducibility": reproducibility_payload,
            "url_feature_hash": url_feat_hash,
            "dom_snapshot_hash": dom_snap_hash,
            "screenshot_hash": shot_hash,
            "model_input_hash": model_in_hash,
            "prediction_hash": pred_hash,
            "live_content_changed": live_changed,
            "content_change_notice": change_notice,
            "reputation": reputation_summary.model_dump(),
            "reason_codes": reason_codes,
            "reason_details": reason_details,
            "decision_policy_version": decision_policy_version,
        }

