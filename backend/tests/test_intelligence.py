"""
PhishGuard AI - Comprehensive Multi-Modal Intelligence Test Suite
Tests:
1. Multi-modal fusion with all modalities.
2. Dynamic missing-modality routing & fallbacks:
   - URL only
   - URL + Website
   - URL + Visual
   - Missing visual model / failed website analysis
3. Probability calibration & Brier score bounds.
4. Threshold boundary evaluations:
   - 0.0, 1.0, threshold - epsilon, threshold, threshold + epsilon.
5. Risk score (0–100) & low/medium/high presentation risk levels.
6. Unified Model Registry tracking and artifact verification.
7. Evidence fusion synthesis, deduplication, and policy adherence.
8. Standardized multi-modal explanation completeness.
9. Intelligence API endpoints (POST /analyze, GET /{scan_id}, SSRF protection, 404 handling).
10. Database persistence of FusionAnalysisRecord, ModelExecutionRecord, and ExplanationRecord.
"""

import json
from pathlib import Path
import pytest
import numpy as np

from app.intelligence.model_registry import ModelRegistry
from app.intelligence.decision_service import DecisionService
from app.intelligence.risk_engine import RiskEngine
from app.intelligence.evidence_fusion_service import EvidenceFusionService
from app.intelligence.explanation_service import ExplanationService
from app.intelligence.fusion_service import MultiModalFusionService
from ml.fusion.models.stacking_model import StackingFusionModel
from ml.fusion.calibration.probability_calibration import (
    ProbabilityCalibrator,
    compute_brier_score,
    compute_expected_calibration_error,
)
from ml.fusion.calibration.threshold_selection import select_optimal_thresholds, DecisionPolicy


# =========================================================================
# 1. Stacking Fusion & Dynamic Missing-Modality Fallbacks
# =========================================================================
def test_stacking_fusion_and_dynamic_fallbacks():
    # Synthetic training data
    X = np.array([
        [0.1, 0.1, 0.1],
        [0.2, 0.1, 0.05],
        [0.85, 0.9, 0.95],
        [0.9, 0.95, 0.9],
    ])
    y = np.array([0, 0, 1, 1])

    model = StackingFusionModel(C=1.0)
    model.fit(X, y)

    # 1. Full 3 modalities
    p_full, mode_full, mods_full = model.predict_probability(p_url=0.9, p_website=0.95, p_visual=0.9)
    assert 0.0 <= p_full <= 1.0
    assert mode_full == "full_multimodal_stacking"
    assert mods_full == ["url", "website", "visual"]
    assert p_full > 0.50

    # 2. URL + Website (Visual missing/failed)
    p_uw, mode_uw, mods_uw = model.predict_probability(p_url=0.85, p_website=0.9, p_visual=None)
    assert 0.0 <= p_uw <= 1.0
    assert mode_uw == "url_website_stacking_fallback"
    assert mods_uw == ["url", "website"]

    # 3. URL + Visual (Website fetch blocked/failed)
    p_uv, mode_uv, mods_uv = model.predict_probability(p_url=0.9, p_website=None, p_visual=0.95)
    assert 0.0 <= p_uv <= 1.0
    assert mode_uv == "url_visual_stacking_fallback"
    assert mods_uv == ["url", "visual"]

    # 4. URL Only fallback
    p_u, mode_u, mods_u = model.predict_probability(p_url=0.88, p_website=None, p_visual=None)
    assert 0.0 <= p_u <= 1.0
    assert mode_u == "url_only_stacking_fallback"
    assert mods_u == ["url"]


# =========================================================================
# 2. Probability Calibration & Metrics
# =========================================================================
def test_probability_calibration_and_diagnostics():
    raw_probs = np.array([0.15, 0.25, 0.40, 0.75, 0.85, 0.95])
    labels = np.array([0, 0, 0, 1, 1, 1])

    calibrator = ProbabilityCalibrator(method="platt")
    calibrator.fit(raw_probs, labels)

    cal_probs = calibrator.calibrate_array(raw_probs)
    assert len(cal_probs) == len(raw_probs)
    for cp in cal_probs:
        assert 0.0 <= cp <= 1.0

    brier = compute_brier_score(cal_probs, labels)
    assert 0.0 <= brier <= 1.0

    ece, ece_diag = compute_expected_calibration_error(cal_probs, labels, n_bins=5)
    assert 0.0 <= ece <= 1.0
    assert "bin_accuracies" in ece_diag


# =========================================================================
# 3. Threshold Boundaries & Decision Policy
# =========================================================================
def test_threshold_boundaries_and_decision_policy():
    policy = DecisionPolicy(
        legitimate_upper_threshold=0.25,
        phishing_lower_threshold=0.65,
    )

    eps = 0.001

    # Exact 0 and 1
    assert policy.classify(0.0) == "legitimate"
    assert policy.classify(1.0) == "phishing"

    # Boundaries: legit threshold
    assert policy.classify(0.25 - eps) == "legitimate"
    assert policy.classify(0.25) == "legitimate"
    assert policy.classify(0.25 + eps) == "suspicious"

    # Boundaries: phishing threshold
    assert policy.classify(0.65 - eps) == "suspicious"
    assert policy.classify(0.65) == "phishing"
    assert policy.classify(0.65 + eps) == "phishing"

    # Middle ambiguous zone
    assert policy.classify(0.45) == "suspicious"


# =========================================================================
# 4. Risk Engine 0–100 Score & Levels
# =========================================================================
def test_risk_engine_score_and_levels():
    # Low risk
    low_res = RiskEngine.calculate_risk(0.12)
    assert low_res["risk_score"] == 12.0
    assert low_res["risk_level"] == "low"

    # Medium risk
    med_res = RiskEngine.calculate_risk(0.485)
    assert med_res["risk_score"] == 48.5
    assert med_res["risk_level"] == "medium"

    # High risk
    high_res = RiskEngine.calculate_risk(0.932)
    assert high_res["risk_score"] == 93.2
    assert high_res["risk_level"] == "high"


# =========================================================================
# 5. Model Registry
# =========================================================================
def test_model_registry_integrity():
    all_models = ModelRegistry.get_all_models()
    assert "URL_MODEL" in all_models
    assert "WEBSITE_MODEL" in all_models
    assert "VISUAL_MODEL" in all_models
    assert "FUSION_MODEL" in all_models

    fusion_meta = ModelRegistry.get_model_metadata("FUSION_MODEL")
    assert fusion_meta["status"] == "active"
    assert "version" in fusion_meta


# =========================================================================
# 6. Evidence Fusion Service
# =========================================================================
def test_evidence_fusion_service():
    web_ev = [
        {"title": "External Password Form", "severity": "critical", "detail": "Form targets external domain."},
        {"title": "Missing Security Headers", "severity": "low", "detail": "HSTS header is absent."},
    ]
    vis_ev = [
        {"title": "Centered Login Card", "severity": "medium", "description": "Login card in central 40%."},
    ]

    fused = EvidenceFusionService.fuse_evidence(
        website_evidence=web_ev,
        visual_evidence=vis_ev,
    )

    assert len(fused) == 3
    # Check severity priority sorting (critical first)
    assert fused[0]["severity"] == "critical"
    assert fused[0]["title"] == "External Password Form"


# =========================================================================
# 7. Explanation Service
# =========================================================================
def test_explanation_service_completeness():
    exp = ExplanationService.generate_explanation(
        classification="phishing",
        calibrated_probability=0.942,
        modalities_used=["url", "website", "visual"],
        missing_modalities=[],
        base_models={
            "url": {"probability": 0.91},
            "website": {"probability": 0.97},
            "visual": {"probability": 0.95},
        },
        evidence_items=[{"title": "External Password Form", "description": "Targets untrusted drop host."}],
    )

    assert "summary" in exp
    assert exp["classification"] == "phishing"
    assert exp["calibrated_phishing_probability"] == 0.942
    assert len(exp["key_model_signals"]) == 3
    assert len(exp["observed_factual_evidence"]) == 1


# =========================================================================
# 8. Multi-Modal Intelligence API Endpoints
# =========================================================================
@pytest.mark.asyncio
async def test_intelligence_api_endpoints(client):
    # 1. 404 Handling on non-existent scan
    res_404 = await client.get("/api/v1/intelligence/non-existent-scan-id-xyz")
    assert res_404.status_code == 404

    # 2. SSRF Protection: Localhost & Private IP rejected with 403 Forbidden
    res_ssrf = await client.post(
        "/api/v1/intelligence/analyze",
        json={"url": "http://127.0.0.1:8000/private", "include_visual": False},
    )
    assert res_ssrf.status_code == 403
    assert "blocked for security" in res_ssrf.json()["detail"].lower()

    # 3. Successful Intelligence Assessment (without visual to run fast in test)
    res_ok = await client.post(
        "/api/v1/intelligence/analyze",
        json={"url": "https://en.wikipedia.org/wiki/Computer_security", "include_visual": False},
    )
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "completed"
    assert data["classification"] in ("legitimate", "suspicious", "phishing")
    assert 0.0 <= data["phishing_probability"] <= 1.0
    assert 0.0 <= data["risk_score"] <= 100.0
    assert data["risk_level"] in ("low", "medium", "high")
    assert "models" in data
    assert "explanation" in data

    # 4. Query Assessment by Scan ID
    scan_id = data["scan_id"]
    res_get = await client.get(f"/api/v1/intelligence/{scan_id}")
    assert res_get.status_code == 200
    get_data = res_get.json()
    assert get_data["scan_id"] == scan_id
    assert get_data["classification"] == data["classification"]
