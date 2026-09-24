"""
PhishGuard AI - Same URL 10-Run Reproducibility Tests
Verifies mathematical determinism across consecutive runs on identical inputs.
Ensures zero variance across 10 runs of ChatGPT URL and fixture targets.
"""

import pytest
import numpy as np
from app.ml.prediction_service import PredictionService
from app.intelligence.fusion_service import MultiModalFusionService
from app.intelligence.decision_service import DecisionService
from app.intelligence.risk_engine import RiskEngine
from app.intelligence.reproducibility import compare_scans


def test_chatgpt_url_10_run_determinism():
    """
    10 consecutive runs of the ML URL model on https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c
    must return identical probability, identical hashes, and standard deviation == 0.0.
    """
    target_url = "https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c"

    probabilities = []
    feature_hashes = []
    prediction_hashes = []

    for _ in range(10):
        pred = PredictionService.predict_url(target_url, explain=False)
        probabilities.append(pred["probability"])
        if pred.get("feature_hash"):
            feature_hashes.append(pred["feature_hash"])
        if pred.get("prediction_hash"):
            prediction_hashes.append(pred["prediction_hash"])

    # 1. Check all probabilities are identical
    assert len(probabilities) == 10
    assert np.std(probabilities) == 0.0, f"Probability variance detected across 10 runs: {probabilities}"
    assert probabilities[0] == probabilities[-1]

    # 2. Check hashes are identical
    if feature_hashes:
        assert len(set(feature_hashes)) == 1, "Feature hashes differed across runs!"
    if prediction_hashes:
        assert len(set(prediction_hashes)) == 1, "Prediction hashes differed across runs!"


def test_fusion_service_10_run_determinism_with_fixed_inputs():
    """
    10 consecutive runs of MultiModalFusionService stacking and calibration pipeline
    with identical model outputs must produce identical calibrated probabilities,
    identical risk scores, identical classification, and strictly zero variance.
    """
    fusion_svc = MultiModalFusionService.get_instance()
    p_url = 0.994
    p_website = 0.0323
    p_visual = None

    runs = []
    for _ in range(10):
        raw_prob, routing_mode, _ = fusion_svc.stacking_model.predict_probability(
            p_url=p_url,
            p_website=p_website,
            p_visual=p_visual,
        )
        if fusion_svc.calibrator and fusion_svc.calibrator.is_fitted:
            cal_prob = fusion_svc.calibrator.calibrate(raw_prob)
        else:
            cal_prob = round(float(raw_prob), 4)

        classification = DecisionService.classify(cal_prob)
        risk_info = RiskEngine.calculate_risk(cal_prob)

        runs.append({
            "raw_prob": raw_prob,
            "cal_prob": cal_prob,
            "risk_score": risk_info["risk_score"],
            "classification": classification,
        })

    # Assert 10 runs are strictly identical
    assert len(runs) == 10
    first_run = runs[0]
    for i, r in enumerate(runs[1:], start=2):
        assert r["raw_prob"] == first_run["raw_prob"], f"Run {i} raw_prob diverged"
        assert r["cal_prob"] == first_run["cal_prob"], f"Run {i} cal_prob diverged"
        assert r["risk_score"] == first_run["risk_score"], f"Run {i} risk_score diverged"
        assert r["classification"] == first_run["classification"], f"Run {i} classification diverged"

    cal_probs = [r["cal_prob"] for r in runs]
    assert np.std(cal_probs) == 0.0, "calibrated probability variance is non-zero!"
