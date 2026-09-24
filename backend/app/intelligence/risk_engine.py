"""
PhishGuard AI - Unified Risk Assessment Engine
Translates scientifically calibrated phishing probabilities into:
1. Continuous 0–100 Risk Score: risk_score = calibrated_probability * 100
2. Presentation Risk Level: LOW, MEDIUM, HIGH
CRITICAL ARCHITECTURAL PRINCIPLE:
Classification terminology ('legitimate', 'suspicious', 'phishing') is strictly decoupled
from presentation risk levels ('low', 'medium', 'high').
No arbitrary points are added for visual cues or headers after calibration.
"""

from typing import Dict, Any
from app.intelligence.decision_service import DecisionService


class RiskEngine:
    @staticmethod
    def calculate_risk(calibrated_probability: float) -> Dict[str, Any]:
        """
        Calculates risk score and risk level from calibrated probability.
        """
        prob = max(0.0, min(1.0, float(calibrated_probability)))
        risk_score = round(prob * 100.0, 1)

        policy = DecisionService.get_policy_metadata()
        legit_th = float(policy.get("legitimate_upper_threshold", 0.25)) * 100.0
        phish_th = float(policy.get("phishing_lower_threshold", 0.65)) * 100.0

        if risk_score >= phish_th:
            risk_level = "high"
        elif risk_score <= legit_th:
            risk_level = "low"
        else:
            risk_level = "medium"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "scale": "0_to_100",
            "thresholds": {
                "low_upper": legit_th,
                "high_lower": phish_th,
            }
        }
