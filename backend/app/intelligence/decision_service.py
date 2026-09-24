"""
PhishGuard AI - Decision Service
Applies empirical, validation-tuned decision policy thresholds to map calibrated
phishing probabilities to final security classifications:
- LEGITIMATE
- SUSPICIOUS
- PHISHING
"""

import json
from pathlib import Path
from typing import Dict, Any

POLICY_FILE = Path(__file__).resolve().parent.parent.parent.parent / "ml" / "fusion" / "artifacts" / "decision_policy.json"


class DecisionService:
    _policy: Dict[str, Any] = None

    @classmethod
    def _load_policy(cls) -> Dict[str, Any]:
        if cls._policy is None:
            if POLICY_FILE.exists():
                try:
                    with open(POLICY_FILE, "r", encoding="utf-8") as f:
                        cls._policy = json.load(f)
                except Exception:
                    cls._policy = cls._default_policy()
            else:
                cls._policy = cls._default_policy()
        return cls._policy

    @classmethod
    def _default_policy(cls) -> Dict[str, Any]:
        return {
            "version": "1.0.0",
            "legitimate_upper_threshold": 0.25,
            "phishing_lower_threshold": 0.65,
            "selection_method": "default_safeguard",
        }

    @classmethod
    def classify(cls, calibrated_probability: float) -> str:
        """
        Maps probability to 'legitimate', 'suspicious', or 'phishing'.
        """
        policy = cls._load_policy()
        legit_th = float(policy.get("legitimate_upper_threshold", 0.25))
        phish_th = float(policy.get("phishing_lower_threshold", 0.65))

        p = float(calibrated_probability)
        if p >= phish_th:
            return "phishing"
        elif p <= legit_th:
            return "legitimate"
        else:
            return "suspicious"

    @classmethod
    def get_policy_metadata(cls) -> Dict[str, Any]:
        return cls._load_policy()
