"""
PhishGuard AI - Empirical Decision Policy & Threshold Selection Engine
Determines optimal decision boundaries for:
- LEGITIMATE: P(phishing) <= legitimate_upper_threshold
- SUSPICIOUS: legitimate_upper_threshold < P(phishing) < phishing_lower_threshold
- PHISHING:   P(phishing) >= phishing_lower_threshold
CRITICAL SCIENTIFIC RULE: Selected strictly using validation data. Never use test data to tune thresholds.
"""

from typing import Dict, Any, Tuple
import json
from pathlib import Path
import numpy as np


class DecisionPolicy:
    def __init__(
        self,
        legitimate_upper_threshold: float = 0.35,
        phishing_lower_threshold: float = 0.65,
        version: str = "1.0.0",
        selection_method: str = "empirical_validation_optimization",
        validation_dataset: str = "val.csv",
        metrics_summary: Dict[str, Any] = None,
    ):
        self.legitimate_upper_threshold = round(float(legitimate_upper_threshold), 4)
        self.phishing_lower_threshold = round(float(phishing_lower_threshold), 4)
        self.version = version
        self.selection_method = selection_method
        self.validation_dataset = validation_dataset
        self.metrics_summary = metrics_summary or {}

    def classify(self, calibrated_probability: float) -> str:
        """
        Maps calibrated phishing probability to:
        - "legitimate"
        - "suspicious"
        - "phishing"
        """
        p = float(calibrated_probability)
        if p >= self.phishing_lower_threshold:
            return "phishing"
        elif p <= self.legitimate_upper_threshold:
            return "legitimate"
        else:
            return "suspicious"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "legitimate_upper_threshold": self.legitimate_upper_threshold,
            "phishing_lower_threshold": self.phishing_lower_threshold,
            "selection_method": self.selection_method,
            "validation_dataset": self.validation_dataset,
            "classification_policy": {
                "legitimate": f"probability <= {self.legitimate_upper_threshold}",
                "suspicious": f"{self.legitimate_upper_threshold} < probability < {self.phishing_lower_threshold}",
                "phishing": f"probability >= {self.phishing_lower_threshold}",
            },
            "validation_metrics": self.metrics_summary,
        }

    def save(self, output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Path) -> "DecisionPolicy":
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        return cls(
            legitimate_upper_threshold=d["legitimate_upper_threshold"],
            phishing_lower_threshold=d["phishing_lower_threshold"],
            version=d.get("version", "1.0.0"),
            selection_method=d.get("selection_method", "custom"),
            validation_dataset=d.get("validation_dataset", "unknown"),
            metrics_summary=d.get("validation_metrics", {}),
        )


def select_optimal_thresholds(
    val_probs: np.ndarray,
    val_labels: np.ndarray,
    target_recall: float = 0.95,
) -> DecisionPolicy:
    """
    Empirically selects thresholds on validation set:
    1. Legitimate upper threshold: max probability of known legitimate samples, capped at 0.35.
    2. Phishing lower threshold: min probability of known phishing samples, floored at 0.65.
    3. Guarantees that suspicious band captures borderline ambiguous scores.
    """
    probs = np.array(val_probs)
    labels = np.array(val_labels)

    legit_probs = probs[labels == 0]
    phish_probs = probs[labels == 1]

    # Find highest legit probability in validation set
    max_legit = float(np.max(legit_probs)) if len(legit_probs) > 0 else 0.20
    # Find lowest phishing probability in validation set
    min_phish = float(np.min(phish_probs)) if len(phish_probs) > 0 else 0.80

    # Apply safety margins
    legit_thresh = min(0.35, max(0.15, max_legit + 0.05))
    phish_thresh = max(0.65, min(0.85, min_phish - 0.05))

    if legit_thresh >= phish_thresh:
        # Fallback if validation set is too tight
        legit_thresh = 0.35
        phish_thresh = 0.65

    # Compute validation classification stats under these thresholds
    classifications = []
    for p in probs:
        if p >= phish_thresh:
            classifications.append("phishing")
        elif p <= legit_thresh:
            classifications.append("legitimate")
        else:
            classifications.append("suspicious")

    metrics = {
        "val_samples_count": len(probs),
        "val_legitimate_count": int(np.sum(labels == 0)),
        "val_phishing_count": int(np.sum(labels == 1)),
        "max_legitimate_prob_observed": round(max_legit, 4),
        "min_phishing_prob_observed": round(min_phish, 4),
        "suspicious_margin_width": round(phish_thresh - legit_thresh, 4),
    }

    return DecisionPolicy(
        legitimate_upper_threshold=legit_thresh,
        phishing_lower_threshold=phish_thresh,
        version="1.0.0",
        selection_method="empirical_validation_optimization",
        validation_dataset="ml/fusion/datasets/val.csv",
        metrics_summary=metrics,
    )
