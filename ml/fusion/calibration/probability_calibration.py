"""
PhishGuard AI - Probability Calibration Engine
Implements mathematically rigorous probability calibration:
1. Platt Scaling (Sigmoidal logistic calibration)
2. Isotonic Regression (Non-parametric isotonic calibration)
3. Calibration Diagnostics:
   - Brier Score (mean squared error of probability forecasts)
   - Expected Calibration Error (ECE) via equal-width binning
   - Reliability Curve generation
CRITICAL SCIENTIFIC RULE: Fitted strictly using validation/calibration data; never test data.
"""

from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
import joblib


def compute_brier_score(y_prob: np.ndarray, y_true: np.ndarray) -> float:
    """Computes Brier Score: 1/N sum((p_i - y_i)^2). Lower is better (0.0 = perfect)."""
    return float(np.mean((np.array(y_prob) - np.array(y_true)) ** 2))


def compute_expected_calibration_error(
    y_prob: np.ndarray, y_true: np.ndarray, n_bins: int = 10
) -> Tuple[float, Dict[str, Any]]:
    """
    Computes Expected Calibration Error (ECE):
    ECE = sum(|B_m| / N * |acc(B_m) - conf(B_m)|)
    Also returns bin edges, confidences, accuracies, and counts for reliability diagrams.
    """
    probs = np.array(y_prob)
    labels = np.array(y_true)
    N = len(probs)
    if N == 0:
        return 0.0, {}

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0

    bin_accs = []
    bin_confs = []
    bin_counts = []

    for i in range(n_bins):
        low, high = bin_edges[i], bin_edges[i + 1]
        if i == n_bins - 1:
            idx = (probs >= low) & (probs <= high)
        else:
            idx = (probs >= low) & (probs < high)

        count = np.sum(idx)
        bin_counts.append(int(count))

        if count > 0:
            bin_acc = float(np.mean(labels[idx]))
            bin_conf = float(np.mean(probs[idx]))
            bin_accs.append(round(bin_acc, 4))
            bin_confs.append(round(bin_conf, 4))
            ece += (count / N) * abs(bin_acc - bin_conf)
        else:
            bin_accs.append(round((low + high) / 2.0, 4))
            bin_confs.append(round((low + high) / 2.0, 4))

    return round(float(ece), 4), {
        "n_bins": n_bins,
        "bin_edges": [round(float(b), 2) for b in bin_edges],
        "bin_accuracies": bin_accs,
        "bin_confidences": bin_confs,
        "bin_counts": bin_counts,
    }


class ProbabilityCalibrator:
    def __init__(self, method: str = "platt"):
        self.method = method.lower()  # "platt" or "isotonic"
        self.model = None
        self.is_fitted = False

    def fit(self, y_prob: np.ndarray, y_true: np.ndarray):
        """
        Fits calibrator using validation probabilities.
        y_prob: raw predicted probabilities in [0.0, 1.0]
        y_true: binary ground truth in {0, 1}
        """
        probs = np.array(y_prob, dtype=float).reshape(-1, 1)
        labels = np.array(y_true, dtype=int)

        if self.method in ("platt", "sigmoid", "logistic"):
            # Platt scaling: LogisticRegression on log-odds or raw probabilities
            eps = 1e-4
            clipped = np.clip(probs, eps, 1.0 - eps)
            log_odds = np.log(clipped / (1.0 - clipped))
            self.model = LogisticRegression(C=1.0, solver="lbfgs")
            self.model.fit(log_odds, labels)
            self.is_fitted = True

        elif self.method in ("isotonic", "iso"):
            self.model = IsotonicRegression(out_of_bounds="clip", y_min=0.01, y_max=0.99)
            self.model.fit(probs.flatten(), labels)
            self.is_fitted = True

        else:
            raise ValueError(f"Unknown calibration method: {self.method}")

        return self

    def calibrate(self, raw_prob: float) -> float:
        """Calibrates a single probability value into a reliable probability estimate."""
        if not self.is_fitted:
            return float(np.clip(raw_prob, 0.0, 1.0))

        if self.method in ("platt", "sigmoid", "logistic"):
            eps = 1e-4
            p_clip = np.clip(raw_prob, eps, 1.0 - eps)
            log_odd = np.log(p_clip / (1.0 - p_clip)).reshape(1, -1)
            cal_p = float(self.model.predict_proba(log_odd)[0, 1])
            return round(float(np.clip(cal_p, 0.001, 0.999)), 4)

        elif self.method in ("isotonic", "iso"):
            cal_p = float(self.model.predict([raw_prob])[0])
            return round(float(np.clip(cal_p, 0.001, 0.999)), 4)

        return round(float(np.clip(raw_prob, 0.0, 1.0)), 4)

    def calibrate_array(self, probs: np.ndarray) -> np.ndarray:
        return np.array([self.calibrate(p) for p in probs])

    def save(self, output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, output_path)

    @classmethod
    def load(cls, path: Path) -> "ProbabilityCalibrator":
        return joblib.load(path)
