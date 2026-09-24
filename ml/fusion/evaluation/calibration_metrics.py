"""
PhishGuard AI - Calibration Diagnostics & Plotting Engine
Plots reliability diagrams (calibration curves) comparing raw vs calibrated probabilities.
"""

from typing import Tuple, Dict, Any, List
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from sklearn.calibration import calibration_curve

from ml.fusion.calibration.probability_calibration import compute_brier_score, compute_expected_calibration_error


def plot_calibration_curves(
    y_true: np.ndarray,
    prob_dict: Dict[str, np.ndarray],
    output_path: Path,
    n_bins: int = 5,
) -> Dict[str, Any]:
    """
    Plots reliability diagram for multiple probability models.
    prob_dict: {"Raw Stacking": raw_probs, "Calibrated Stacking": cal_probs}
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(7, 6))

    # Reference diagonal (perfect calibration)
    plt.plot([0, 1], [0, 1], "k--", label="Perfect Calibration", linewidth=1.5)

    stats = {}
    colors = ["#f59e0b", "#06b6d4", "#10b981", "#8b5cf6"]

    for i, (name, probs) in enumerate(prob_dict.items()):
        brier = compute_brier_score(probs, y_true)
        ece, _ = compute_expected_calibration_error(probs, y_true, n_bins=n_bins)
        stats[name] = {"brier_score": round(brier, 4), "ece": round(ece, 4)}

        prob_true, prob_pred = calibration_curve(y_true, probs, n_bins=n_bins, strategy="uniform")
        color = colors[i % len(colors)]
        plt.plot(prob_pred, prob_true, marker="o", linewidth=2, color=color, label=f"{name} (Brier: {brier:.4f}, ECE: {ece:.3f})")

    plt.title("PhishGuard AI - Reliability Diagram (Probability Calibration)", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel("Mean Predicted Probability", fontsize=11)
    plt.ylabel("Fraction of True Phishing Positives", fontsize=11)
    plt.ylim([-0.05, 1.05])
    plt.xlim([-0.05, 1.05])
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.legend(loc="lower right", frameon=True)
    plt.tight_layout()

    plt.savefig(output_path, dpi=300)
    plt.close()
    return stats
