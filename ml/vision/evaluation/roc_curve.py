"""
PhishGuard AI - ROC Curve & Calibration Plotter
Generates Receiver Operating Characteristic (ROC) curve plots and metrics.
"""

from typing import List, Dict, Any
from pathlib import Path
import json
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc


def generate_and_save_roc_curve(
    y_true: List[int],
    y_probs: List[float],
    output_dir: Path,
    model_name: str,
) -> Dict[str, Any]:
    """
    Computes ROC curve, AUC score, and saves plot + JSON metadata.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        fpr, tpr, thresholds = roc_curve(y_true, y_probs)
        roc_auc = float(auc(fpr, tpr))
    except Exception:
        fpr = [0.0, 1.0]
        tpr = [0.0, 1.0]
        thresholds = [1.0, 0.0]
        roc_auc = 0.5

    roc_data = {
        "model_name": model_name,
        "roc_auc": round(roc_auc, 4),
        "fpr": [round(float(x), 4) for x in fpr],
        "tpr": [round(float(x), 4) for x in tpr],
        "thresholds": [round(float(x), 4) for x in thresholds],
    }

    # Save JSON
    json_path = output_dir / f"roc_curve_{model_name.lower()}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(roc_data, f, indent=2)

    # Plot
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, color="#0072b2", lw=2, label=f"ROC curve (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color="#999999", lw=1.5, linestyle="--", label="Random Classifier")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (1 - Specificity)")
    plt.ylabel("True Positive Rate (Recall)")
    plt.title(f"ROC Curve — {model_name}")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.tight_layout()

    plot_path = output_dir / f"roc_curve_{model_name.lower()}.png"
    plt.savefig(plot_path, dpi=200)
    plt.close()

    roc_data["plot_path"] = str(plot_path)
    roc_data["json_path"] = str(json_path)
    return roc_data
