"""
PhishGuard AI - Confusion Matrix Visualizer.
Generates publication-quality confusion matrix figures and saves them in ml/experiments/figures/
"""

from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

FIGURES_DIR = Path(__file__).resolve().parent.parent / "experiments" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def plot_and_save_confusion_matrix(cm_dict: dict, model_name: str) -> Path:
    """
    Renders and saves a labeled confusion matrix figure.
    """
    tn = cm_dict["tn"]
    fp = cm_dict["fp"]
    fn = cm_dict["fn"]
    tp = cm_dict["tp"]

    matrix = np.array([[tn, fp], [fn, tp]])
    labels = ["Actual Legitimate", "Actual Phishing"]
    pred_labels = ["Predicted Legitimate", "Predicted Phishing"]

    plt.figure(figsize=(6, 5))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=pred_labels,
        yticklabels=labels,
        cbar=False,
        annot_kws={"size": 14, "weight": "bold"}
    )
    plt.title(f"Confusion Matrix: {model_name}", fontsize=12, pad=12, weight="bold")
    plt.ylabel("Ground Truth", fontsize=10)
    plt.xlabel("Classifier Prediction", fontsize=10)
    plt.tight_layout()

    out_path = FIGURES_DIR / f"cm_{model_name.lower().replace(' ', '_')}.png"
    plt.savefig(out_path, dpi=200)
    plt.close()
    return out_path
