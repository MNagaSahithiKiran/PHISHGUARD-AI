"""
PhishGuard AI - Confusion Matrix Generator
Plots and saves confusion matrix visualizations and raw count tables for vision models.
"""

from typing import List, Dict, Any
from pathlib import Path
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix


def generate_and_save_confusion_matrix(
    y_true: List[int],
    y_pred: List[int],
    output_dir: Path,
    model_name: str,
) -> Dict[str, Any]:
    """
    Computes confusion matrix, saves PNG heatmap and JSON counts.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    labels = ["Legitimate", "Phishing"]
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    tn, fp, fn, tp = cm.ravel()
    cm_data = {
        "model_name": model_name,
        "classes": labels,
        "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }

    # Save JSON
    json_path = output_dir / f"confusion_matrix_{model_name.lower()}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(cm_data, f, indent=2)

    # Save Plot
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels,
        cbar=False,
    )
    plt.title(f"Confusion Matrix — {model_name}")
    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Ground Truth")
    plt.tight_layout()

    plot_path = output_dir / f"confusion_matrix_{model_name.lower()}.png"
    plt.savefig(plot_path, dpi=200)
    plt.close()

    cm_data["plot_path"] = str(plot_path)
    cm_data["json_path"] = str(json_path)
    return cm_data
