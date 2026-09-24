"""
PhishGuard AI - Comprehensive Multi-Modal Fusion Evaluation Harness
Evaluates:
- Strategy A: Weighted Probability Fusion
- Strategy B: Stacking Meta-Classifier (Raw & Calibrated)
- Strategy C: Evidence-Enhanced Meta-Classifier
Generates:
- ml/fusion/experiments/fusion_model_comparison.csv
- ml/fusion/experiments/figures/confusion_matrix_fusion.png
- ml/fusion/experiments/figures/roc_curve_fusion.png
- ml/fusion/experiments/figures/pr_curve_fusion.png
- ml/fusion/experiments/figures/calibration_curve.png
"""

import sys
import time
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
    precision_recall_curve,
)

# Ensure project root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.fusion.models.fusion_factory import create_fusion_model
from ml.fusion.models.meta_classifier import EVIDENCE_FEATURE_NAMES
from ml.fusion.calibration.probability_calibration import ProbabilityCalibrator, compute_brier_score
from ml.fusion.evaluation.calibration_metrics import plot_calibration_curves

DATASETS_DIR = REPO_ROOT / "ml" / "fusion" / "datasets"
ARTIFACTS_DIR = REPO_ROOT / "ml" / "fusion" / "artifacts"
EXPERIMENTS_DIR = REPO_ROOT / "ml" / "fusion" / "experiments"
FIGURES_DIR = EXPERIMENTS_DIR / "figures"


def evaluate_fusion_harness():
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    print("============================================================")
    print("PHISHGUARD AI - MULTI-MODAL FUSION EVALUATION HARNESS")
    print("============================================================")

    test_path = DATASETS_DIR / "test.csv"
    if not test_path.exists():
        raise FileNotFoundError(f"Holdout test set not found at {test_path}")

    test_df = pd.read_csv(test_path)
    y_test = test_df["label"].values

    # Load artifacts
    simple_model = create_fusion_model("simple", checkpoint_path=ARTIFACTS_DIR / "simple_fusion_best.joblib")
    stacking_model = create_fusion_model("stacking", checkpoint_path=ARTIFACTS_DIR / "stacking_fusion_best.joblib")
    evidence_model = create_fusion_model("evidence", checkpoint_path=ARTIFACTS_DIR / "evidence_fusion_best.joblib")
    calibrator = ProbabilityCalibrator.load(ARTIFACTS_DIR / "probability_calibrator_best.joblib")

    # Generate predictions & measure latency
    X_probs = test_df[["p_url", "p_website", "p_visual"]].values

    # Strategy A
    t0 = time.perf_counter()
    probs_simple = np.array([simple_model.predict_probability(row) for row in X_probs])
    lat_simple = round((time.perf_counter() - t0) * 1000 / len(y_test), 3)

    # Strategy B (Raw)
    t0 = time.perf_counter()
    probs_stack_raw = np.array([
        stacking_model.predict_probability(row[0], row[1], row[2])[0]
        for row in X_probs
    ])
    lat_stack_raw = round((time.perf_counter() - t0) * 1000 / len(y_test), 3)

    # Strategy B (Calibrated)
    t0 = time.perf_counter()
    probs_stack_cal = calibrator.calibrate_array(probs_stack_raw)
    lat_stack_cal = round((time.perf_counter() - t0) * 1000 / len(y_test), 3)

    # Strategy C
    X_ev = test_df[EVIDENCE_FEATURE_NAMES].values
    t0 = time.perf_counter()
    probs_evidence = np.array([evidence_model.predict_probability(row) for row in X_ev])
    lat_evidence = round((time.perf_counter() - t0) * 1000 / len(y_test), 3)

    models_to_evaluate = {
        "Strategy_A_Weighted_Probability": (probs_simple, lat_simple),
        "Strategy_B_Stacking_Raw": (probs_stack_raw, lat_stack_raw),
        "Strategy_B_Stacking_Calibrated": (probs_stack_cal, lat_stack_cal),
        "Strategy_C_Evidence_Enhanced": (probs_evidence, lat_evidence),
    }

    comparison_results = []

    for name, (probs, latency) in models_to_evaluate.items():
        preds = (probs >= 0.50).astype(int)

        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, zero_division=0)
        rec = recall_score(y_test, preds, zero_division=0)
        f1 = f1_score(y_test, preds, zero_division=0)

        try:
            auc = roc_auc_score(y_test, probs)
        except Exception:
            auc = 0.5

        cm = confusion_matrix(y_test, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        brier = compute_brier_score(probs, y_test)

        comparison_results.append({
            "strategy": name,
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(auc), 4),
            "brier_score": round(float(brier), 4),
            "false_positive_rate": round(float(fpr), 4),
            "false_negative_rate": round(float(fnr), 4),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "inference_time_ms": latency,
        })

    comp_df = pd.DataFrame(comparison_results)
    out_csv = EXPERIMENTS_DIR / "fusion_model_comparison.csv"
    comp_df.to_csv(out_csv, index=False)
    print(f"\n[Artifact] Saved fusion model comparison to: {out_csv}")
    print(comp_df[["strategy", "accuracy", "f1", "roc_auc", "brier_score", "inference_time_ms"]])

    # 1. Confusion Matrix for Deployment Model (Strategy B Calibrated)
    cm_best = confusion_matrix(y_test, (probs_stack_cal >= 0.50).astype(int), labels=[0, 1])
    plt.figure(figsize=(5, 4.5))
    plt.imshow(cm_best, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title("PhishGuard AI - Multi-Modal Fusion Confusion Matrix", fontsize=11, fontweight="bold")
    plt.colorbar()
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ["Legitimate", "Phishing"], fontsize=10)
    plt.yticks(tick_marks, ["Legitimate", "Phishing"], fontsize=10)
    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(cm_best[i, j]), horizontalalignment="center",
                     color="white" if cm_best[i, j] > cm_best.max() / 2 else "black",
                     fontsize=14, fontweight="bold")
    plt.ylabel("True Label", fontsize=10)
    plt.xlabel("Predicted Label", fontsize=10)
    plt.tight_layout()
    cm_path = FIGURES_DIR / "confusion_matrix_fusion.png"
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[Artifact] Saved confusion matrix figure to: {cm_path}")

    # 2. ROC Curves
    plt.figure(figsize=(6, 5))
    for name, (probs, _) in models_to_evaluate.items():
        fpr, tpr, _ = roc_curve(y_test, probs)
        auc = roc_auc_score(y_test, probs)
        plt.plot(fpr, tpr, label=f"{name} (AUC={auc:.4f})", linewidth=1.8)
    plt.plot([0, 1], [0, 1], "k--", label="Random Classifier", alpha=0.6)
    plt.title("PhishGuard AI - Multi-Modal Fusion ROC Curves", fontsize=12, fontweight="bold")
    plt.xlabel("False Positive Rate", fontsize=10)
    plt.ylabel("True Positive Rate (Recall)", fontsize=10)
    plt.legend(loc="lower right", fontsize=8)
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    roc_path = FIGURES_DIR / "roc_curve_fusion.png"
    plt.savefig(roc_path, dpi=300)
    plt.close()
    print(f"[Artifact] Saved ROC curve figure to: {roc_path}")

    # 3. Precision-Recall Curves
    plt.figure(figsize=(6, 5))
    for name, (probs, _) in models_to_evaluate.items():
        prec, rec, _ = precision_recall_curve(y_test, probs)
        plt.plot(rec, prec, label=name, linewidth=1.8)
    plt.title("PhishGuard AI - Precision-Recall Curves", fontsize=12, fontweight="bold")
    plt.xlabel("Recall", fontsize=10)
    plt.ylabel("Precision", fontsize=10)
    plt.legend(loc="lower left", fontsize=8)
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    pr_path = FIGURES_DIR / "pr_curve_fusion.png"
    plt.savefig(pr_path, dpi=300)
    plt.close()
    print(f"[Artifact] Saved PR curve figure to: {pr_path}")

    # 4. Calibration Curve
    cal_path = FIGURES_DIR / "calibration_curve.png"
    plot_calibration_curves(
        y_test,
        {"Raw Stacking": probs_stack_raw, "Calibrated Stacking": probs_stack_cal},
        cal_path,
        n_bins=5,
    )
    print(f"[Artifact] Saved calibration reliability diagram to: {cal_path}")

    return comp_df


if __name__ == "__main__":
    evaluate_fusion_harness()
