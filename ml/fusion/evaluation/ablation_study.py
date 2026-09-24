"""
PhishGuard AI - Multi-Modal Ablation Study
Empirically evaluates the 7 possible modality combinations on the holdout test set:
1. URL Only
2. Website Only
3. Visual Only
4. URL + Website
5. URL + Visual
6. Website + Visual
7. URL + Website + Visual (Full Multimodal)
Exports: ml/fusion/experiments/ablation_study.csv
CRITICAL RULE: Never assume multimodal always performs better. Report actual empirical metrics.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

# Ensure project root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.fusion.models.fusion_factory import create_fusion_model
from ml.fusion.calibration.probability_calibration import compute_brier_score

DATASETS_DIR = REPO_ROOT / "ml" / "fusion" / "datasets"
ARTIFACTS_DIR = REPO_ROOT / "ml" / "fusion" / "artifacts"
EXPERIMENTS_DIR = REPO_ROOT / "ml" / "fusion" / "experiments"


def run_ablation_study():
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
    print("============================================================")
    print("PHISHGUARD AI - MULTI-MODAL ABLATION STUDY")
    print("============================================================")

    test_path = DATASETS_DIR / "test.csv"
    if not test_path.exists():
        raise FileNotFoundError(f"Holdout test set not found at {test_path}")

    test_df = pd.read_csv(test_path)
    y_test = test_df["label"].values

    stacking_path = ARTIFACTS_DIR / "stacking_fusion_best.joblib"
    if not stacking_path.exists():
        raise FileNotFoundError(f"Stacking artifact not found at {stacking_path}")

    stacking_model = create_fusion_model("stacking", checkpoint_path=stacking_path)

    p_url = test_df["p_url"].values
    p_web = test_df["p_website"].values
    p_vis = test_df["p_visual"].values

    # Define the 7 ablation modalities
    ablation_configs = {
        "URL_Only": p_url,
        "Website_Only": p_web,
        "Visual_Only": p_vis,
        "URL_Website": np.array([
            stacking_model.predict_probability(p_u, p_w, None)[0]
            for p_u, p_w in zip(p_url, p_web)
        ]),
        "URL_Visual": np.array([
            stacking_model.predict_probability(p_u, None, p_v)[0]
            for p_u, p_v in zip(p_url, p_vis)
        ]),
        "Website_Visual": np.array([
            stacking_model.predict_probability(None, p_w, p_v)[0]
            for p_w, p_v in zip(p_web, p_vis)
        ]),
        "URL_Website_Visual (Full)": np.array([
            stacking_model.predict_probability(p_u, p_w, p_v)[0]
            for p_u, p_w, p_v in zip(p_url, p_web, p_vis)
        ]),
    }

    results = []

    for name, probs in ablation_configs.items():
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

        results.append({
            "modality_combination": name,
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(auc), 4),
            "false_positive_rate": round(float(fpr), 4),
            "false_negative_rate": round(float(fnr), 4),
            "brier_score": round(float(brier), 4),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        })

    ablation_df = pd.DataFrame(results)
    out_csv = EXPERIMENTS_DIR / "ablation_study.csv"
    ablation_df.to_csv(out_csv, index=False)
    print(f"\n[Artifact] Saved ablation study results to: {out_csv}")
    print(ablation_df[["modality_combination", "accuracy", "f1_score", "roc_auc", "brier_score", "false_positive_rate"]])

    return ablation_df


if __name__ == "__main__":
    run_ablation_study()
