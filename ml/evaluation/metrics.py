"""
PhishGuard AI - Comprehensive Evaluation Metrics.
Calculates:
- Accuracy, Precision, Recall, F1-Score, ROC-AUC
- Confusion Matrix: TN, FP, FN, TP
- False Positive Rate (FPR), False Negative Rate (FNR) with safe division
- Latency (inference time per sample)
"""

from typing import Dict, Any
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


def calculate_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray = None,
    training_time_sec: float = 0.0,
    inference_time_ms: float = 0.0,
) -> Dict[str, Any]:
    """
    Computes rigorous classification metrics on binary labels (0=Legitimate, 1=Phishing).
    """
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    roc_auc = None
    if y_prob is not None:
        try:
            # Handle 1D probabilities or 2D (take class 1)
            prob_scores = y_prob[:, 1] if y_prob.ndim == 2 else y_prob
            roc_auc = float(roc_auc_score(y_true, prob_scores))
        except Exception:
            roc_auc = None

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # Safe denominator calculations
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "training_time_seconds": round(training_time_sec, 3),
        "inference_time_ms": round(inference_time_ms, 3),
    }
