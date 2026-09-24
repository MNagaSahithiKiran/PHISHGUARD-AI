"""
PhishGuard AI - Vision Model Evaluation Metrics
Computes full performance metrics on held-out test sets:
- Accuracy, Precision, Recall, F1-Score, ROC-AUC
- False Positive Rate (FPR), False Negative Rate (FNR)
- Latency (ms), Parameter count, Model size (MB)
"""

import time
from typing import Dict, Any, List, Tuple
from pathlib import Path
import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


def calculate_vision_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_probs: List[float],
) -> Dict[str, Any]:
    """
    Computes rigorous classification metrics from binary targets and model predictions.
    0: Legitimate, 1: Phishing
    """
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)
    y_probs_arr = np.array(y_probs)

    acc = float(accuracy_score(y_true_arr, y_pred_arr))
    prec = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
    rec = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))

    try:
        if len(np.unique(y_true_arr)) > 1:
            auc = float(roc_auc_score(y_true_arr, y_probs_arr))
        else:
            auc = 0.5
    except Exception:
        auc = 0.5

    tn, fp, fn, tp = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, (fp + tn)))
    fnr = float(fn / max(1, (fn + tp)))

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "total_test_samples": len(y_true),
    }


def measure_model_efficiency(
    model: torch.nn.Module,
    input_shape: Tuple[int, int, int, int] = (1, 3, 224, 224),
    num_runs: int = 20,
    device: str = "cpu",
) -> Dict[str, Any]:
    """
    Measures parameter counts, model memory footprint, and inference latency.
    """
    model.eval()
    model.to(device)

    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

    # Estimate size in MB (float32 = 4 bytes)
    param_size_mb = total_params * 4 / (1024 * 1024)

    # Measure latency
    dummy_input = torch.randn(*input_shape, device=device)
    # Warmup
    with torch.no_grad():
        for _ in range(5):
            _ = model(dummy_input)

    latencies = []
    with torch.no_grad():
        for _ in range(num_runs):
            t0 = time.perf_counter()
            _ = model(dummy_input)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)  # ms

    avg_latency = float(np.mean(latencies))
    std_latency = float(np.std(latencies))

    return {
        "total_parameters": int(total_params),
        "trainable_parameters": int(trainable_params),
        "model_size_mb": round(param_size_mb, 2),
        "inference_latency_ms": round(avg_latency, 2),
        "latency_std_ms": round(std_latency, 2),
    }
