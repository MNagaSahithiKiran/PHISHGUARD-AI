"""
PhishGuard AI - Comprehensive Vision Model Evaluation Harness
Evaluates both trained computer-vision models on the untouched Holdout Test Set.
Computes complete metrics, latency, parameter counts, generates confusion matrices,
ROC curves, and Grad-CAM explainability heatmaps.
Saves metrics.json and model_comparison.csv.
"""

import os
import sys
import json
import csv
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import torch
from torch.utils.data import DataLoader

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.vision.models.baseline_cnn import PhishVisionCNN
from ml.vision.models.transfer_learning import PhishMobileNetV2
from ml.vision.training.dataset import WebpageScreenshotDataset
from ml.vision.preprocessing.image_preprocessor import ImagePreprocessor
from ml.vision.evaluation.metrics import calculate_vision_metrics, measure_model_efficiency
from ml.vision.evaluation.confusion_matrix import generate_and_save_confusion_matrix
from ml.vision.evaluation.roc_curve import generate_and_save_roc_curve
from ml.vision.evaluation.explainability import GradCAM

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "models_artifacts"
EXPERIMENTS_DIR = Path(__file__).resolve().parent.parent / "experiments"
EXPLANATIONS_DIR = EXPERIMENTS_DIR / "explanations"
TEST_DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "processed" / "test"


def evaluate_single_model(
    model: torch.nn.Module,
    model_name: str,
    test_loader: DataLoader,
    device: str = "cpu",
) -> Dict[str, Any]:
    model.eval()
    model.to(device)

    all_preds = []
    all_targets = []
    all_probs = []
    sample_paths = []

    with torch.no_grad():
        for tensors, labels, paths in test_loader:
            tensors = tensors.to(device)
            logits = model(tensors)
            probs = torch.sigmoid(logits).cpu().numpy().flatten().tolist()
            preds = [1 if p >= 0.5 else 0 for p in probs]
            targets = labels.numpy().flatten().astype(int).tolist()

            all_probs.extend(probs)
            all_preds.extend(preds)
            all_targets.extend(targets)
            sample_paths.extend(paths)

    # Calculate classification metrics
    perf_metrics = calculate_vision_metrics(all_targets, all_preds, all_probs)

    # Efficiency measurements
    efficiency = measure_model_efficiency(model, device=device)

    # Generate Confusion Matrix
    cm_info = generate_and_save_confusion_matrix(
        y_true=all_targets,
        y_pred=all_preds,
        output_dir=EXPERIMENTS_DIR,
        model_name=model_name,
    )

    # Generate ROC Curve
    roc_info = generate_and_save_roc_curve(
        y_true=all_targets,
        y_probs=all_probs,
        output_dir=EXPERIMENTS_DIR,
        model_name=model_name,
    )

    # Consolidate results
    result = {
        "model_name": model_name,
        **perf_metrics,
        **efficiency,
        "confusion_matrix_plot": cm_info["plot_path"],
        "roc_curve_plot": roc_info["plot_path"],
        "sample_paths": sample_paths,
        "y_true": all_targets,
        "y_pred": all_preds,
        "y_probs": all_probs,
    }
    return result


def run_full_evaluation():
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
    EXPLANATIONS_DIR.mkdir(parents=True, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"

    print("=" * 60)
    print("PHISHGUARD AI — PHASE 4 VISION MODEL EVALUATION HARNESS")
    print("=" * 60)
    print(f"Evaluation Device: {device}")
    print(f"Holdout Test Path: {TEST_DATASET_DIR}")

    # 1. Prepare Test DataLoader
    preprocessor = ImagePreprocessor()
    test_dataset = WebpageScreenshotDataset(
        split_dir=TEST_DATASET_DIR,
        split_name="test",
        preprocessor=preprocessor,
        augmentor=None,  # Strictly NO augmentation for test evaluation
    )
    print(f"Total Untouched Test Samples: {len(test_dataset)}")
    test_loader = DataLoader(test_dataset, batch_size=4, shuffle=False)

    results = []

    # 2. Evaluate Baseline CNN
    baseline_weights = ARTIFACTS_DIR / "baseline_cnn_best.pt"
    if baseline_weights.exists():
        print("\nEvaluating Baseline CNN (PhishVisionCNN)...")
        baseline_model = PhishVisionCNN(num_classes=1)
        checkpoint = torch.load(baseline_weights, map_location=device, weights_only=True)
        baseline_model.load_state_dict(checkpoint["model_state_dict"])
        res_baseline = evaluate_single_model(baseline_model, "Baseline_CNN", test_loader, device=device)
        results.append(res_baseline)
        print(f"  Accuracy: {res_baseline['accuracy']:.4f} | F1: {res_baseline['f1']:.4f} | ROC-AUC: {res_baseline['roc_auc']:.4f} | Latency: {res_baseline['inference_latency_ms']:.2f}ms")
    else:
        print(f"Warning: Baseline checkpoint not found at {baseline_weights}")

    # 3. Evaluate Transfer Learning (MobileNetV2)
    transfer_weights = ARTIFACTS_DIR / "transfer_mobilenet_best.pt"
    if transfer_weights.exists():
        print("\nEvaluating Transfer Learning Model (PhishMobileNetV2)...")
        transfer_model = PhishMobileNetV2(pretrained=False, num_classes=1)
        checkpoint = torch.load(transfer_weights, map_location=device, weights_only=True)
        transfer_model.load_state_dict(checkpoint["model_state_dict"])
        res_transfer = evaluate_single_model(transfer_model, "MobileNetV2_Transfer", test_loader, device=device)
        results.append(res_transfer)
        print(f"  Accuracy: {res_transfer['accuracy']:.4f} | F1: {res_transfer['f1']:.4f} | ROC-AUC: {res_transfer['roc_auc']:.4f} | Latency: {res_transfer['inference_latency_ms']:.2f}ms")

        # 4. Generate Grad-CAM Visual Explainability Heatmaps
        print("\nGenerating Grad-CAM Visual Explainability heatmaps...")
        try:
            gradcam = GradCAM(transfer_model, transfer_model.get_target_conv_layer())
            # Select test samples (1 legitimate, 1 phishing)
            sample_count = 0
            for path_str, true_label, pred_label in zip(res_transfer["sample_paths"], res_transfer["y_true"], res_transfer["y_pred"]):
                sample_p = Path(path_str)
                out_p = EXPLANATIONS_DIR / f"gradcam_{sample_p.stem}.png"
                gradcam.explain_and_save(sample_p, out_p, preprocessor=preprocessor, device=device)
                sample_count += 1
                if sample_count >= 4:
                    break
            gradcam.remove_hooks()
            print(f"  Grad-CAM heatmaps saved to: {EXPLANATIONS_DIR}")
        except Exception as cam_err:
            print(f"  Grad-CAM generation notice: {cam_err}")

    # 5. Save model comparison CSV
    csv_path = EXPERIMENTS_DIR / "model_comparison.csv"
    csv_headers = [
        "model", "accuracy", "precision", "recall", "f1", "roc_auc",
        "false_positive_rate", "false_negative_rate", "parameters",
        "inference_ms", "model_size_mb"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(csv_headers)
        for r in results:
            writer.writerow([
                r["model_name"],
                r["accuracy"],
                r["precision"],
                r["recall"],
                r["f1"],
                r["roc_auc"],
                r["false_positive_rate"],
                r["false_negative_rate"],
                r["total_parameters"],
                r["inference_latency_ms"],
                r["model_size_mb"],
            ])

    # 6. Save JSON metrics
    json_path = EXPERIMENTS_DIR / "metrics.json"
    clean_results = []
    for r in results:
        cr = {k: v for k, v in r.items() if k not in ("sample_paths", "y_true", "y_pred", "y_probs")}
        clean_results.append(cr)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(clean_results, f, indent=2)

    print(f"\n[Artifact] Model comparison saved to: {csv_path}")
    print(f"[Artifact] Detailed metrics saved to: {json_path}")
    return clean_results


if __name__ == "__main__":
    run_full_evaluation()
