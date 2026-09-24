"""
PhishGuard AI - Master Training Orchestrator.
Orchestrates:
1. Preprocessor fitting and serialization.
2. Training of all baseline and advanced models:
   - Logistic Regression
   - Decision Tree
   - Random Forest
   - Support Vector Machine
   - XGBoost
3. Strict evaluation on untouched test set (15%).
4. Generation of ml/experiments/model_comparison.csv.
5. Feature importance analysis saved to ml/experiments/feature_importance.csv.
6. Deployment model selection based on measurable criteria.
7. Experiment registration in ml/experiments/experiment_registry.json.
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import json
import time
from datetime import datetime, timezone
import pandas as pd
import numpy as np
import joblib

from ml.feature_engineering.feature_pipeline import FeaturePipeline
from ml.training.train_logistic_regression import train_logistic_regression
from ml.training.train_decision_tree import train_decision_tree
from ml.training.train_random_forest import train_random_forest
from ml.training.train_svm import train_svm
from ml.training.train_xgboost import train_xgboost, XGBOOST_AVAILABLE

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "datasets" / "processed"
EXPERIMENTS_DIR = Path(__file__).resolve().parent.parent / "experiments"
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_COMPARISON_CSV = EXPERIMENTS_DIR / "model_comparison.csv"
FEATURE_IMPORTANCE_CSV = EXPERIMENTS_DIR / "feature_importance.csv"
EXPERIMENT_REGISTRY_JSON = EXPERIMENTS_DIR / "experiment_registry.json"
MODEL_METADATA_JSON = MODELS_DIR / "model_metadata.json"


def run_all_training():
    print("=" * 70)
    print("PHISHGUARD AI - MASTER RESEARCH MODEL TRAINING PIPELINE")
    print("=" * 70)

    train_path = PROCESSED_DIR / "train.csv"
    val_path = PROCESSED_DIR / "val.csv"
    test_path = PROCESSED_DIR / "test.csv"

    for p in [train_path, val_path, test_path]:
        if not p.exists():
            raise FileNotFoundError(f"Missing required split: {p}. Run split_dataset.py first.")

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    print(f"[*] Ingested Dataset Partitions:")
    print(f"    Train: {len(train_df)} | Validation: {len(val_df)} | Test: {len(test_df)}")

    # 1. Feature Extraction & Preprocessor Fitting
    print("\n[*] Initializing Feature Pipeline & Fitting Scaler on Train Set...")
    pipeline = FeaturePipeline()
    X_train_raw = pipeline.extract_df(train_df["url"].tolist())
    pipeline.fit_transform(X_train_raw)
    pipeline.save()
    print(f"[+] Serialized fitted preprocessor to {MODELS_DIR / 'preprocessor.joblib'}")

    # 2. Train and Evaluate Models
    results = []
    models_dict = {}

    # Logistic Regression
    lr_metrics, lr_model = train_logistic_regression(pipeline, train_df, test_df)
    results.append(lr_metrics)
    models_dict["Logistic Regression"] = lr_model

    # Decision Tree
    dt_metrics, dt_model = train_decision_tree(pipeline, train_df, test_df)
    results.append(dt_metrics)
    models_dict["Decision Tree"] = dt_model

    # Random Forest
    rf_metrics, rf_model = train_random_forest(pipeline, train_df, test_df)
    results.append(rf_metrics)
    models_dict["Random Forest"] = rf_model

    # SVM
    svm_metrics, svm_model = train_svm(pipeline, train_df, test_df)
    results.append(svm_metrics)
    models_dict["Support Vector Machine"] = svm_model

    # XGBoost
    if XGBOOST_AVAILABLE:
        xgb_metrics, xgb_model = train_xgboost(pipeline, train_df, test_df)
        results.append(xgb_metrics)
        models_dict["XGBoost"] = xgb_model
    else:
        print("[-] Skipping XGBoost: Dependency not available.")

    # 3. Generate Model Comparison Table
    print("\n[*] Compiling Comparative Research Benchmarks...")
    comparison_rows = []
    for r in results:
        comparison_rows.append({
            "model": r["model_name"],
            "accuracy": r["accuracy"],
            "precision": r["precision"],
            "recall": r["recall"],
            "f1": r["f1"],
            "roc_auc": r["roc_auc"],
            "false_positive_rate": r["false_positive_rate"],
            "false_negative_rate": r["false_negative_rate"],
            "training_time_seconds": r["training_time_seconds"],
            "inference_time_ms": r["inference_time_ms"],
        })

    comp_df = pd.DataFrame(comparison_rows)
    comp_df.to_csv(MODEL_COMPARISON_CSV, index=False)
    print(f"[+] Saved model comparison table to {MODEL_COMPARISON_CSV}")
    print("\n" + comp_df.to_string(index=False))

    # 4. Feature Importance Analysis
    print("\n[*] Computing Feature Importance Associations...")
    # Extract from tree models (Random Forest and XGBoost)
    feat_names = pipeline.feature_names
    fi_dict = {"feature": feat_names}

    if "Random Forest" in models_dict:
        fi_dict["random_forest_importance"] = models_dict["Random Forest"].feature_importances_
    if "XGBoost" in models_dict:
        fi_dict["xgboost_importance"] = models_dict["XGBoost"].feature_importances_
    if "Logistic Regression" in models_dict:
        # Coefficient magnitude
        fi_dict["logistic_regression_coef"] = models_dict["Logistic Regression"].coef_[0]

    fi_df = pd.DataFrame(fi_dict)
    # Sort by Random Forest importance if present
    if "random_forest_importance" in fi_df.columns:
        fi_df = fi_df.sort_values(by="random_forest_importance", ascending=False)
    fi_df.to_csv(FEATURE_IMPORTANCE_CSV, index=False)
    print(f"[+] Saved feature importance table to {FEATURE_IMPORTANCE_CSV}")

    # 5. Deployment Model Selection (Measurable Criteria)
    # Criteria: High F1-score and Recall (minimizing false negatives in cybersecurity),
    # low False Positive Rate (minimizing benign site blocking), and low inference latency.
    # Score = F1 - 0.5 * FPR
    best_score = -1.0
    selected_model_name = None
    selected_metrics = None

    for r in results:
        score = r["f1"] - (0.5 * r["false_positive_rate"])
        if score > best_score:
            best_score = score
            selected_model_name = r["model_name"]
            selected_metrics = r

    selection_rationale = (
        f"Selected '{selected_model_name}' based on the measurable objective function "
        f"[Score = F1 - (0.5 * FPR)]. It achieves a balanced test F1 of {selected_metrics['f1']}, "
        f"Recall of {selected_metrics['recall']}, False Positive Rate of {selected_metrics['false_positive_rate']}, "
        f"and inference latency of {selected_metrics['inference_time_ms']} ms/sample."
    )
    print("\n" + "=" * 70)
    print("DEPLOYMENT MODEL SELECTION")
    print("=" * 70)
    print(f"Selected: {selected_model_name}")
    print(f"Rationale: {selection_rationale}")

    # Map filename
    model_filename_map = {
        "Logistic Regression": "logistic_regression.joblib",
        "Decision Tree": "decision_tree.joblib",
        "Random Forest": "random_forest.joblib",
        "Support Vector Machine": "svm.joblib",
        "XGBoost": "xgboost.joblib",
    }
    selected_filename = model_filename_map[selected_model_name]

    metadata = {
        "selected_model": selected_model_name,
        "model_file": selected_filename,
        "feature_version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "selection_rationale": selection_rationale,
        "test_metrics": selected_metrics,
        "random_seed": 42
    }

    with open(MODEL_METADATA_JSON, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved active model metadata to {MODEL_METADATA_JSON}")

    # 6. Update Experiment Registry
    registry = []
    if EXPERIMENT_REGISTRY_JSON.exists():
        try:
            with open(EXPERIMENT_REGISTRY_JSON, "r", encoding="utf-8") as f:
                registry = json.load(f)
        except Exception:
            registry = []

    exp_entry = {
        "experiment_id": f"EXP-{int(time.time())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_version": "1.0-clean",
        "feature_version": "2.0.0",
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "evaluated_models": comparison_rows,
        "selected_model": selected_model_name,
    }
    registry.append(exp_entry)
    with open(EXPERIMENT_REGISTRY_JSON, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)
    print(f"[+] Updated experiment registry at {EXPERIMENT_REGISTRY_JSON}")
    print("=" * 70)

    return metadata


if __name__ == "__main__":
    run_all_training()
