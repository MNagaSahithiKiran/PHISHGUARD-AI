"""
PhishGuard AI - Advanced Model 2: Support Vector Machine (Linear SVM with Calibrated Probabilities).
Trains linear SVM on training partition, evaluates on test partition.
"""

import time
import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import pandas as pd
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

from ml.feature_engineering.feature_pipeline import FeaturePipeline
from ml.evaluation.metrics import calculate_metrics
from ml.evaluation.confusion_matrix import plot_and_save_confusion_matrix

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_SAVE_PATH = MODELS_DIR / "svm.joblib"


def train_svm(pipeline: FeaturePipeline, train_df: pd.DataFrame, test_df: pd.DataFrame) -> dict:
    print("[*] Training Advanced Model: Support Vector Machine...")
    X_train = pipeline.transform(pipeline.extract_df(train_df["url"].tolist()))
    y_train = train_df["label"].values

    X_test = pipeline.transform(pipeline.extract_df(test_df["url"].tolist()))
    y_test = test_df["label"].values

    start_time = time.time()
    base_svm = LinearSVC(random_state=42, max_iter=2000, dual="auto")
    model = CalibratedClassifierCV(estimator=base_svm, cv=3)
    model.fit(X_train, y_train)
    training_time = time.time() - start_time

    inf_start = time.time()
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)
    inference_time_ms = ((time.time() - inf_start) / max(1, len(X_test))) * 1000

    metrics = calculate_metrics(
        y_true=y_test,
        y_pred=y_pred,
        y_prob=y_prob,
        training_time_sec=training_time,
        inference_time_ms=inference_time_ms,
    )
    metrics["model_name"] = "Support Vector Machine"

    joblib.dump(model, MODEL_SAVE_PATH)
    plot_and_save_confusion_matrix(metrics["confusion_matrix"], "Support Vector Machine")
    print(f"[+] SVM trained in {training_time:.2f}s | Test Accuracy: {metrics['accuracy']} | F1: {metrics['f1']}")
    return metrics, model
