"""
PhishGuard AI - Baseline Model 1: Logistic Regression.
Trains L2-regularized Logistic Regression on the training partition,
evaluates on the untouched test partition.
"""

import time
import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression

from ml.feature_engineering.feature_pipeline import FeaturePipeline
from ml.evaluation.metrics import calculate_metrics
from ml.evaluation.confusion_matrix import plot_and_save_confusion_matrix

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "datasets" / "processed"
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_SAVE_PATH = MODELS_DIR / "logistic_regression.joblib"


def train_logistic_regression(pipeline: FeaturePipeline, train_df: pd.DataFrame, test_df: pd.DataFrame) -> dict:
    print("[*] Training Baseline Model: Logistic Regression...")
    X_train = pipeline.transform(pipeline.extract_df(train_df["url"].tolist()))
    y_train = train_df["label"].values

    X_test = pipeline.transform(pipeline.extract_df(test_df["url"].tolist()))
    y_test = test_df["label"].values

    # Train
    start_time = time.time()
    model = LogisticRegression(max_iter=1000, random_state=42, C=1.0)
    model.fit(X_train, y_train)
    training_time = time.time() - start_time

    # Inference benchmark
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
    metrics["model_name"] = "Logistic Regression"

    # Save artifact
    joblib.dump(model, MODEL_SAVE_PATH)
    plot_and_save_confusion_matrix(metrics["confusion_matrix"], "Logistic Regression")
    print(f"[+] Logistic Regression trained in {training_time:.2f}s | Test Accuracy: {metrics['accuracy']} | F1: {metrics['f1']}")
    return metrics, model


if __name__ == "__main__":
    train_df = pd.read_csv(PROCESSED_DIR / "train.csv")
    test_df = pd.read_csv(PROCESSED_DIR / "test.csv")
    pipeline = FeaturePipeline()
    X_train_raw = pipeline.extract_df(train_df["url"].tolist())
    pipeline.fit_transform(X_train_raw)
    pipeline.save()
    train_logistic_regression(pipeline, train_df, test_df)
