import csv
from pathlib import Path
from typing import List
from fastapi import APIRouter, HTTPException, status
from app.schemas.ml import MLPredictRequest, MLPredictResponse, MLModelStatusResponse, ModelBenchmarkItem
from app.ml.prediction_service import PredictionService
from app.ml.model_loader import model_loader, REPO_ROOT

router = APIRouter(prefix="/ml", tags=["Machine Learning"])

MODEL_COMPARISON_CSV = REPO_ROOT / "ml" / "experiments" / "model_comparison.csv"


@router.post("/predict", response_model=MLPredictResponse)
async def predict_phishing(payload: MLPredictRequest):
    """
    Submits a target URL to the trained machine learning ensemble.
    Extracts identical 34-dimensional feature vector, computes genuine
    classification probability, and generates SHAP local feature attributions.
    """
    return PredictionService.predict_url(payload.url)


@router.get("/models", response_model=MLModelStatusResponse)
async def get_model_status():
    """
    Retrieves the training status, active deployment model metadata,
    and empirical benchmark comparison across all evaluated models.
    """
    if not model_loader.is_loaded:
        model_loader.reload()

    if not model_loader.is_loaded or model_loader.metadata is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Machine learning model weights not loaded or training pipeline has not been executed."
        )

    benchmarks: List[ModelBenchmarkItem] = []
    if MODEL_COMPARISON_CSV.exists():
        with open(MODEL_COMPARISON_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                benchmarks.append(ModelBenchmarkItem(
                    model=row["model"],
                    accuracy=float(row["accuracy"]),
                    precision=float(row["precision"]),
                    recall=float(row["recall"]),
                    f1=float(row["f1"]),
                    roc_auc=float(row["roc_auc"]) if row.get("roc_auc") and row["roc_auc"] != "" else None,
                    false_positive_rate=float(row["false_positive_rate"]),
                    false_negative_rate=float(row["false_negative_rate"]),
                    training_time_seconds=float(row["training_time_seconds"]),
                    inference_time_ms=float(row["inference_time_ms"]),
                ))

    return MLModelStatusResponse(
        is_trained=model_loader.is_loaded,
        selected_model=model_loader.metadata.get("selected_model", "None"),
        model_file=model_loader.metadata.get("model_file", "None"),
        feature_version=model_loader.metadata.get("feature_version", "2.0.0"),
        selection_rationale=model_loader.metadata.get("selection_rationale", ""),
        benchmarks=benchmarks
    )
