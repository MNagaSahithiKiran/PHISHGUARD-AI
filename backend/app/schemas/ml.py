from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class MLPredictRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048, description="Target website URL to predict")


class SHAPContribution(BaseModel):
    feature: str
    value: float
    contribution: float
    direction: str


class MLPredictResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    prediction: str  # "legitimate" or "phishing"
    label: int  # 0 or 1
    probability: float  # Real class 1 probability from model
    confidence: float  # Absolute confidence percentage (e.g. 98.4%)
    model_version: str
    feature_version: str
    inference_time_ms: float
    top_explanations: Optional[List[SHAPContribution]] = None


class ModelBenchmarkItem(BaseModel):
    model: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: Optional[float] = None
    false_positive_rate: float
    false_negative_rate: float
    training_time_seconds: float
    inference_time_ms: float


class MLModelStatusResponse(BaseModel):
    is_trained: bool
    selected_model: str
    model_file: str
    feature_version: str
    selection_rationale: str
    benchmarks: List[ModelBenchmarkItem]
