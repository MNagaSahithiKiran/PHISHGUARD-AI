"""
PhishGuard AI - Visual Analysis Schemas
Pydantic schemas for visual analysis requests and responses.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class VisualAnalysisRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Existing scan ID to analyze")
    url: Optional[str] = Field(None, description="Target URL if running standalone screenshot analysis")


class VisualEvidenceSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_type: str = "visual_model_signal"
    severity: str = "medium"  # "info", "low", "medium", "high", "critical"
    title: str
    description: str
    source: str = "visual_model"


class VisualFeaturesSchema(BaseModel):
    image_width: int = 1280
    image_height: int = 800
    aspect_ratio: float = 1.6
    mean_luminance: float = 0.5
    visual_contrast: float = 0.5
    whitespace_ratio: float = 0.5
    edge_density: float = 0.05
    colorfulness: float = 0.2
    dominant_colors: List[str] = []
    has_centered_card: bool = False


class VisualAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: str  # "completed", "queued", "not_available", "failed"
    scan_id: Optional[str] = None
    prediction: Optional[str] = None  # "phishing", "legitimate"
    label: Optional[int] = None  # 0 or 1
    phishing_probability: Optional[float] = None
    confidence_score: Optional[float] = None
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    preprocessing_version: Optional[str] = None
    inference_latency_ms: Optional[float] = None
    screenshot_url: Optional[str] = None
    heatmap_url: Optional[str] = None
    visual_features: Optional[VisualFeaturesSchema] = None
    evidence: List[VisualEvidenceSchema] = []
    message: Optional[str] = None
