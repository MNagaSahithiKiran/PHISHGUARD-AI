"""
PhishGuard AI - Multi-Modal Intelligence Schemas
Pydantic v2 schemas for final multi-modal assessment requests and responses.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class IntelligenceAnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target webpage URL to evaluate", min_length=4, max_length=2048)
    include_visual: bool = Field(True, description="Whether to execute headless browser screenshot and vision analysis")
    scan_id: Optional[str] = Field(None, description="Optional existing Scan ID to attach this intelligence result to")


class ModalityModelOutput(BaseModel):
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    prediction: Optional[str] = None
    probability: Optional[float] = None
    confidence: Optional[float] = None
    latency_ms: Optional[float] = None
    status: str = "available"  # "available", "failed", "not_available"
    error: Optional[str] = None
    message: Optional[str] = None
    screenshot_url: Optional[str] = None
    heatmap_url: Optional[str] = None


class FusionModelOutput(BaseModel):
    model_name: str
    model_version: str
    routing_mode: str
    raw_fusion_probability: float
    calibrated_probability: float
    calibration_method: str
    decision_policy_version: str
    status: str = "completed"


class IntelligenceEvidenceItem(BaseModel):
    category: str
    severity: str
    title: str
    description: str
    source: str


class IntelligenceExplanationSchema(BaseModel):
    summary: str
    classification: str
    calibrated_phishing_probability: float
    key_model_signals: List[str] = []
    observed_factual_evidence: List[str] = []
    modality_status: Dict[str, Any] = {}
    feature_attributions: List[Dict[str, Any]] = []


class PerformanceMetrics(BaseModel):
    total_analysis_ms: float = 0.0


class IntelligenceAnalyzeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: Optional[str] = None
    url: str
    original_url: Optional[str] = None
    normalized_url: Optional[str] = None
    final_url: Optional[str] = None
    canonical_url: Optional[str] = None
    redirect_chain: List[Dict[str, Any]] = []
    domain: Optional[str] = None
    status: str  # "completed", "queued", "failed", "blocked"
    classification: str  # "phishing", "suspicious", "legitimate"
    phishing_probability: float
    risk_score: float
    risk_level: str  # "low", "medium", "high"
    modalities_used: List[str] = []
    missing_modalities: List[str] = []
    models: Dict[str, Any] = {}
    evidence: List[IntelligenceEvidenceItem] = []
    explanation: IntelligenceExplanationSchema
    performance: PerformanceMetrics
    screenshot_url: Optional[str] = None
    heatmap_url: Optional[str] = None
    reproducibility: Optional[Dict[str, Any]] = None
    url_feature_hash: Optional[str] = None
    dom_snapshot_hash: Optional[str] = None
    screenshot_hash: Optional[str] = None
    model_input_hash: Optional[str] = None
    prediction_hash: Optional[str] = None
    live_content_changed: bool = False
    content_change_notice: Optional[str] = None
    reputation: Optional[Dict[str, Any]] = None
    reason_codes: List[str] = []
    reason_details: List[Dict[str, Any]] = []
    decision_policy_version: Optional[str] = "risk_policy_v1"
