from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator


class ScanCreate(BaseModel):
    url: str = Field(..., description="Target website URL to analyze", min_length=4, max_length=2048)


class ScanCreationResponse(BaseModel):
    scan_id: str
    url: str
    status: str
    message: str


class URLFeaturesSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    count_dots: int
    count_hyphens: int
    count_at: int
    count_question_marks: int
    count_equal_signs: int
    count_subdomains: int
    has_ip_address: bool
    has_punycode: bool
    has_shortener: bool
    has_port_in_url: bool
    entropy_score: Optional[float] = None


class DomainInformationSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    dnssec: Optional[bool] = None
    has_valid_ssl: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    nameservers: Optional[str] = None


class HTMLFeaturesSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    has_login_form: Optional[bool] = None
    external_form_action: Optional[bool] = None
    iframe_count: Optional[int] = None
    hidden_element_count: Optional[int] = None
    script_count: Optional[int] = None
    suspicious_keywords: Optional[str] = None


class VisualAnalysisSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    screenshot_path: Optional[str] = None
    dominant_colors: Optional[str] = None
    brand_similarity_score: Optional[float] = None
    detected_logos: Optional[str] = None


class ThreatIndicatorSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator_type: str
    severity: str
    rule_id: str
    description: str
    details: Optional[str] = None
    created_at: datetime


class ScanResultSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    verdict: str
    risk_score: Optional[float] = None
    confidence_score: Optional[float] = None  # Strictly None until real ML prediction executes
    summary: Optional[str] = None
    rule_match_count: int
    model_version: Optional[str] = None
    feature_version: Optional[str] = None
    url_feature_hash: Optional[str] = None
    dom_snapshot_hash: Optional[str] = None
    screenshot_hash: Optional[str] = None
    model_input_hash: Optional[str] = None
    prediction_hash: Optional[str] = None
    decision_policy_version: Optional[str] = None
    live_content_changed: Optional[bool] = False
    content_change_notice: Optional[str] = None
    reproducibility_data: Optional[str] = None
    completed_at: Optional[datetime] = None


class ScanEvidenceSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    provider: str
    evidence_type: str
    status: str
    value: Optional[str] = None
    confidence: Optional[float] = None
    source_url: Optional[str] = None
    observed_at: datetime
    evidence_hash: Optional[str] = None
    raw_reference: Optional[str] = None


class ScanDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    url: str
    original_url: Optional[str] = None
    normalized_url: str
    final_url: Optional[str] = None
    canonical_url: Optional[str] = None
    redirect_chain: Optional[str] = None
    domain: str

    @model_validator(mode="after")
    def populate_url_identities(self) -> "ScanDetailResponse":
        if not self.original_url:
            self.original_url = self.url
        if not self.final_url:
            self.final_url = self.normalized_url
        if not self.canonical_url:
            self.canonical_url = self.normalized_url
        return self

    status: str
    created_at: datetime
    updated_at: datetime
    scan_result: Optional[ScanResultSchema] = None
    url_features: Optional[URLFeaturesSchema] = None
    domain_info: Optional[DomainInformationSchema] = None
    html_features: Optional[HTMLFeaturesSchema] = None
    visual_analysis: Optional[VisualAnalysisSchema] = None
    threat_indicators: List[ThreatIndicatorSchema] = []
    evidence_ledger: List[ScanEvidenceSchema] = []


class ScanSummaryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    url: str
    domain: str
    status: str
    verdict: Optional[str] = "unrated"
    risk_score: Optional[float] = None
    created_at: datetime


class ScanListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[ScanSummaryItem]
