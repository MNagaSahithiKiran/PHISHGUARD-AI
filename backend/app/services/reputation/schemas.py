from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ReputationStatus(str, Enum):
    CONFIRMED_RESULT = "CONFIRMED_RESULT"
    NO_RESULT = "NO_RESULT"
    SAFE = "SAFE"
    THREAT_MATCH = "THREAT_MATCH"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"


class ProviderResult(BaseModel):
    provider_name: str
    status: ReputationStatus
    summary: str
    is_threat: Optional[bool] = None
    confidence: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    query: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: float = 0.0
    raw_response: Optional[Dict[str, Any]] = None


class ReputationEvidenceItem(BaseModel):
    provider: str
    evidence_type: str
    status: str
    value: Optional[str] = None
    confidence: Optional[float] = None
    source_url: Optional[str] = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_hash: str
    raw_reference: Optional[str] = None


class ExternalReputationSummary(BaseModel):
    overall_status: str  # "CLEAN", "THREAT_DETECTED", "NO_REPUTATION_DATA", "PARTIAL"
    threat_matches: int = 0
    providers_queried: int = 0
    providers_configured: int = 0
    evidence_ledger: List[ReputationEvidenceItem] = Field(default_factory=list)
    provider_results: Dict[str, ProviderResult] = Field(default_factory=dict)
