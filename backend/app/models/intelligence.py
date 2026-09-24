"""
PhishGuard AI - Multi-Modal Intelligence Database Models
Stores persistent records for:
- FusionAnalysisRecord: Final multimodal classification, calibrated probability, risk score, and policy version.
- ModelExecutionRecord: Telemetry and probabilities per individual modality model.
- ExplanationRecord: Factual explainability findings, key signals, and feature attributions.
CRITICAL DEFENSE RULE: Never stores sensitive user credentials.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Text, Float, Integer, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class FusionAnalysisRecord(Base):
    __tablename__ = "fusion_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)

    url: Mapped[str] = mapped_column(Text, nullable=False)
    classification: Mapped[str] = mapped_column(String(50), nullable=False)  # "phishing", "suspicious", "legitimate"
    raw_probability: Mapped[float] = mapped_column(Float, nullable=False)
    calibrated_probability: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 to 100.0
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)  # "low", "medium", "high"

    modalities_used: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    missing_modalities: Mapped[str] = mapped_column(Text, default="[]", nullable=False)

    decision_policy_version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    calibration_version: Mapped[str] = mapped_column(String(50), default="platt_v1", nullable=False)
    total_latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Reproducibility Fingerprints
    url_feature_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dom_snapshot_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    screenshot_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    model_input_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prediction_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    live_content_changed: Mapped[Optional[bool]] = mapped_column(Boolean, default=False, nullable=True)
    content_change_notice: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reproducibility_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    model_executions: Mapped[List["ModelExecutionRecord"]] = relationship(
        "ModelExecutionRecord",
        back_populates="fusion_analysis",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    explanation: Mapped[Optional["ExplanationRecord"]] = relationship(
        "ExplanationRecord",
        back_populates="fusion_analysis",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class ModelExecutionRecord(Base):
    __tablename__ = "model_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    fusion_analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("fusion_analyses.id", ondelete="CASCADE"), nullable=False, index=True)

    modality: Mapped[str] = mapped_column(String(50), nullable=False)  # "url", "website", "visual", "fusion"
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    prediction: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="available", nullable=False)

    fusion_analysis: Mapped["FusionAnalysisRecord"] = relationship(
        "FusionAnalysisRecord", back_populates="model_executions"
    )


class ExplanationRecord(Base):
    __tablename__ = "explanations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    fusion_analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("fusion_analyses.id", ondelete="CASCADE"), nullable=False, index=True)

    summary: Mapped[str] = mapped_column(Text, nullable=False)
    key_signals: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON array
    observed_evidence: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON array
    feature_attributions: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON array

    fusion_analysis: Mapped["FusionAnalysisRecord"] = relationship(
        "FusionAnalysisRecord", back_populates="explanation"
    )
