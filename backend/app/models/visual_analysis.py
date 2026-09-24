"""
PhishGuard AI - Visual Analysis Database Models
Stores screenshots, computer-vision predictions, visual telemetry, and visual evidence.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Text, Float, Integer, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class ScreenshotRecord(Base):
    __tablename__ = "screenshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    
    url: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    width: Mapped[int] = mapped_column(Integer, default=1280, nullable=False)
    height: Mapped[int] = mapped_column(Integer, default=800, nullable=False)
    format_name: Mapped[str] = mapped_column(String(20), default="PNG", nullable=False)
    md5_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    capture_duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    visual_analyses: Mapped[List["VisualAnalysisRecord"]] = relationship(
        "VisualAnalysisRecord",
        back_populates="screenshot",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class VisualAnalysisRecord(Base):
    __tablename__ = "visual_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    screenshot_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("screenshots.id", ondelete="SET NULL"), nullable=True, index=True)

    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    preprocessing_version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    prediction: Mapped[str] = mapped_column(String(50), nullable=False)  # "phishing", "legitimate"
    label: Mapped[int] = mapped_column(Integer, nullable=False)  # 0 or 1
    phishing_probability: Mapped[float] = mapped_column(Float, nullable=False)  # [0.0, 1.0]
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    inference_latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Visual features telemetry
    has_centered_card: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    edge_density: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    whitespace_ratio: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    dominant_colors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    heatmap_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    screenshot: Mapped[Optional["ScreenshotRecord"]] = relationship(
        "ScreenshotRecord", back_populates="visual_analyses"
    )
    visual_evidence: Mapped[List["VisualEvidenceRecord"]] = relationship(
        "VisualEvidenceRecord",
        back_populates="visual_analysis",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class VisualEvidenceRecord(Base):
    __tablename__ = "visual_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    visual_analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("visual_analyses.id", ondelete="CASCADE"), nullable=False, index=True)

    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "visual_model_signal", "layout_anomaly", etc.
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # "info", "low", "medium", "high", "critical"
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), default="visual_model", nullable=False)

    visual_analysis: Mapped["VisualAnalysisRecord"] = relationship(
        "VisualAnalysisRecord", back_populates="visual_evidence"
    )
