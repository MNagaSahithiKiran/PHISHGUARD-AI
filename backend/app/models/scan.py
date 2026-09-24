import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Text, Float, Integer, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    final_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    redirect_chain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="queued", index=True, nullable=False)  # queued, processing, completed, failed
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    scan_result: Mapped[Optional["ScanResult"]] = relationship(
        "ScanResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    url_features: Mapped[Optional["URLFeatures"]] = relationship(
        "URLFeatures",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    domain_info: Mapped[Optional["DomainInformation"]] = relationship(
        "DomainInformation",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    html_features: Mapped[Optional["HTMLFeatures"]] = relationship(
        "HTMLFeatures",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    visual_analysis: Mapped[Optional["VisualAnalysis"]] = relationship(
        "VisualAnalysis",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    threat_indicators: Mapped[List["ThreatIndicator"]] = relationship(
        "ThreatIndicator",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    evidence_ledger: Mapped[List["ScanEvidence"]] = relationship(
        "ScanEvidence",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin"
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    verdict: Mapped[str] = mapped_column(String(50), default="unrated", index=True, nullable=False)  # legitimate, suspicious, phishing, unrated
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0 to 100
    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # None until ML prediction is genuinely run
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Reproducibility & Fingerprinting Metadata
    model_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    feature_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    preprocessing_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    decision_policy_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    url_feature_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dom_snapshot_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    screenshot_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    model_input_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prediction_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    live_content_changed: Mapped[Optional[bool]] = mapped_column(Boolean, default=False, nullable=True)
    content_change_notice: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reproducibility_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="scan_result")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # lexical, domain, ssl, network, heuristic, ml
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)  # info, low, medium, high, critical
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="threat_indicators")


class ScanEvidence(Base):
    __tablename__ = "scan_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    raw_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="evidence_ledger")
