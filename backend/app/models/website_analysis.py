import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Text, Float, Integer, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class WebsiteAnalysisRecord(Base):
    __tablename__ = "website_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    
    initial_url: Mapped[str] = mapped_column(Text, nullable=False)
    final_url: Mapped[str] = mapped_column(Text, nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    content_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    # HTML & DOM
    title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    language: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    charset: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    dom_depth: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_tags: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    text_ratio: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    hidden_elements_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Forms
    total_forms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    login_forms_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    has_password_field: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    external_form_action_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Links
    total_links: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    internal_links: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    external_links: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    external_link_ratio: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    null_link_ratio: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Scripts
    total_scripts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    inline_scripts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    external_scripts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Iframes
    total_iframes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    hidden_iframes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cross_origin_iframes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Resources
    total_resources: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    external_resource_ratio: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    mixed_content_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Headers
    hsts_present: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    csp_present: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    x_frame_options: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    x_content_type_options: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    security_header_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Redirects & Visual
    redirect_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    analysis_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    redirect_hops: Mapped[List["RedirectHopRecord"]] = relationship(
        "RedirectHopRecord",
        back_populates="website_analysis",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    evidence_items: Mapped[List["EvidenceRecord"]] = relationship(
        "EvidenceRecord",
        back_populates="website_analysis",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class RedirectHopRecord(Base):
    __tablename__ = "website_redirect_hops"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    website_analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("website_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    hop_number: Mapped[int] = mapped_column(Integer, nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)

    website_analysis: Mapped["WebsiteAnalysisRecord"] = relationship("WebsiteAnalysisRecord", back_populates="redirect_hops")


class EvidenceRecord(Base):
    __tablename__ = "website_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    website_analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("website_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # info, low, medium, high, critical
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    website_analysis: Mapped["WebsiteAnalysisRecord"] = relationship("WebsiteAnalysisRecord", back_populates="evidence_items")
