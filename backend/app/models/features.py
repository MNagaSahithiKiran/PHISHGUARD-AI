import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, Float, Boolean, Text, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class URLFeatures(Base):
    __tablename__ = "url_features"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)

    url_length: Mapped[int] = mapped_column(Integer, default=0)
    hostname_length: Mapped[int] = mapped_column(Integer, default=0)
    path_length: Mapped[int] = mapped_column(Integer, default=0)
    query_length: Mapped[int] = mapped_column(Integer, default=0)
    
    count_dots: Mapped[int] = mapped_column(Integer, default=0)
    count_hyphens: Mapped[int] = mapped_column(Integer, default=0)
    count_at: Mapped[int] = mapped_column(Integer, default=0)
    count_question_marks: Mapped[int] = mapped_column(Integer, default=0)
    count_equal_signs: Mapped[int] = mapped_column(Integer, default=0)
    count_subdomains: Mapped[int] = mapped_column(Integer, default=0)
    
    has_ip_address: Mapped[bool] = mapped_column(Boolean, default=False)
    has_punycode: Mapped[bool] = mapped_column(Boolean, default=False)
    has_shortener: Mapped[bool] = mapped_column(Boolean, default=False)
    has_port_in_url: Mapped[bool] = mapped_column(Boolean, default=False)
    
    entropy_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="url_features")


class DomainInformation(Base):
    __tablename__ = "domain_information"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)

    registrar: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    creation_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    domain_age_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    dnssec: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    has_valid_ssl: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    ssl_issuer: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    nameservers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="domain_info")


class HTMLFeatures(Base):
    __tablename__ = "html_features"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)

    has_login_form: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    external_form_action: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    iframe_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    hidden_element_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    script_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    suspicious_keywords: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="html_features")


class VisualAnalysis(Base):
    __tablename__ = "visual_analysis"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)

    screenshot_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    dominant_colors: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    brand_similarity_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detected_logos: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="visual_analysis")
