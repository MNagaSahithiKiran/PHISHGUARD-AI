from datetime import datetime, timezone
from typing import Optional, Tuple, List
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.core.security import validate_and_sanitize_url
from app.analyzers.url_analyzer import extract_url_lexical_features, detect_heuristic_indicators
from app.models.scan import Scan, ScanResult, ThreatIndicator
from app.models.features import URLFeatures, DomainInformation
from app.schemas.scan import ScanCreate, ScanCreationResponse, ScanDetailResponse, ScanListResponse, ScanSummaryItem
from app.core.logging import logger


class ScanService:
    @staticmethod
    async def create_scan(
        db: AsyncSession,
        scan_in: ScanCreate,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> ScanCreationResponse:
        """
        Validates URL with SSRF checks, extracts initial lexical features,
        records heuristic indicators, and stores a new Scan record in 'queued' status.
        Does NOT fake ML prediction.
        """
        # Step 1: Validate URL and enforce SSRF defenses
        sanitized = validate_and_sanitize_url(scan_in.url)
        normalized_url = sanitized["normalized_url"]
        domain = sanitized["domain"]

        # Step 2: Initialize Scan record in queued status
        scan = Scan(
            url=sanitized["original_url"],
            normalized_url=normalized_url,
            final_url=normalized_url,
            canonical_url=normalized_url,
            domain=domain,
            status="queued",
            user_id=user_id,
            client_ip=client_ip,
            user_agent=user_agent,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.flush()  # Populates scan.id

        # Step 3: Extract genuine lexical features
        features_dict = extract_url_lexical_features(sanitized)
        url_features = URLFeatures(
            scan_id=scan.id,
            url_length=features_dict["url_length"],
            hostname_length=features_dict["hostname_length"],
            path_length=features_dict["path_length"],
            query_length=features_dict["query_length"],
            count_dots=features_dict["count_dots"],
            count_hyphens=features_dict["count_hyphens"],
            count_at=features_dict["count_at"],
            count_question_marks=features_dict["count_question_marks"],
            count_equal_signs=features_dict["count_equal_signs"],
            count_subdomains=features_dict["count_subdomains"],
            has_ip_address=features_dict["has_ip_address"],
            has_punycode=features_dict["has_punycode"],
            has_shortener=features_dict["has_shortener"],
            has_port_in_url=features_dict["has_port_in_url"],
            entropy_score=features_dict["entropy_score"],
        )
        db.add(url_features)

        # Step 4: Extract heuristic threat indicators
        raw_indicators = detect_heuristic_indicators(features_dict, sanitized)
        for ind in raw_indicators:
            threat_indicator = ThreatIndicator(
                scan_id=scan.id,
                indicator_type=ind["indicator_type"],
                severity=ind["severity"],
                rule_id=ind["rule_id"],
                description=ind["description"],
                details=ind.get("details"),
            )
            db.add(threat_indicator)

        # Step 5: Initial placeholder ScanResult (strictly honest: unrated, zero fake ML confidence)
        scan_result = ScanResult(
            scan_id=scan.id,
            verdict="unrated",
            risk_score=None,
            confidence_score=None,
            summary="Scan queued. Lexical features extracted; awaiting deep multi-modal pipeline execution.",
            rule_match_count=len(raw_indicators),
        )
        db.add(scan_result)

        await db.commit()
        await db.refresh(scan)

        logger.info(f"Scan created with ID {scan.id} for domain {domain} (status: queued)")

        return ScanCreationResponse(
            scan_id=scan.id,
            url=scan.url,
            status=scan.status,
            message="Scan created successfully"
        )

    @staticmethod
    async def get_scan_by_id(db: AsyncSession, scan_id: str) -> ScanDetailResponse:
        """Retrieves a single scan by UUID with all extracted features and indicators."""
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID '{scan_id}' not found."
            )

        return ScanDetailResponse.model_validate(scan)

    @staticmethod
    async def list_scans(
        db: AsyncSession,
        page: int = 1,
        limit: int = 20,
        status_filter: Optional[str] = None,
        verdict_filter: Optional[str] = None,
        search: Optional[str] = None,
        user_id_filter: Optional[str] = None,
    ) -> ScanListResponse:
        """Retrieves a paginated, searchable, and filterable list of scans."""
        offset = (page - 1) * limit

        query = select(Scan).outerjoin(ScanResult, Scan.id == ScanResult.scan_id).order_by(desc(Scan.created_at))

        if status_filter:
            query = query.where(Scan.status == status_filter)
        if verdict_filter:
            query = query.where(ScanResult.verdict == verdict_filter.lower())
        if user_id_filter:
            query = query.where(Scan.user_id == user_id_filter)
        if search:
            search_term = f"%{search.strip()}%"
            query = query.where((Scan.url.ilike(search_term)) | (Scan.domain.ilike(search_term)))

        # Count total
        count_stmt = select(func.count(Scan.id)).outerjoin(ScanResult, Scan.id == ScanResult.scan_id)
        if status_filter:
            count_stmt = count_stmt.where(Scan.status == status_filter)
        if verdict_filter:
            count_stmt = count_stmt.where(ScanResult.verdict == verdict_filter.lower())
        if user_id_filter:
            count_stmt = count_stmt.where(Scan.user_id == user_id_filter)
        if search:
            search_term = f"%{search.strip()}%"
            count_stmt = count_stmt.where((Scan.url.ilike(search_term)) | (Scan.domain.ilike(search_term)))

        total_res = await db.execute(count_stmt)
        total = total_res.scalar() or 0

        # Fetch page items
        items_stmt = query.offset(offset).limit(limit)
        items_res = await db.execute(items_stmt)
        scans = items_res.scalars().all()

        items = []
        for s in scans:
            verdict = s.scan_result.verdict if s.scan_result else "unrated"
            risk_score = s.scan_result.risk_score if s.scan_result else None
            items.append(
                ScanSummaryItem(
                    id=s.id,
                    url=s.url,
                    domain=s.domain,
                    status=s.status,
                    verdict=verdict,
                    risk_score=risk_score,
                    created_at=s.created_at
                )
            )

        return ScanListResponse(
            total=total,
            page=page,
            limit=limit,
            items=items
        )

    @staticmethod
    async def get_system_stats(db: AsyncSession) -> dict:
        """
        Calculates honest dashboard metrics based on actual scan records in the database.
        Zero fabricated statistics.
        """
        total_scans_stmt = select(func.count(Scan.id))
        total_scans = (await db.execute(total_scans_stmt)).scalar() or 0

        queued_stmt = select(func.count(Scan.id)).where(Scan.status == "queued")
        queued_count = (await db.execute(queued_stmt)).scalar() or 0

        completed_stmt = select(func.count(Scan.id)).where(Scan.status == "completed")
        completed_count = (await db.execute(completed_stmt)).scalar() or 0

        # Verdict distribution from scan_results
        phishing_stmt = select(func.count(ScanResult.id)).where(ScanResult.verdict == "phishing")
        phishing_count = (await db.execute(phishing_stmt)).scalar() or 0

        suspicious_stmt = select(func.count(ScanResult.id)).where(ScanResult.verdict == "suspicious")
        suspicious_count = (await db.execute(suspicious_stmt)).scalar() or 0

        legitimate_stmt = select(func.count(ScanResult.id)).where(ScanResult.verdict == "legitimate")
        legitimate_count = (await db.execute(legitimate_stmt)).scalar() or 0

        unrated_stmt = select(func.count(ScanResult.id)).where(ScanResult.verdict == "unrated")
        unrated_count = (await db.execute(unrated_stmt)).scalar() or 0

        return {
            "total_scans": total_scans,
            "queued_scans": queued_count,
            "completed_scans": completed_count,
            "phishing_detected": phishing_count,
            "suspicious_sites": suspicious_count,
            "legitimate_sites": legitimate_count,
            "unrated_sites": unrated_count,
            "pipeline_state": "Phase 1 - Ingestion & Lexical Heuristics active. Deep ML training pipeline ready for dataset.",
        }
