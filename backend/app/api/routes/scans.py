import csv
import io
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, Response, HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_optional_current_user
from app.db.session import get_db
from app.models.user import User
from app.models.scan import Scan, ScanResult
from app.services.scan_service import ScanService
from app.services.audit_service import log_audit_event
from app.reports.pdf_report_service import PDFReportService
from app.schemas.scan import (
    ScanCreate,
    ScanCreationResponse,
    ScanDetailResponse,
    ScanListResponse,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanCreationResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    request: Request,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Submits a target URL for automated analysis.
    Validates URL syntax, enforces SSRF barriers, extracts initial lexical features,
    and returns a queued scan record.
    """
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    user_id = current_user.id if current_user else None
    user_email = current_user.email if current_user else None

    result = await ScanService.create_scan(
        db=db,
        scan_in=payload,
        client_ip=client_ip,
        user_agent=user_agent,
        user_id=user_id,
    )

    await log_audit_event(
        db=db,
        event_type="SCAN_INITIATED",
        action=f"Target scan initiated for {payload.url[:100]}",
        user_id=user_id,
        user_email=user_email,
        status="success",
        client_ip=client_ip,
        details=f"Scan ID: {result.scan_id}",
    )

    return result


@router.get("/stats")
async def get_scan_statistics(db: AsyncSession = Depends(get_db)):
    """Provides genuine aggregate statistics of all recorded scans."""
    return await ScanService.get_system_stats(db=db)


@router.get("/export/csv")
async def export_scans_csv(
    status: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Exports website scan telemetry and verdicts as a downloadable RFC 4180 CSV spreadsheet.
    """
    query = select(Scan).outerjoin(ScanResult, Scan.id == ScanResult.scan_id).order_by(desc(Scan.created_at))
    if status:
        query = query.where(Scan.status == status)
    if verdict:
        query = query.where(ScanResult.verdict == verdict.lower())

    res = await db.execute(query)
    scans = res.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "scan_id",
        "url",
        "domain",
        "status",
        "verdict",
        "risk_score",
        "confidence_score",
        "rule_match_count",
        "created_at",
    ])

    for s in scans:
        v = s.scan_result.verdict if s.scan_result else "unrated"
        r = s.scan_result.risk_score if (s.scan_result and s.scan_result.risk_score is not None) else ""
        c = s.scan_result.confidence_score if (s.scan_result and s.scan_result.confidence_score is not None) else ""
        m = s.scan_result.rule_match_count if s.scan_result else 0
        writer.writerow([
            s.id,
            s.url,
            s.domain,
            s.status,
            v,
            r,
            c,
            m,
            s.created_at.isoformat() if s.created_at else "",
        ])

    csv_data = output.getvalue()
    output.close()

    if current_user:
        await log_audit_event(
            db=db,
            event_type="EXPORT_CSV",
            action="Scans dataset exported to CSV",
            user_id=current_user.id,
            user_email=current_user.email,
            status="success",
        )

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="phishguard-scans-export.csv"'},
    )


@router.get("/{scan_id}/report.pdf")
async def download_scan_pdf_report(
    scan_id: str,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generates and returns an official cybersecurity threat assessment PDF report for a scan.
    """
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    pdf_bytes = PDFReportService.generate_scan_pdf(scan)

    if current_user:
        await log_audit_event(
            db=db,
            event_type="REPORT_DOWNLOAD",
            action=f"Downloaded PDF threat report for scan {scan.id}",
            user_id=current_user.id,
            user_email=current_user.email,
            status="success",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="phishguard-report-{scan.id[:8]}.pdf"'},
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by scan status: queued, processing, completed, failed"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: legitimate, suspicious, phishing"),
    search: Optional[str] = Query(None, description="Search keyword in URL or domain"),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves a paginated list of all website scans with search and filter capabilities."""
    return await ScanService.list_scans(
        db=db,
        page=page,
        limit=limit,
        status_filter=status,
        verdict_filter=verdict,
        search=search,
    )


@router.get("/compare")
async def compare_two_scans(
    scan_id_1: str = Query(..., description="First Scan ID to compare"),
    scan_id_2: str = Query(..., description="Second Scan ID to compare"),
    db: AsyncSession = Depends(get_db),
):
    """
    Compares two scans side-by-side to verify reproducibility, snapshot consistency,
    and detect live content changes.
    """
    from app.intelligence.reproducibility import compare_scans

    s1_res = await db.execute(
        select(Scan).outerjoin(ScanResult, Scan.id == ScanResult.scan_id).where(Scan.id == scan_id_1)
    )
    s1 = s1_res.scalar_one_or_none()
    if not s1:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id_1}' not found.")

    s2_res = await db.execute(
        select(Scan).outerjoin(ScanResult, Scan.id == ScanResult.scan_id).where(Scan.id == scan_id_2)
    )
    s2 = s2_res.scalar_one_or_none()
    if not s2:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id_2}' not found.")

    def scan_to_dict(scan_obj: Scan):
        res = getattr(scan_obj, "scan_result", None)
        return {
            "id": scan_obj.id,
            "url": scan_obj.url,
            "normalized_url": scan_obj.normalized_url,
            "canonical_url": getattr(scan_obj, "canonical_url", None) or scan_obj.normalized_url,
            "verdict": res.verdict if res else None,
            "risk_score": res.risk_score if res else None,
            "model_version": getattr(res, "model_version", None) if res else None,
            "feature_version": getattr(res, "feature_version", None) if res else None,
            "preprocessing_version": getattr(res, "preprocessing_version", None) if res else None,
            "decision_policy_version": getattr(res, "decision_policy_version", None) if res else None,
            "url_feature_hash": getattr(res, "url_feature_hash", None) if res else None,
            "dom_snapshot_hash": getattr(res, "dom_snapshot_hash", None) if res else None,
            "screenshot_hash": getattr(res, "screenshot_hash", None) if res else None,
            "model_input_hash": getattr(res, "model_input_hash", None) if res else None,
            "prediction_hash": getattr(res, "prediction_hash", None) if res else None,
            "live_content_changed": getattr(res, "live_content_changed", False) if res else False,
        }

    d1 = scan_to_dict(s1)
    d2 = scan_to_dict(s2)
    cmp_res = compare_scans(d1, d2)
    cmp_res["scan_1"] = d1
    cmp_res["scan_2"] = d2
    cmp_res["reproducible"] = cmp_res.get("is_reproducible", False)
    cmp_res["prediction_hash_match"] = bool(d1.get("prediction_hash") and d1.get("prediction_hash") == d2.get("prediction_hash"))
    cmp_res["model_input_hash_match"] = bool(d1.get("model_input_hash") and d1.get("model_input_hash") == d2.get("model_input_hash"))
    cmp_res["dom_snapshot_hash_match"] = bool(d1.get("dom_snapshot_hash") and d1.get("dom_snapshot_hash") == d2.get("dom_snapshot_hash"))
    cmp_res["verdict_match"] = bool(d1.get("verdict") == d2.get("verdict"))
    r1 = d1.get("risk_score")
    r2 = d2.get("risk_score")
    cmp_res["risk_score_diff"] = round(abs(float(r1) - float(r2)), 2) if (r1 is not None and r2 is not None) else None
    return cmp_res


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves full analysis details, lexical indicators, and status for a scan."""
    return await ScanService.get_scan_by_id(db=db, scan_id=scan_id)
