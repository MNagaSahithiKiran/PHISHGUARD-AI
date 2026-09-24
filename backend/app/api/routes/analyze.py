"""
PhishGuard AI - Website Analysis Endpoints
Provides controlled website intelligence scanning, redirect tracking,
DOM/form/script/header telemetry, and auditable security evidence.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.website_analysis import WebsiteAnalyzeRequest, WebsiteAnalyzeResponse
from app.services.website_analysis_service import WebsiteAnalysisService

router = APIRouter(prefix="/analyze", tags=["Website Intelligence Analysis"])


@router.post(
    "",
    response_model=WebsiteAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze website",
    description="Executes a controlled, safe network fetch, DOM/form/header analysis, and Phase 2 ML prediction.",
)
async def analyze_website_endpoint(
    request_data: WebsiteAnalyzeRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = req.client.host if req.client else None
    result = await WebsiteAnalysisService.analyze_url(
        raw_url=request_data.url,
        db=db,
        client_ip=client_ip,
        capture_screenshot=False,
    )
    return result


@router.get(
    "/{scan_id}",
    response_model=WebsiteAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Get website analysis by scan ID",
    description="Retrieves a previously executed website analysis result including evidence records.",
)
async def get_website_analysis_endpoint(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await WebsiteAnalysisService.get_analysis_by_scan_id(scan_id=scan_id, db=db)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Website analysis with scan ID '{scan_id}' not found.",
        )
    return result
