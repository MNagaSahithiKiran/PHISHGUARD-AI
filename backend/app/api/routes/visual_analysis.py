"""
PhishGuard AI - Visual Analysis API Route
Endpoint for running and retrieving webpage screenshot computer vision analysis,
visual telemetry, and Grad-CAM explainability heatmaps.
"""

import json
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.scan import Scan
from app.models.visual_analysis import (
    ScreenshotRecord,
    VisualAnalysisRecord,
    VisualEvidenceRecord,
)
from app.schemas.visual_analysis import (
    VisualAnalysisRequest,
    VisualAnalysisResponse,
    VisualEvidenceSchema,
    VisualFeaturesSchema,
)
from app.vision.screenshot_service import ScreenshotService
from app.vision.visual_prediction_service import VisualPredictionService
from app.analyzers.safety.ssrf_guard import SSRFSecurityException

logger = logging.getLogger("phishguard.api.visual")

router = APIRouter(prefix="/visual-analysis", tags=["Visual AI Analysis"])


@router.post(
    "",
    response_model=VisualAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze webpage visual screenshot",
    description="Captures a sandboxed browser screenshot and analyzes visual features with transfer learning CNN and Grad-CAM.",
)
async def analyze_visual_endpoint(
    req: VisualAnalysisRequest,
    db: AsyncSession = Depends(get_db),
):
    target_url = req.url
    scan_id = req.scan_id

    # If url is not given but scan_id is, look up the scan
    if not target_url and scan_id:
        stmt = select(Scan).where(Scan.id == scan_id)
        res = await db.execute(stmt)
        scan = res.scalars().first()
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan ID '{scan_id}' not found.",
            )
        target_url = scan.url

    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'url' or a valid 'scan_id' must be provided.",
        )

    # 1. Capture Screenshot
    try:
        shot_res = await ScreenshotService.capture_target_screenshot(
            target_url=target_url,
            scan_id=scan_id,
        )
    except SSRFSecurityException as ssrf_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Screenshot blocked for security: {str(ssrf_err)}",
        )
    except Exception as e:
        logger.error(f"Failed to capture screenshot: {e}")
        return VisualAnalysisResponse(
            status="failed",
            scan_id=scan_id,
            message=f"Screenshot capture failed: {str(e)}",
        )

    # 2. Persist Screenshot record
    shot_rec = ScreenshotRecord(
        id=shot_res["screenshot_id"],
        scan_id=scan_id,
        url=shot_res["url"],
        file_path=shot_res["file_path"],
        file_size_bytes=shot_res["file_size_bytes"],
        width=shot_res["width"],
        height=shot_res["height"],
        format_name=shot_res["format"],
        md5_hash=shot_res["md5_hash"],
        capture_duration_ms=shot_res["duration_ms"],
    )
    db.add(shot_rec)

    # 3. Execute Model Inference & Explainability
    predictor = VisualPredictionService.get_instance()
    if not predictor.is_ready():
        await db.commit()
        return VisualAnalysisResponse(
            status="not_available",
            scan_id=scan_id,
            screenshot_url=shot_res["relative_url"],
            message="Visual AI model weights are not loaded.",
        )

    try:
        pred_res = predictor.analyze_image(shot_res["file_path"], generate_heatmap=True)
    except Exception as pred_err:
        logger.error(f"Visual prediction inference failed: {pred_err}")
        await db.commit()
        return VisualAnalysisResponse(
            status="failed",
            scan_id=scan_id,
            screenshot_url=shot_res["relative_url"],
            message=f"Visual model inference failed: {str(pred_err)}",
        )

    # 4. Persist Visual Analysis & Evidence records
    vis_rec = VisualAnalysisRecord(
        scan_id=scan_id,
        screenshot_id=shot_rec.id,
        model_name=pred_res["model_name"],
        model_version=pred_res["model_version"],
        preprocessing_version=pred_res["preprocessing_version"],
        prediction=pred_res["prediction"],
        label=pred_res["label"],
        phishing_probability=pred_res["phishing_probability"],
        confidence_score=pred_res["confidence_score"],
        inference_latency_ms=pred_res["inference_latency_ms"],
        has_centered_card=pred_res["visual_features"]["has_centered_card"],
        edge_density=pred_res["visual_features"]["edge_density"],
        whitespace_ratio=pred_res["visual_features"]["whitespace_ratio"],
        dominant_colors=json.dumps(pred_res["visual_features"]["dominant_colors"]),
        heatmap_path=pred_res["heatmap_url"],
    )
    db.add(vis_rec)
    await db.flush()

    evidence_models = []
    for ev in pred_res["evidence"]:
        ev_rec = VisualEvidenceRecord(
            visual_analysis_id=vis_rec.id,
            evidence_type=ev["evidence_type"],
            severity=ev["severity"],
            title=ev["title"],
            description=ev["description"],
            source=ev["source"],
        )
        db.add(ev_rec)
        evidence_models.append(
            VisualEvidenceSchema(
                evidence_type=ev["evidence_type"],
                severity=ev["severity"],
                title=ev["title"],
                description=ev["description"],
                source=ev["source"],
            )
        )

    await db.commit()

    return VisualAnalysisResponse(
        status="completed",
        scan_id=scan_id,
        prediction=pred_res["prediction"],
        label=pred_res["label"],
        phishing_probability=pred_res["phishing_probability"],
        confidence_score=pred_res["confidence_score"],
        model_name=pred_res["model_name"],
        model_version=pred_res["model_version"],
        preprocessing_version=pred_res["preprocessing_version"],
        inference_latency_ms=pred_res["inference_latency_ms"],
        screenshot_url=shot_res["relative_url"],
        heatmap_url=pred_res["heatmap_url"],
        visual_features=VisualFeaturesSchema(**pred_res["visual_features"]),
        evidence=evidence_models,
    )


@router.get(
    "/{scan_id}",
    response_model=VisualAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Get visual analysis by scan ID",
    description="Retrieves previously calculated visual classification, screenshot, and Grad-CAM heatmap.",
)
async def get_visual_analysis_endpoint(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(VisualAnalysisRecord)
        .where(VisualAnalysisRecord.scan_id == scan_id)
        .order_by(VisualAnalysisRecord.created_at.desc())
    )
    res = await db.execute(stmt)
    rec = res.scalars().first()

    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Visual analysis for scan ID '{scan_id}' not found.",
        )

    screenshot_url = None
    if rec.screenshot:
        screenshot_url = f"/api/v1/screenshots/{rec.screenshot.file_path.split('/')[-1].split(chr(92))[-1]}"

    dom_colors = []
    if rec.dominant_colors:
        try:
            dom_colors = json.loads(rec.dominant_colors)
        except Exception:
            dom_colors = []

    evidence_schemas = [
        VisualEvidenceSchema(
            evidence_type=ev.evidence_type,
            severity=ev.severity,
            title=ev.title,
            description=ev.description,
            source=ev.source,
        )
        for ev in rec.visual_evidence
    ]

    return VisualAnalysisResponse(
        status="completed",
        scan_id=rec.scan_id,
        prediction=rec.prediction,
        label=rec.label,
        phishing_probability=rec.phishing_probability,
        confidence_score=rec.confidence_score,
        model_name=rec.model_name,
        model_version=rec.model_version,
        preprocessing_version=rec.preprocessing_version,
        inference_latency_ms=rec.inference_latency_ms,
        screenshot_url=screenshot_url,
        heatmap_url=rec.heatmap_path,
        visual_features=VisualFeaturesSchema(
            whitespace_ratio=rec.whitespace_ratio or 0.0,
            edge_density=rec.edge_density or 0.0,
            has_centered_card=rec.has_centered_card,
            dominant_colors=dom_colors,
        ),
        evidence=evidence_schemas,
    )
