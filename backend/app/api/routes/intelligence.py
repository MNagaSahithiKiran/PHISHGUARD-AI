"""
PhishGuard AI - Multi-Modal Intelligence API Endpoints
Provides:
- POST /api/v1/intelligence/analyze: Trigger full multimodal phishing assessment.
- GET /api/v1/intelligence/{scan_id}: Query previous multimodal assessment record.
"""

import uuid
import json
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.scan import Scan, ScanResult, ScanEvidence
from app.models.intelligence import FusionAnalysisRecord, ModelExecutionRecord, ExplanationRecord
from app.schemas.intelligence import (
    IntelligenceAnalyzeRequest,
    IntelligenceAnalyzeResponse,
    IntelligenceEvidenceItem,
    IntelligenceExplanationSchema,
    PerformanceMetrics,
)
from app.core.security import SecurityValidationError
from app.analyzers.safety.ssrf_guard import SSRFSecurityException
from app.intelligence.fusion_service import MultiModalFusionService
from app.services.notification_service import create_notification


logger = logging.getLogger("phishguard.api.intelligence")

router = APIRouter(prefix="/intelligence", tags=["Multi-Modal Intelligence Engine"])


@router.post(
    "/analyze",
    response_model=IntelligenceAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Multi-Modal AI Assessment",
    description="Fuses URL lexical intelligence, DOM/HTTP structure, and visual screenshot signals into a calibrated security verdict.",
)
async def analyze_target_multimodal(
    req: IntelligenceAnalyzeRequest,
    http_req: Request,
    db: AsyncSession = Depends(get_db),
):
    scan_id = req.scan_id or str(uuid.uuid4())
    client_ip = http_req.client.host if http_req.client else None

    # Check for previous snapshot hash of this URL to detect live content changes
    previous_snapshot_hash = None
    try:
        prev_stmt = (
            select(ScanResult.dom_snapshot_hash)
            .join(Scan, Scan.id == ScanResult.scan_id)
            .where(
                (Scan.url == req.url) | (Scan.normalized_url == req.url),
                ScanResult.dom_snapshot_hash.isnot(None),
            )
            .order_by(ScanResult.completed_at.desc())
            .limit(1)
        )
        prev_res = await db.execute(prev_stmt)
        previous_snapshot_hash = prev_res.scalars().first()
    except Exception as prev_err:
        logger.warning(f"Could not query previous snapshot hash: {prev_err}")

    fusion_svc = MultiModalFusionService.get_instance()

    try:
        result = await fusion_svc.analyze_target(
            raw_url=req.url,
            scan_id=scan_id,
            include_visual=req.include_visual,
            previous_snapshot_hash=previous_snapshot_hash,
        )
    except (SSRFSecurityException, SecurityValidationError) as ssrf_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Analysis blocked for security: {str(ssrf_err)}",
        )
    except Exception as e:
        logger.error(f"Intelligence analysis failed for {req.url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Intelligence processing failed: {str(e)}",
        )

    # Database Persistence
    try:
        # 1. Base Scan: Update existing if present, else create new
        existing_scan = await db.get(Scan, scan_id)
        redirect_chain_json = json.dumps(result.get("redirect_chain", [])) if result.get("redirect_chain") is not None else None
        if existing_scan:
            existing_scan.status = "completed"
            existing_scan.normalized_url = result["normalized_url"]
            existing_scan.final_url = result.get("final_url", result["normalized_url"])
            existing_scan.canonical_url = result.get("canonical_url", result["normalized_url"])
            existing_scan.redirect_chain = redirect_chain_json
            existing_scan.domain = result["domain"]
            scan = existing_scan
        else:
            scan = Scan(
                id=scan_id,
                url=result["url"],
                normalized_url=result["normalized_url"],
                final_url=result.get("final_url", result["normalized_url"]),
                canonical_url=result.get("canonical_url", result["normalized_url"]),
                redirect_chain=redirect_chain_json,
                domain=result["domain"],
                status="completed",
                client_ip=client_ip,
            )
            db.add(scan)

        # 2. ScanResult: Update existing or create
        existing_res = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
        scan_res = existing_res.scalars().first()
        if scan_res:
            scan_res.verdict = result["classification"]
            scan_res.risk_score = result["risk_score"]
            scan_res.confidence_score = round(result["phishing_probability"] * 100.0, 1)
            scan_res.summary = result["explanation"]["summary"]
            scan_res.completed_at = datetime.now(timezone.utc)
            scan_res.model_version = result.get("models", {}).get("fusion", {}).get("model_version", "1.0.0")
            scan_res.feature_version = "1.0.0"
            scan_res.preprocessing_version = "1.0.0"
            scan_res.decision_policy_version = result.get("models", {}).get("fusion", {}).get("decision_policy_version", "1.0.0")
            scan_res.url_feature_hash = result.get("url_feature_hash")
            scan_res.dom_snapshot_hash = result.get("dom_snapshot_hash")
            scan_res.screenshot_hash = result.get("screenshot_hash")
            scan_res.model_input_hash = result.get("model_input_hash")
            scan_res.prediction_hash = result.get("prediction_hash")
            scan_res.live_content_changed = result.get("live_content_changed", False)
            scan_res.content_change_notice = result.get("content_change_notice")
            scan_res.reproducibility_data = json.dumps(result.get("reproducibility", {}))
        else:
            scan_res = ScanResult(
                scan_id=scan_id,
                verdict=result["classification"],
                risk_score=result["risk_score"],
                confidence_score=round(result["phishing_probability"] * 100.0, 1),
                summary=result["explanation"]["summary"],
                completed_at=datetime.now(timezone.utc),
                model_version=result.get("models", {}).get("fusion", {}).get("model_version", "1.0.0"),
                feature_version="1.0.0",
                preprocessing_version="1.0.0",
                decision_policy_version=result.get("models", {}).get("fusion", {}).get("decision_policy_version", "1.0.0"),
                url_feature_hash=result.get("url_feature_hash"),
                dom_snapshot_hash=result.get("dom_snapshot_hash"),
                screenshot_hash=result.get("screenshot_hash"),
                model_input_hash=result.get("model_input_hash"),
                prediction_hash=result.get("prediction_hash"),
                live_content_changed=result.get("live_content_changed", False),
                content_change_notice=result.get("content_change_notice"),
                reproducibility_data=json.dumps(result.get("reproducibility", {})),
            )
            db.add(scan_res)

        # 3. FusionAnalysisRecord
        fusion_rec = FusionAnalysisRecord(
            scan_id=scan_id,
            url=result["url"],
            classification=result["classification"],
            raw_probability=result["models"]["fusion"]["raw_fusion_probability"],
            calibrated_probability=result["phishing_probability"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            modalities_used=json.dumps(result["modalities_used"]),
            missing_modalities=json.dumps(result["missing_modalities"]),
            decision_policy_version=result["models"]["fusion"]["decision_policy_version"],
            calibration_version=result["models"]["fusion"]["calibration_method"],
            total_latency_ms=result["performance"]["total_analysis_ms"],
            url_feature_hash=result.get("url_feature_hash"),
            dom_snapshot_hash=result.get("dom_snapshot_hash"),
            screenshot_hash=result.get("screenshot_hash"),
            model_input_hash=result.get("model_input_hash"),
            prediction_hash=result.get("prediction_hash"),
            live_content_changed=result.get("live_content_changed", False),
            content_change_notice=result.get("content_change_notice"),
            reproducibility_data=json.dumps(result.get("reproducibility", {})),
        )
        db.add(fusion_rec)
        await db.flush()

        # 4. ModelExecutionRecords
        for mod_name, mod_data in result["models"].items():
            if isinstance(mod_data, dict):
                m_rec = ModelExecutionRecord(
                    fusion_analysis_id=fusion_rec.id,
                    modality=mod_name,
                    model_name=mod_data.get("model_name", mod_name),
                    model_version=mod_data.get("model_version", "1.0.0"),
                    prediction=mod_data.get("prediction"),
                    probability=mod_data.get("probability", mod_data.get("calibrated_probability")),
                    latency_ms=mod_data.get("latency_ms", 0.0),
                    status=mod_data.get("status", "available"),
                )
                db.add(m_rec)

        # 5. ExplanationRecord
        exp_data = result["explanation"]
        exp_rec = ExplanationRecord(
            fusion_analysis_id=fusion_rec.id,
            summary=exp_data["summary"],
            key_signals=json.dumps(exp_data.get("key_model_signals", [])),
            observed_evidence=json.dumps(exp_data.get("observed_factual_evidence", [])),
            feature_attributions=json.dumps(exp_data.get("feature_attributions", [])),
        )
        db.add(exp_rec)

        # 6. Persist External Threat Intelligence Evidence Ledger
        reputation_data = result.get("reputation", {})
        ledger_items = reputation_data.get("evidence_ledger", [])
        for item in ledger_items:
            obs = item.get("observed_at")
            if isinstance(obs, str):
                try:
                    obs_dt = datetime.fromisoformat(obs)
                except Exception:
                    obs_dt = datetime.now(timezone.utc)
            elif isinstance(obs, datetime):
                obs_dt = obs
            else:
                obs_dt = datetime.now(timezone.utc)

            ev_rec = ScanEvidence(
                scan_id=scan_id,
                provider=item.get("provider", "unknown"),
                evidence_type=item.get("evidence_type", "generic"),
                status=item.get("status", "UNAVAILABLE"),
                value=item.get("value"),
                confidence=item.get("confidence"),
                source_url=item.get("source_url"),
                observed_at=obs_dt,
                evidence_hash=item.get("evidence_hash"),
                raw_reference=item.get("raw_reference"),
            )
            db.add(ev_rec)

        await db.commit()

        # Emit automatic security alert notification if threat detected
        domain = result.get("domain", "Unknown")
        if result["classification"] in ["PHISHING", "SUSPICIOUS"]:
            sev = "critical" if result["classification"] == "PHISHING" else "warning"
            await create_notification(
                db=db,
                title=f"{result['classification']} Target Identified: {domain}",
                message=f"Threat detected for target {result['url'][:80]} with risk score {result['risk_score']}/100.",
                severity=sev,
                link=f"/scans/{scan_id}",
            )
    except Exception as db_err:
        logger.error(f"Error persisting fusion analysis to DB: {db_err}")
        await db.rollback()

    return IntelligenceAnalyzeResponse(
        scan_id=scan_id,
        url=result["url"],
        original_url=result.get("original_url", result["url"]),
        normalized_url=result["normalized_url"],
        final_url=result.get("final_url", result["normalized_url"]),
        canonical_url=result.get("canonical_url", result["normalized_url"]),
        redirect_chain=result.get("redirect_chain", []),
        domain=result["domain"],
        status=result["status"],
        classification=result["classification"],
        phishing_probability=result["phishing_probability"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        modalities_used=result["modalities_used"],
        missing_modalities=result["missing_modalities"],
        models=result["models"],
        evidence=[IntelligenceEvidenceItem(**e) for e in result["evidence"]],
        explanation=IntelligenceExplanationSchema(**result["explanation"]),
        performance=PerformanceMetrics(**result["performance"]),
        screenshot_url=result.get("screenshot_url"),
        heatmap_url=result.get("heatmap_url"),
        reproducibility=result.get("reproducibility"),
        url_feature_hash=result.get("url_feature_hash"),
        dom_snapshot_hash=result.get("dom_snapshot_hash"),
        screenshot_hash=result.get("screenshot_hash"),
        model_input_hash=result.get("model_input_hash"),
        prediction_hash=result.get("prediction_hash"),
        live_content_changed=result.get("live_content_changed", False),
        content_change_notice=result.get("content_change_notice"),
        reputation=result.get("reputation"),
        reason_codes=result.get("reason_codes", []),
        reason_details=result.get("reason_details", []),
        decision_policy_version=result.get("decision_policy_version", "risk_policy_v1"),
    )


@router.get(
    "/{scan_id}",
    response_model=IntelligenceAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Multi-Modal Assessment by Scan ID",
    description="Retrieves a previously computed multimodal assessment with models, evidence, and explanation.",
)
async def get_multimodal_assessment(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(FusionAnalysisRecord)
        .where(FusionAnalysisRecord.scan_id == scan_id)
        .order_by(FusionAnalysisRecord.created_at.desc())
    )
    res = await db.execute(stmt)
    rec = res.scalars().first()

    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Multi-modal assessment with scan ID '{scan_id}' not found.",
        )

    # Reconstruct models dict
    models_dict = {}
    for m in rec.model_executions:
        models_dict[m.modality] = {
            "model_name": m.model_name,
            "model_version": m.model_version,
            "prediction": m.prediction,
            "probability": m.probability,
            "latency_ms": m.latency_ms,
            "status": m.status,
        }

    # Reconstruct explanation
    explanation_obj = {
        "summary": rec.explanation.summary if rec.explanation else "",
        "classification": rec.classification,
        "calibrated_phishing_probability": rec.calibrated_probability,
        "key_model_signals": json.loads(rec.explanation.key_signals) if rec.explanation else [],
        "observed_factual_evidence": json.loads(rec.explanation.observed_evidence) if rec.explanation else [],
        "modality_status": {
            "modalities_used": json.loads(rec.modalities_used),
            "missing_modalities": json.loads(rec.missing_modalities),
        },
        "feature_attributions": json.loads(rec.explanation.feature_attributions) if rec.explanation else [],
    }

    repro_data = json.loads(rec.reproducibility_data) if rec.reproducibility_data else None

    # Reconstruct reputation from scan_evidence
    target_scan_id = rec.scan_id or scan_id
    ev_stmt = select(ScanEvidence).where(ScanEvidence.scan_id == target_scan_id)
    ev_res = await db.execute(ev_stmt)
    ev_records = ev_res.scalars().all()
    evidence_ledger_list = []
    provider_results_dict = {}
    threat_matches = 0
    providers_configured = 0
    for ev in ev_records:
        evidence_ledger_list.append({
            "provider": ev.provider,
            "evidence_type": ev.evidence_type,
            "status": ev.status,
            "value": ev.value,
            "confidence": ev.confidence,
            "source_url": ev.source_url,
            "observed_at": ev.observed_at.isoformat() if ev.observed_at else None,
            "evidence_hash": ev.evidence_hash,
            "raw_reference": ev.raw_reference,
        })
        if ev.status != "NOT_CONFIGURED":
            providers_configured += 1
        if ev.status == "THREAT_MATCH":
            threat_matches += 1
        raw_det = {}
        if ev.raw_reference:
            try:
                raw_det = json.loads(ev.raw_reference)
            except Exception:
                raw_det = {"raw": ev.raw_reference}
        provider_results_dict[ev.provider] = {
            "provider_name": ev.provider,
            "status": ev.status,
            "summary": ev.value or "",
            "confidence": ev.confidence,
            "details": raw_det,
            "query": rec.url,
        }

    reputation_summary = {
        "overall_status": "THREAT_DETECTED" if threat_matches > 0 else ("CLEAN" if providers_configured > 0 else "NO_REPUTATION_DATA"),
        "threat_matches": threat_matches,
        "providers_queried": len(provider_results_dict),
        "providers_configured": providers_configured,
        "evidence_ledger": evidence_ledger_list,
        "provider_results": provider_results_dict,
    }

    from app.intelligence.decision_policy import DecisionPolicyEngine, POLICY_VERSION
    eval_res = DecisionPolicyEngine.evaluate(
        calibrated_probability=rec.calibrated_probability,
        modalities_used=json.loads(rec.modalities_used),
        missing_modalities=json.loads(rec.missing_modalities),
        dom_signals={},
        lexical_signals={},
        reputation_summary=reputation_summary,
    )

    scan_obj = await db.get(Scan, target_scan_id) if target_scan_id else None
    orig_url = scan_obj.url if scan_obj else rec.url
    norm_url = scan_obj.normalized_url if scan_obj else rec.url
    fin_url = (scan_obj.final_url if scan_obj and scan_obj.final_url else norm_url)
    canon_url = (scan_obj.canonical_url if scan_obj and scan_obj.canonical_url else norm_url)
    redir_chain = []
    if scan_obj and scan_obj.redirect_chain:
        try:
            redir_chain = json.loads(scan_obj.redirect_chain)
        except Exception:
            redir_chain = []
    scan_domain = scan_obj.domain if scan_obj else None

    return IntelligenceAnalyzeResponse(
        scan_id=rec.scan_id or scan_id,
        url=rec.url,
        original_url=orig_url,
        normalized_url=norm_url,
        final_url=fin_url,
        canonical_url=canon_url,
        redirect_chain=redir_chain,
        domain=scan_domain,
        status="completed",
        classification=rec.classification,
        phishing_probability=rec.calibrated_probability,
        risk_score=rec.risk_score,
        risk_level=rec.risk_level,
        modalities_used=json.loads(rec.modalities_used),
        missing_modalities=json.loads(rec.missing_modalities),
        models=models_dict,
        evidence=[],
        explanation=IntelligenceExplanationSchema(**explanation_obj),
        performance=PerformanceMetrics(total_analysis_ms=rec.total_latency_ms),
        reproducibility=repro_data,
        url_feature_hash=rec.url_feature_hash,
        dom_snapshot_hash=rec.dom_snapshot_hash,
        screenshot_hash=rec.screenshot_hash,
        model_input_hash=rec.model_input_hash,
        prediction_hash=rec.prediction_hash,
        live_content_changed=rec.live_content_changed or False,
        content_change_notice=rec.content_change_notice,
        reputation=reputation_summary,
        reason_codes=eval_res["reason_codes"],
        reason_details=eval_res["reason_details"],
        decision_policy_version=POLICY_VERSION,
    )
