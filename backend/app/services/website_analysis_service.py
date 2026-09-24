"""
PhishGuard AI - Website Analysis Service
Orchestrates the entire Phase 3 website intelligence workflow:
1. URL safety and SSRF validation
2. Controlled, stream-capped HTTP fetch and redirect chain tracking
3. Passive HTML/DOM/Form/Link/Script/Iframe/Resource/Header analysis
4. Structured factual security evidence generation
5. Website feature extraction (48 features)
6. Phase 2 trained URL model prediction
7. Transparent Phase 3 multi-modal status declaration
8. Optional sandboxed screenshot capture
9. Database persistence (Scan, WebsiteAnalysisRecord, RedirectHopRecord, EvidenceRecord)
"""

import uuid
import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import select

from app.core.security import validate_and_sanitize_url
from app.analyzers.safety.ssrf_guard import SSRFGuard, SSRFSecurityException
from app.analyzers.website_analyzer import analyze_website
from app.services.evidence_service import generate_website_evidence
from app.services.browser_service import capture_website_screenshot
from app.ml.prediction_service import PredictionService
from ml.feature_engineering.website_features import extract_website_features

from app.analyzers.network_analyzer import NetworkAnalyzer
from app.models.features import DomainInformation
from app.models.scan import Scan, ScanResult
from app.models.website_analysis import (
    WebsiteAnalysisRecord,
    RedirectHopRecord,
    EvidenceRecord,
)

logger = logging.getLogger("phishguard.website_service")


class WebsiteAnalysisService:
    @classmethod
    async def analyze_url(
        cls,
        raw_url: str,
        db: Optional[AsyncSession] = None,
        client_ip: Optional[str] = None,
        capture_screenshot: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes comprehensive, controlled website intelligence analysis.
        """
        scan_id = str(uuid.uuid4())

        # 1. URL syntax & pre-fetch SSRF check
        try:
            sanitized = validate_and_sanitize_url(raw_url)
            normalized_url = sanitized["normalized_url"]
            domain = sanitized["domain"]
            SSRFGuard.validate_target_url(normalized_url)
        except (ValueError, HTTPException, SSRFSecurityException) as e:

            logger.warning(f"URL rejected during pre-validation: {e}")
            # Return safe blocked response
            return {
                "scan_id": scan_id,
                "status": "blocked",
                "url": raw_url,
                "final_url": raw_url,
                "http": {
                    "initial_url": raw_url,
                    "final_url": raw_url,
                    "status_code": None,
                    "content_length": 0,
                    "response_time_ms": 0.0,
                    "error": "Analysis blocked for security reasons.",
                    "truncated": False,
                    "ip_address": None,
                    "content_type": "",
                },
                "redirects": {"total_hops": 0, "hops": [], "protocol_downgrades": 0, "cross_domain_redirects": 0},
                "html": {"title": "", "language": "", "charset": "", "meta_tags": {}, "body_byte_length": 0},
                "dom": {"total_tags": 0, "dom_depth": 0, "text_ratio": 0.0, "hidden_elements_count": 0, "tag_frequencies": {}},
                "forms": {"total_forms": 0, "login_forms_count": 0, "has_password_field": False, "external_action_count": 0, "empty_action_count": 0, "forms": []},
                "links": {"total_links": 0, "internal_links": 0, "external_links": 0, "null_empty_links": 0, "external_link_ratio": 0.0, "null_link_ratio": 0.0, "distinct_external_domains": []},
                "scripts": {"total_scripts": 0, "inline_scripts": 0, "external_scripts": 0, "external_script_domains": [], "inline_script_bytes": 0},
                "iframes": {"total_iframes": 0, "hidden_iframes": 0, "cross_origin_iframes": 0, "sandboxed_iframes": 0, "suspicious_fullpage_iframes": 0, "iframe_sources": []},
                "resources": {"total_resources": 0, "external_resources": 0, "external_resource_ratio": 0.0, "mixed_content_count": 0, "distinct_resource_domains": [], "stylesheet_count": 0, "external_stylesheets": 0, "image_count": 0, "external_images": 0},
                "headers": {"hsts_present": False, "hsts_max_age": None, "hsts_includes_subdomains": False, "hsts_preload": False, "csp_present": False, "csp_has_default_src": False, "csp_has_frame_ancestors": False, "x_frame_options": None, "x_content_type_options": None, "referrer_policy": None, "permissions_policy_present": False, "server_banner": None, "x_powered_by": None, "security_header_score": 0.0, "raw_headers": {}},
                "evidence": [
                    {
                        "category": "network",
                        "severity": "critical",
                        "title": "Destination Address Restricted",
                        "detail": "Target resolves to private, loopback, cloud metadata, or unroutable network address.",
                        "recommendation": "Submit a valid public internet website.",
                    }
                ],
                "screenshot_url": None,
                "url_model": None,
                "website_model": {
                    "status": "not_available",
                    "message": "Phase 2 evaluated URL-based models. Dedicated multimodal website model will be trained in Phase 4 once live dataset is accumulated.",
                },
            }

        # 2. Controlled Website Analysis (HTTP fetch + Analyzers)
        website_result = await analyze_website(normalized_url)
        http_data = website_result.http_data
        redirect_data = website_result.redirect_data
        html_data = website_result.html_data
        dom_data = website_result.dom_data
        form_data = website_result.form_data
        link_data = website_result.link_data
        script_data = website_result.script_data
        iframe_data = website_result.iframe_data
        resource_data = website_result.resource_data
        header_data = website_result.header_data

        # 2.5 Passive Network Probes (DNS, TLS, RDAP)
        network_res = await NetworkAnalyzer.analyze(
            domain=domain,
            hostname=sanitized.get("hostname", domain),
            scheme=sanitized.get("scheme", "https"),
        )

        # 3. Evidence Generation
        evidence_items = generate_website_evidence(
            http_data=http_data,
            redirect_data=redirect_data,
            html_data=html_data,
            dom_data=dom_data,
            form_data=form_data,
            link_data=link_data,
            script_data=script_data,
            iframe_data=iframe_data,
            resource_data=resource_data,
            header_data=header_data,
        )
        evidence_dicts = [e.to_dict() for e in evidence_items]

        # Add DNS resolution failure evidence if applicable
        if network_res.get("dns", {}).get("status") == "DNS_FAILED":
            evidence_dicts.append({
                "category": "network",
                "severity": "critical",
                "title": "DNS Resolution Failed",
                "detail": network_res["dns"].get("error", "Domain could not be resolved via DNS."),
                "recommendation": "Target domain does not exist or has no active DNS records.",
            })

        # 4. Feature Extraction (48 features)
        features_dict = extract_website_features(
            http_data=http_data,
            redirect_data=redirect_data,
            html_data=html_data,
            dom_data=dom_data,
            form_data=form_data,
            link_data=link_data,
            script_data=script_data,
            iframe_data=iframe_data,
            resource_data=resource_data,
            header_data=header_data,
        )

        # 5. URL ML Model Inference (Phase 2 model)
        url_model_pred = None
        try:
            url_model_pred = PredictionService.predict_url(normalized_url, explain=False)
        except Exception as ml_err:
            logger.warning(f"URL ML model prediction bypassed: {ml_err}")
            url_model_pred = {"status": "error", "error": str(ml_err)}

        # 6. Screenshot (Optional / Non-blocking)
        screenshot_url = None
        if capture_screenshot and not http_data.get("error"):
            try:
                screenshot_url, _ = await capture_website_screenshot(normalized_url, scan_id)
            except Exception as ss_err:
                logger.warning(f"Screenshot capture skipped: {ss_err}")

        # 7. Database Persistence (if session provided)
        if db is not None:
            try:
                # Create root Scan record
                scan = Scan(
                    id=scan_id,
                    url=raw_url,
                    normalized_url=normalized_url,
                    final_url=http_data.get("final_url", normalized_url),
                    canonical_url=html_data.get("meta_tags", {}).get("canonical") or normalized_url,
                    redirect_chain=json.dumps(redirect_data.get("hops", [])),
                    domain=domain,
                    status="completed" if not http_data.get("error") else "failed",
                    client_ip=client_ip,
                )
                db.add(scan)

                # ScanResult
                verdict = "unrated"
                risk_score = None
                conf = None
                if url_model_pred and "verdict" in url_model_pred:
                    verdict = url_model_pred["verdict"]
                    conf = url_model_pred.get("confidence_score")
                    prob = url_model_pred.get("probabilities", {}).get("phishing", 0.0)
                    risk_score = round(prob * 100.0, 1)

                scan_result = ScanResult(
                    scan_id=scan_id,
                    verdict=verdict,
                    risk_score=risk_score,
                    confidence_score=conf,
                    summary=f"Analysis of {normalized_url}. Status code: {http_data.get('status_code')}",
                    completed_at=datetime.now(timezone.utc),
                )
                db.add(scan_result)

                # DomainInformation Record
                dom_info_data = network_res.get("domain_info", {})
                dom_info_rec = DomainInformation(
                    scan_id=scan_id,
                    registrar=dom_info_data.get("registrar"),
                    creation_date=dom_info_data.get("creation_date"),
                    expiration_date=dom_info_data.get("expiration_date"),
                    domain_age_days=dom_info_data.get("domain_age_days"),
                    dnssec=dom_info_data.get("dnssec"),
                    has_valid_ssl=dom_info_data.get("has_valid_ssl"),
                    ssl_issuer=dom_info_data.get("ssl_issuer"),
                    nameservers=dom_info_data.get("nameservers"),
                )
                db.add(dom_info_rec)

                # WebsiteAnalysisRecord
                analysis_rec = WebsiteAnalysisRecord(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    initial_url=raw_url,
                    final_url=http_data.get("final_url", normalized_url),
                    status_code=http_data.get("status_code"),
                    response_time_ms=http_data.get("response_time_ms"),
                    content_length=http_data.get("content_length"),
                    content_type=http_data.get("content_type"),
                    ip_address=http_data.get("ip_address"),
                    title=html_data.get("title", "")[:500],
                    language=html_data.get("language", "")[:50],
                    charset=html_data.get("charset", "")[:50],
                    dom_depth=dom_data.get("dom_depth"),
                    total_tags=dom_data.get("total_tags"),
                    text_ratio=dom_data.get("text_ratio"),
                    hidden_elements_count=dom_data.get("hidden_elements_count"),
                    total_forms=form_data.get("total_forms"),
                    login_forms_count=form_data.get("login_forms_count"),
                    has_password_field=form_data.get("has_password_field"),
                    external_form_action_count=form_data.get("external_action_count"),
                    total_links=link_data.get("total_links"),
                    internal_links=link_data.get("internal_links"),
                    external_links=link_data.get("external_links"),
                    external_link_ratio=link_data.get("external_link_ratio"),
                    null_link_ratio=link_data.get("null_link_ratio"),
                    total_scripts=script_data.get("total_scripts"),
                    inline_scripts=script_data.get("inline_scripts"),
                    external_scripts=script_data.get("external_scripts"),
                    total_iframes=iframe_data.get("total_iframes"),
                    hidden_iframes=iframe_data.get("hidden_iframes"),
                    cross_origin_iframes=iframe_data.get("cross_origin_iframes"),
                    total_resources=resource_data.get("total_resources"),
                    external_resource_ratio=resource_data.get("external_resource_ratio"),
                    mixed_content_count=resource_data.get("mixed_content_count"),
                    hsts_present=header_data.get("hsts_present"),
                    csp_present=header_data.get("csp_present"),
                    x_frame_options=header_data.get("x_frame_options"),
                    x_content_type_options=header_data.get("x_content_type_options"),
                    security_header_score=header_data.get("security_header_score"),
                    redirect_count=redirect_data.get("total_hops", 0),
                    screenshot_path=screenshot_url,
                    analysis_error=http_data.get("error"),
                )
                db.add(analysis_rec)

                # Redirect hops
                for hop in redirect_data.get("hops", []):
                    db.add(
                        RedirectHopRecord(
                            website_analysis_id=analysis_rec.id,
                            hop_number=hop.get("hop_number", 0),
                            source_url=hop.get("source_url", ""),
                            target_url=hop.get("target_url", ""),
                            status_code=hop.get("status_code", 0),
                        )
                    )

                # Evidence items
                for ev in evidence_items:
                    db.add(
                        EvidenceRecord(
                            website_analysis_id=analysis_rec.id,
                            category=ev.category,
                            severity=ev.severity,
                            title=ev.title,
                            detail=ev.detail,
                            recommendation=ev.recommendation,
                        )
                    )

                await db.commit()
            except Exception as db_err:
                logger.error(f"Error persisting website analysis to DB: {db_err}")
                await db.rollback()

        # 8. Build final response
        return {
            "scan_id": scan_id,
            "status": "completed" if not http_data.get("error") else "failed",
            "url": raw_url,
            "final_url": http_data.get("final_url", normalized_url),
            "http": http_data,
            "redirects": redirect_data,
            "html": html_data,
            "dom": dom_data,
            "dom_snapshot_hash": getattr(website_result, "dom_snapshot_hash", ""),
            "forms": form_data,
            "links": link_data,
            "scripts": script_data,
            "iframes": iframe_data,
            "resources": resource_data,
            "headers": header_data,
            "network": network_res,
            "domain_info": network_res.get("domain_info", {}),
            "evidence": evidence_dicts,
            "screenshot_url": screenshot_url,
            "url_model": url_model_pred,
            "website_model": {
                "status": "not_available",
                "message": "Dedicated multimodal website model will be trained once live HTML/DOM dataset is accumulated.",
            },
            "visual_model": {
                "status": "not_available",
                "message": "Visual analysis can be triggered via /api/v1/visual-analysis.",
            },
        }

    @classmethod
    async def get_analysis_by_scan_id(cls, scan_id: str, db: AsyncSession) -> Optional[Dict[str, Any]]:
        """
        Retrieves a stored website analysis by scan_id.
        """
        stmt = select(WebsiteAnalysisRecord).where(WebsiteAnalysisRecord.scan_id == scan_id)
        result = await db.execute(stmt)
        record = result.scalars().first()
        if not record:
            return None

        # Build response dict from database record
        return {
            "scan_id": record.scan_id,
            "status": "completed" if not record.analysis_error else "failed",
            "url": record.initial_url,
            "final_url": record.final_url,
            "http": {
                "initial_url": record.initial_url,
                "final_url": record.final_url,
                "status_code": record.status_code,
                "content_length": record.content_length or 0,
                "response_time_ms": record.response_time_ms or 0.0,
                "error": record.analysis_error,
                "truncated": False,
                "ip_address": record.ip_address,
                "content_type": record.content_type or "",
            },
            "redirects": {
                "total_hops": record.redirect_count,
                "hops": [
                    {
                        "hop_number": h.hop_number,
                        "source_url": h.source_url,
                        "target_url": h.target_url,
                        "status_code": h.status_code,
                    }
                    for h in record.redirect_hops
                ],
                "protocol_downgrades": 0,
                "cross_domain_redirects": 0,
            },
            "html": {
                "title": record.title or "",
                "language": record.language or "",
                "charset": record.charset or "",
                "meta_tags": {},
                "body_byte_length": record.content_length or 0,
            },
            "dom": {
                "total_tags": record.total_tags or 0,
                "dom_depth": record.dom_depth or 0,
                "text_ratio": record.text_ratio or 0.0,
                "hidden_elements_count": record.hidden_elements_count or 0,
                "tag_frequencies": {},
            },
            "forms": {
                "total_forms": record.total_forms or 0,
                "login_forms_count": record.login_forms_count or 0,
                "has_password_field": record.has_password_field or False,
                "external_action_count": record.external_form_action_count or 0,
                "empty_action_count": 0,
                "forms": [],
            },
            "links": {
                "total_links": record.total_links or 0,
                "internal_links": record.internal_links or 0,
                "external_links": record.external_links or 0,
                "null_empty_links": 0,
                "external_link_ratio": record.external_link_ratio or 0.0,
                "null_link_ratio": record.null_link_ratio or 0.0,
                "distinct_external_domains": [],
            },
            "scripts": {
                "total_scripts": record.total_scripts or 0,
                "inline_scripts": record.inline_scripts or 0,
                "external_scripts": record.external_scripts or 0,
                "external_script_domains": [],
                "inline_script_bytes": 0,
            },
            "iframes": {
                "total_iframes": record.total_iframes or 0,
                "hidden_iframes": record.hidden_iframes or 0,
                "cross_origin_iframes": record.cross_origin_iframes or 0,
                "sandboxed_iframes": 0,
                "suspicious_fullpage_iframes": 0,
                "iframe_sources": [],
            },
            "resources": {
                "total_resources": record.total_resources or 0,
                "external_resources": 0,
                "external_resource_ratio": record.external_resource_ratio or 0.0,
                "mixed_content_count": record.mixed_content_count or 0,
                "distinct_resource_domains": [],
                "stylesheet_count": 0,
                "external_stylesheets": 0,
                "image_count": 0,
                "external_images": 0,
            },
            "headers": {
                "hsts_present": record.hsts_present or False,
                "hsts_max_age": None,
                "hsts_includes_subdomains": False,
                "hsts_preload": False,
                "csp_present": record.csp_present or False,
                "csp_has_default_src": False,
                "csp_has_frame_ancestors": False,
                "x_frame_options": record.x_frame_options,
                "x_content_type_options": record.x_content_type_options,
                "referrer_policy": None,
                "permissions_policy_present": False,
                "server_banner": None,
                "x_powered_by": None,
                "security_header_score": record.security_header_score or 0.0,
                "raw_headers": {},
            },
            "evidence": [
                {
                    "category": e.category,
                    "severity": e.severity,
                    "title": e.title,
                    "detail": e.detail,
                    "recommendation": e.recommendation,
                }
                for e in record.evidence_items
            ],
            "screenshot_url": record.screenshot_path,
            "url_model": None,
            "website_model": {
                "status": "not_available",
                "message": "Dedicated multimodal website model will be trained once live HTML/DOM dataset is accumulated.",
            },
            "visual_model": {
                "status": "not_available",
                "message": "Visual analysis can be triggered via /api/v1/visual-analysis.",
            },
        }
