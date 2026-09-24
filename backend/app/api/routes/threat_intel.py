from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.scan import Scan, ScanResult, ThreatIndicator

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


class TopIndicator(BaseModel):
    rule_id: str
    indicator_type: str
    severity: str
    count: int
    description: str


class ThreatIntelIndicatorsResponse(BaseModel):
    total_indicators_detected: int
    top_indicators: List[TopIndicator]
    severity_breakdown: dict
    type_breakdown: dict


class ObservedDomain(BaseModel):
    domain: str
    scan_count: int
    phishing_count: int
    average_risk_score: float
    last_scanned_at: str


class RecentThreatItem(BaseModel):
    scan_id: str
    url: str
    domain: str
    verdict: str
    risk_score: float
    detected_at: str
    rule_match_count: int


@router.get("/indicators", response_model=ThreatIntelIndicatorsResponse)
async def get_threat_indicators_intel(limit: int = 15, db: AsyncSession = Depends(get_db)):
    """
    Returns authentic empirical aggregations of triggered threat indicators from the database.
    """
    # Total count
    res_tot = await db.execute(select(func.count(ThreatIndicator.id)))
    total_count = res_tot.scalar_one() or 0

    # Severity breakdown
    res_sev = await db.execute(
        select(ThreatIndicator.severity, func.count(ThreatIndicator.id)).group_by(ThreatIndicator.severity)
    )
    sev_map = {row[0].lower(): row[1] for row in res_sev.all()}

    # Type breakdown
    res_type = await db.execute(
        select(ThreatIndicator.indicator_type, func.count(ThreatIndicator.id)).group_by(ThreatIndicator.indicator_type)
    )
    type_map = {row[0].lower(): row[1] for row in res_type.all()}

    # Top triggered indicator rules
    res_top = await db.execute(
        select(
            ThreatIndicator.rule_id,
            ThreatIndicator.indicator_type,
            ThreatIndicator.severity,
            ThreatIndicator.description,
            func.count(ThreatIndicator.id).label("match_count"),
        )
        .group_by(ThreatIndicator.rule_id, ThreatIndicator.indicator_type, ThreatIndicator.severity, ThreatIndicator.description)
        .order_by(desc("match_count"))
        .limit(limit)
    )

    top_indicators = [
        TopIndicator(
            rule_id=r[0],
            indicator_type=r[1],
            severity=r[2],
            description=r[3],
            count=r[4],
        )
        for r in res_top.all()
    ]

    return ThreatIntelIndicatorsResponse(
        total_indicators_detected=total_count,
        top_indicators=top_indicators,
        severity_breakdown=sev_map,
        type_breakdown=type_map,
    )


@router.get("/domains", response_model=List[ObservedDomain])
async def get_observed_domains(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """
    Aggregates threat analytics grouped by target domain.
    """
    # Group by domain
    query = (
        select(
            Scan.domain,
            func.count(Scan.id).label("scan_count"),
            func.max(Scan.created_at).label("last_scanned"),
        )
        .group_by(Scan.domain)
        .order_by(desc("scan_count"))
        .limit(limit)
    )
    res = await db.execute(query)
    domain_rows = res.all()

    domains: List[ObservedDomain] = []
    for d, s_count, last_time in domain_rows:
        # Get phishing count and avg score for this domain
        res_d_scans = await db.execute(select(Scan.id).where(Scan.domain == d))
        d_scan_ids = res_d_scans.scalars().all()

        phishing_count = 0
        avg_risk = 0.0
        if d_scan_ids:
            res_p = await db.execute(
                select(func.count(ScanResult.id)).where(
                    ScanResult.scan_id.in_(d_scan_ids),
                    ScanResult.verdict == "phishing"
                )
            )
            phishing_count = res_p.scalar_one() or 0

            res_avg = await db.execute(
                select(func.avg(ScanResult.risk_score)).where(
                    ScanResult.scan_id.in_(d_scan_ids),
                    ScanResult.risk_score != None
                )
            )
            raw_avg = res_avg.scalar_one()
            avg_risk = round(float(raw_avg), 1) if raw_avg is not None else 0.0

        domains.append(
            ObservedDomain(
                domain=d,
                scan_count=s_count,
                phishing_count=phishing_count,
                average_risk_score=avg_risk,
                last_scanned_at=last_time.isoformat() if last_time else "",
            )
        )

    return domains


@router.get("/recent-threats", response_model=List[RecentThreatItem])
async def get_recent_threats(limit: int = 10, db: AsyncSession = Depends(get_db)):
    """
    Returns the most recent confirmed phishing or suspicious scans.
    """
    query = (
        select(Scan, ScanResult)
        .join(ScanResult, Scan.id == ScanResult.scan_id)
        .where(ScanResult.verdict.in_(["phishing", "suspicious"]))
        .order_by(desc(Scan.created_at))
        .limit(limit)
    )
    res = await db.execute(query)
    rows = res.all()

    items: List[RecentThreatItem] = []
    for scan, result in rows:
        items.append(
            RecentThreatItem(
                scan_id=scan.id,
                url=scan.url,
                domain=scan.domain,
                verdict=result.verdict,
                risk_score=result.risk_score or 0.0,
                detected_at=scan.created_at.isoformat() if scan.created_at else "",
                rule_match_count=result.rule_match_count or 0,
            )
        )

    return items
