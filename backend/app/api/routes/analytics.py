from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.scan import Scan, ScanResult, ThreatIndicator

router = APIRouter(prefix="/analytics", tags=["Analytics"])


class RiskBucket(BaseModel):
    range: str
    count: int
    label: str


class AnalyticsOverviewResponse(BaseModel):
    total_scans: int
    phishing_scans: int
    suspicious_scans: int
    legitimate_scans: int
    unrated_scans: int
    detection_rate_pct: float
    average_risk_score: float
    total_threat_indicators: int
    scans_today: int
    scans_last_7_days: int
    risk_distribution: List[RiskBucket]


class DailyTrendItem(BaseModel):
    date: str
    total: int
    phishing: int
    suspicious: int
    legitimate: int


@router.get("/overview", response_model=AnalyticsOverviewResponse)
async def get_analytics_overview(db: AsyncSession = Depends(get_db)):
    """
    Computes authentic system analytics across the database without synthetic data.
    """
    # Total scans
    res_total = await db.execute(select(func.count(Scan.id)))
    total_scans = res_total.scalar_one() or 0

    # Verdict counts
    res_verdicts = await db.execute(
        select(ScanResult.verdict, func.count(ScanResult.id)).group_by(ScanResult.verdict)
    )
    verdict_map = {row[0].lower(): row[1] for row in res_verdicts.all()}
    phishing_count = verdict_map.get("phishing", 0)
    suspicious_count = verdict_map.get("suspicious", 0)
    legitimate_count = verdict_map.get("legitimate", 0)
    unrated_count = total_scans - (phishing_count + suspicious_count + legitimate_count)
    if unrated_count < 0:
        unrated_count = 0

    # Average risk score
    res_avg_risk = await db.execute(select(func.avg(ScanResult.risk_score)))
    avg_risk = res_avg_risk.scalar_one()
    avg_risk_score = round(float(avg_risk), 2) if avg_risk is not None else 0.0

    # Total threat indicators
    res_ind = await db.execute(select(func.count(ThreatIndicator.id)))
    total_indicators = res_ind.scalar_one() or 0

    # Detection rate
    scanned_with_verdict = phishing_count + suspicious_count + legitimate_count
    detection_rate_pct = (
        round(((phishing_count + suspicious_count) / scanned_with_verdict) * 100, 2)
        if scanned_with_verdict > 0
        else 0.0
    )

    # Time filters
    now = datetime.now(timezone.utc)
    today_start = now - timedelta(days=1)
    week_start = now - timedelta(days=7)

    res_today = await db.execute(
        select(func.count(Scan.id)).where(Scan.created_at >= today_start)
    )
    scans_today = res_today.scalar_one() or 0

    res_week = await db.execute(
        select(func.count(Scan.id)).where(Scan.created_at >= week_start)
    )
    scans_last_7_days = res_week.scalar_one() or 0

    # Risk distribution bins (0-20, 21-40, 41-60, 61-80, 81-100)
    res_scores = await db.execute(
        select(ScanResult.risk_score).where(ScanResult.risk_score != None)
    )
    scores = [r[0] for r in res_scores.all() if r[0] is not None]

    b0_20 = sum(1 for s in scores if 0 <= s <= 20)
    b21_40 = sum(1 for s in scores if 20 < s <= 40)
    b41_60 = sum(1 for s in scores if 40 < s <= 60)
    b61_80 = sum(1 for s in scores if 60 < s <= 80)
    b81_100 = sum(1 for s in scores if 80 < s <= 100)

    risk_distribution = [
        RiskBucket(range="0-20", count=b0_20, label="Low Risk"),
        RiskBucket(range="21-40", count=b21_40, label="Guarded"),
        RiskBucket(range="41-60", count=b41_60, label="Elevated"),
        RiskBucket(range="61-80", count=b61_80, label="High Risk"),
        RiskBucket(range="81-100", count=b81_100, label="Critical Threat"),
    ]

    return AnalyticsOverviewResponse(
        total_scans=total_scans,
        phishing_scans=phishing_count,
        suspicious_scans=suspicious_count,
        legitimate_scans=legitimate_count,
        unrated_scans=unrated_count,
        detection_rate_pct=detection_rate_pct,
        average_risk_score=avg_risk_score,
        total_threat_indicators=total_indicators,
        scans_today=scans_today,
        scans_last_7_days=scans_last_7_days,
        risk_distribution=risk_distribution,
    )


@router.get("/trends", response_model=List[DailyTrendItem])
async def get_daily_trends(days: int = 7, db: AsyncSession = Depends(get_db)):
    """Computes daily scan volume trends over the requested number of days."""
    days = min(max(days, 1), 30)
    now = datetime.now(timezone.utc)
    trends: List[DailyTrendItem] = []

    # Iterate day by day in reverse
    for i in range(days - 1, -1, -1):
        day_date = (now - timedelta(days=i)).date()
        day_start = datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0, tzinfo=timezone.utc)
        day_end = day_start + timedelta(days=1)

        # Scans for this day
        q = select(Scan.id).where(Scan.created_at >= day_start, Scan.created_at < day_end)
        scan_ids = (await db.execute(q)).scalars().all()
        total_day = len(scan_ids)

        phishing_day = 0
        suspicious_day = 0
        legitimate_day = 0

        if total_day > 0:
            res_res = await db.execute(
                select(ScanResult.verdict, func.count(ScanResult.id))
                .where(ScanResult.scan_id.in_(scan_ids))
                .group_by(ScanResult.verdict)
            )
            v_counts = {r[0].lower(): r[1] for r in res_res.all()}
            phishing_day = v_counts.get("phishing", 0)
            suspicious_day = v_counts.get("suspicious", 0)
            legitimate_day = v_counts.get("legitimate", 0)

        trends.append(
            DailyTrendItem(
                date=day_date.isoformat(),
                total=total_day,
                phishing=phishing_day,
                suspicious=suspicious_day,
                legitimate=legitimate_day,
            )
        )

    return trends
