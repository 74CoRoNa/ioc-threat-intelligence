from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import IOC, Investigation, RiskAssessment
from app.schemas.stats import (
    DistributionResponse,
    RecentInvestigationResponse,
    SummaryStatsResponse,
    TopIOCResponse,
)


router = APIRouter(prefix="/api/stats", tags=["dashboard"])


@router.get("/summary", response_model=SummaryStatsResponse)
async def summary(session: Session = Depends(get_db)) -> SummaryStatsResponse:
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    total = session.scalar(select(func.count(Investigation.id))) or 0
    scores = [row[0] for row in session.execute(select(RiskAssessment.score)).all()]
    return SummaryStatsResponse(
        total=total,
        low=sum(score <= 20 for score in scores),
        medium=sum(21 <= score <= 60 for score in scores),
        high=sum(61 <= score <= 80 for score in scores),
        critical=sum(score >= 81 for score in scores),
        today=session.scalar(
            select(func.count(Investigation.id)).where(
                Investigation.created_at >= today
            )
        )
        or 0,
        last_seven_days=session.scalar(
            select(func.count(Investigation.id)).where(
                Investigation.created_at >= now - timedelta(days=7)
            )
        )
        or 0,
    )


@router.get("/recent", response_model=list[RecentInvestigationResponse])
async def recent(
    limit: int = Query(default=10, ge=1, le=50),
    session: Session = Depends(get_db),
) -> list[RecentInvestigationResponse]:
    rows = session.execute(
        select(
            Investigation.id,
            Investigation.target,
            Investigation.target_type,
            Investigation.created_at,
            RiskAssessment.score,
            RiskAssessment.verdict,
        )
        .outerjoin(RiskAssessment)
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(limit)
    ).all()
    return [
        RecentInvestigationResponse(
            id=row.id,
            target=row.target,
            target_type=row.target_type,
            created_at=row.created_at,
            score=row.score,
            verdict=row.verdict,
        )
        for row in rows
    ]


@router.get("/top-iocs", response_model=list[TopIOCResponse])
async def top_iocs(
    limit: int = Query(default=10, ge=1, le=50),
    session: Session = Depends(get_db),
) -> list[TopIOCResponse]:
    rows = session.execute(
        select(
            IOC.ioc_value,
            IOC.ioc_type,
            func.count(IOC.id).label("occurrences"),
            func.max(RiskAssessment.score).label("highest_score"),
        )
        .join(Investigation, IOC.investigation_id == Investigation.id)
        .outerjoin(RiskAssessment, RiskAssessment.investigation_id == Investigation.id)
        .group_by(IOC.ioc_value, IOC.ioc_type)
        .order_by(desc("highest_score"), desc("occurrences"))
        .limit(limit)
    ).all()
    return [
        TopIOCResponse(
            value=row.ioc_value,
            type=row.ioc_type,
            occurrences=row.occurrences,
            highest_score=row.highest_score,
        )
        for row in rows
    ]


@router.get("/distribution", response_model=DistributionResponse)
async def distribution(session: Session = Depends(get_db)) -> DistributionResponse:
    buckets = {name: 0 for name in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    for (score,) in session.execute(select(RiskAssessment.score)).all():
        bucket = "LOW" if score <= 20 else "MEDIUM" if score <= 60 else "HIGH" if score <= 80 else "CRITICAL"
        buckets[bucket] += 1
    start = datetime.now(timezone.utc).date() - timedelta(days=6)
    rows = session.execute(
        select(
            func.date(Investigation.created_at).label("day"),
            func.count(Investigation.id).label("count"),
        )
        .where(Investigation.created_at >= datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc))
        .group_by(func.date(Investigation.created_at))
    ).all()
    values = {str(row.day): row.count for row in rows}
    series = [
        {"date": str(start + timedelta(days=offset)), "count": values.get(str(start + timedelta(days=offset)), 0)}
        for offset in range(7)
    ]
    return DistributionResponse(risk_buckets=buckets, time_series=series)
