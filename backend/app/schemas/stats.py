from datetime import datetime

from pydantic import BaseModel


class SummaryStatsResponse(BaseModel):
    total: int
    low: int
    medium: int
    high: int
    critical: int
    today: int
    last_seven_days: int


class RecentInvestigationResponse(BaseModel):
    id: int
    target: str
    target_type: str
    created_at: datetime
    score: int | None
    verdict: str | None


class TopIOCResponse(BaseModel):
    value: str
    type: str
    occurrences: int
    highest_score: int | None


class DistributionResponse(BaseModel):
    risk_buckets: dict[str, int]
    time_series: list[dict[str, int | str]]

