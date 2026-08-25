from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


class IOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ioc_value: str
    ioc_type: str
    first_seen: datetime
    last_seen: datetime


class ThreatResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    status: str
    raw_response: dict[str, Any] | None
    fetched_at: datetime


class RiskAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    score: int
    verdict: str
    evidence: list[dict[str, Any]]
    created_at: datetime


class InvestigationSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    target_type: str
    created_at: datetime
    status: str
    duration_ms: int
    risk_assessments: list[RiskAssessmentResponse] = Field(exclude=True)

    @computed_field
    @property
    def score(self) -> int | None:
        return self.risk_assessments[-1].score if self.risk_assessments else None

    @computed_field
    @property
    def verdict(self) -> str | None:
        return self.risk_assessments[-1].verdict if self.risk_assessments else None


class InvestigationDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    target_type: str
    created_at: datetime
    status: str
    duration_ms: int
    raw_result: dict[str, Any]
    iocs: list[IOCResponse]
    threat_results: list[ThreatResultResponse]
    risk_assessments: list[RiskAssessmentResponse]


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummaryResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class DeleteInvestigationResponse(BaseModel):
    deleted: bool
    investigation_id: int

