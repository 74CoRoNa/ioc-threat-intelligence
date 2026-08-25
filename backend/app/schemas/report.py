from typing import Any

from pydantic import BaseModel


class InvestigationReportResponse(BaseModel):
    report_title: str
    investigation_id: int
    target: str
    target_type: str
    timestamp: Any
    status: str
    duration_ms: int
    analysis: dict[str, Any]
    iocs: list[dict[str, Any]]
    threat_intelligence: list[dict[str, Any]]
    sources_consulted: list[str]
    sources_unavailable: list[dict[str, str]]
    risk: dict[str, Any] | None
    recommendations: list[str]
    disclaimer: str

