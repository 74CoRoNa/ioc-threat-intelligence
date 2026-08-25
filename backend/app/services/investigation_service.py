from datetime import datetime
from math import ceil
from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlalchemy import Select, delete, distinct, func, select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import NotFound
from app.models import IOC, Investigation, RiskAssessment, ThreatResult


class InvestigationService:
    """Store and retrieve complete investigations transactionally."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def record(
        self,
        *,
        target: str,
        target_type: str,
        raw_result: Any,
        status: str = "completed",
        duration_ms: int = 0,
        iocs: list[dict[str, Any]] | None = None,
        threat_results: list[dict[str, Any]] | None = None,
        risk_assessment: dict[str, Any] | None = None,
    ) -> Investigation:
        investigation = Investigation(
            target=target,
            target_type=target_type,
            status=status,
            duration_ms=duration_ms,
            raw_result=jsonable_encoder(raw_result),
        )
        for item in iocs or []:
            investigation.iocs.append(IOC(**item))
        for item in threat_results or []:
            investigation.threat_results.append(ThreatResult(**item))
        if risk_assessment:
            investigation.risk_assessments.append(RiskAssessment(**risk_assessment))

        try:
            self.session.add(investigation)
            self.session.commit()
            self.session.refresh(investigation)
        except Exception:
            self.session.rollback()
            raise
        return investigation

    def list(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        target_type: str | None = None,
        verdict: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
    ) -> tuple[list[Investigation], int, int]:
        filters: list[Any] = []
        if target_type:
            filters.append(Investigation.target_type == target_type)
        if date_from:
            filters.append(Investigation.created_at >= date_from)
        if date_to:
            filters.append(Investigation.created_at <= date_to)
        if search:
            filters.append(Investigation.target.ilike(f"%{search.strip()}%"))

        statement: Select[tuple[Investigation]] = select(Investigation)
        count_statement = select(func.count(distinct(Investigation.id)))
        if verdict:
            statement = statement.join(Investigation.risk_assessments)
            count_statement = count_statement.join(Investigation.risk_assessments)
            filters.append(RiskAssessment.verdict == verdict.upper())

        statement = (
            statement.where(*filters)
            .options(
                selectinload(Investigation.risk_assessments),
                selectinload(Investigation.iocs),
                selectinload(Investigation.threat_results),
            )
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        total = self.session.scalar(count_statement.where(*filters)) or 0
        items = list(self.session.scalars(statement).unique())
        return items, total, ceil(total / page_size) if total else 0

    def get(self, investigation_id: int) -> Investigation:
        statement = (
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(
                selectinload(Investigation.iocs),
                selectinload(Investigation.threat_results),
                selectinload(Investigation.risk_assessments),
            )
        )
        investigation = self.session.scalar(statement)
        if investigation is None:
            raise NotFound("Investigation not found.")
        return investigation

    def delete(self, investigation_id: int) -> None:
        result = self.session.execute(
            delete(Investigation).where(Investigation.id == investigation_id)
        )
        if result.rowcount == 0:
            self.session.rollback()
            raise NotFound("Investigation not found.")
        self.session.commit()

