from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.investigation import (
    DeleteInvestigationResponse,
    InvestigationDetailResponse,
    InvestigationListResponse,
    InvestigationSummaryResponse,
)
from app.schemas.report import InvestigationReportResponse
from app.services.investigation_service import InvestigationService
from app.services.report_service import ReportService


router = APIRouter(prefix="/api/investigations", tags=["investigations"])


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    target_type: str | None = None,
    verdict: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    search: str | None = Query(default=None, max_length=256),
    session: Session = Depends(get_db),
) -> InvestigationListResponse:
    items, total, total_pages = InvestigationService(session).list(
        page=page,
        page_size=page_size,
        target_type=target_type,
        verdict=verdict,
        date_from=date_from,
        date_to=date_to,
        search=search,
    )
    return InvestigationListResponse(
        items=[InvestigationSummaryResponse.model_validate(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get("/{investigation_id}/report")
async def generate_report(
    investigation_id: int,
    format: str = Query(default="json", pattern="^(json|md|html)$"),
    session: Session = Depends(get_db),
):
    investigation = InvestigationService(session).get(investigation_id)
    report = ReportService.build(investigation)
    if format == "md":
        return PlainTextResponse(
            ReportService.to_markdown(report),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="investigation-{investigation_id}.md"'},
        )
    if format == "html":
        return HTMLResponse(ReportService.to_html(report))
    return InvestigationReportResponse.model_validate(report)


@router.get("/{investigation_id}", response_model=InvestigationDetailResponse)
async def get_investigation(
    investigation_id: int,
    session: Session = Depends(get_db),
) -> InvestigationDetailResponse:
    result = InvestigationService(session).get(investigation_id)
    return InvestigationDetailResponse.model_validate(result)


@router.delete("/{investigation_id}", response_model=DeleteInvestigationResponse)
async def delete_investigation(
    investigation_id: int,
    session: Session = Depends(get_db),
) -> DeleteInvestigationResponse:
    InvestigationService(session).delete(investigation_id)
    return DeleteInvestigationResponse(deleted=True, investigation_id=investigation_id)
