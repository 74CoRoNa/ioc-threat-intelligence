from time import perf_counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.persistence import record_analysis
from app.core.database import get_db
from app.schemas.subnet import SubnetCalculationResponse, SubnetRequest, SubnetResponse
from app.services.subnet_service import SubnetService


router = APIRouter(prefix="/api/subnet", tags=["subnet"])


@router.post("/calculate", response_model=SubnetCalculationResponse)
async def calculate_subnet(
    request: SubnetRequest,
    session: Session = Depends(get_db),
) -> SubnetCalculationResponse:
    started_at = perf_counter()
    result = SubnetService.calculate(request.ip_cidr)
    investigation_id = record_analysis(
        session,
        target=result.input,
        target_type="subnet",
        result=result,
        started_at=started_at,
    )
    response = SubnetResponse.model_validate(result)
    return SubnetCalculationResponse(
        **response.model_dump(),
        investigation_id=investigation_id,
    )
