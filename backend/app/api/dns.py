import ipaddress
from time import perf_counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_dns_service
from app.api.persistence import record_analysis
from app.core.database import get_db
from app.schemas.dns import DNSLookupResponse, DNSRequest
from app.services.dns_service import DNSAnalysis, DNSService
from app.utils.patterns import refang


router = APIRouter(prefix="/api/analyze", tags=["dns"])


@router.post("/dns", response_model=DNSLookupResponse)
async def analyze_dns(
    request: DNSRequest,
    dns_service: DNSService = Depends(get_dns_service),
    session: Session = Depends(get_db),
) -> DNSLookupResponse:
    started_at = perf_counter()
    target = refang(request.target.strip())
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        result = await dns_service.resolve(target)
    else:
        ptr = await dns_service.reverse(str(address))
        result = DNSAnalysis(target=str(address), records={"PTR": ptr})
    investigation_id = record_analysis(
        session,
        target=result.target,
        target_type="dns",
        result=result,
        started_at=started_at,
    )
    return DNSLookupResponse.model_validate(
        {
            "target": result.target,
            "records": result.records,
            "investigation_id": investigation_id,
        }
    )
