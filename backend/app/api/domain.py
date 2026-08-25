from time import perf_counter
from dataclasses import replace

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_dns_service, get_threat_intelligence_service
from app.api.persistence import record_analysis
from app.core.database import get_db
from app.core.exceptions import ValidationError
from app.schemas.domain import (
    DomainAnalysisResponse,
    DomainRequest,
    TargetAnalysisResponse,
    TargetRequest,
    URLAnalysisResponse,
    URLRequest,
)
from app.services.dns_service import DNSService
from app.services.threat_intelligence_service import ThreatIntelligenceService
from app.services.risk_engine import RiskEngine
from app.services.url_service import URLService


router = APIRouter(prefix="/api/analyze", tags=["analysis"])


@router.post("/domain", response_model=DomainAnalysisResponse)
async def analyze_domain(
    request: DomainRequest,
    dns_service: DNSService = Depends(get_dns_service),
    threat_intelligence: ThreatIntelligenceService = Depends(
        get_threat_intelligence_service
    ),
    session: Session = Depends(get_db),
) -> DomainAnalysisResponse:
    started_at = perf_counter()
    result = await URLService(dns_service).analyze_domain(request.target)
    result = await threat_intelligence.enrich_domain(result)
    result = replace(result, risk_assessment=RiskEngine.assess_domain(result))
    investigation_id = record_analysis(
        session,
        target=result.domain,
        target_type="domain",
        result=result,
        started_at=started_at,
    )
    return DomainAnalysisResponse.model_validate(result).model_copy(
        update={"investigation_id": investigation_id}
    )


@router.post("/url", response_model=URLAnalysisResponse)
async def analyze_url(
    request: URLRequest,
    dns_service: DNSService = Depends(get_dns_service),
    threat_intelligence: ThreatIntelligenceService = Depends(
        get_threat_intelligence_service
    ),
    session: Session = Depends(get_db),
) -> URLAnalysisResponse:
    started_at = perf_counter()
    result = await URLService(dns_service).analyze_url(request.url)
    result = await threat_intelligence.enrich_url(result)
    result = replace(result, risk_assessment=RiskEngine.assess_url(result))
    investigation_id = record_analysis(
        session,
        target=result.refanged,
        target_type="url",
        result=result,
        started_at=started_at,
    )
    return URLAnalysisResponse.model_validate(result).model_copy(
        update={"investigation_id": investigation_id}
    )


@router.post("/target", response_model=TargetAnalysisResponse)
async def analyze_target(
    request: TargetRequest,
    dns_service: DNSService = Depends(get_dns_service),
    threat_intelligence: ThreatIntelligenceService = Depends(
        get_threat_intelligence_service
    ),
    session: Session = Depends(get_db),
) -> TargetAnalysisResponse:
    started_at = perf_counter()
    service = URLService(dns_service)
    target_type = service.detect_target_type(request.target)
    if target_type == "ip":
        raise ValidationError("Direct IP inquiries are disabled. Enter a domain or URL.")
    elif target_type == "url":
        result = await service.analyze_url(request.target)
        result = await threat_intelligence.enrich_url(result)
        result = replace(result, risk_assessment=RiskEngine.assess_url(result))
    else:
        result = await service.analyze_domain(request.target)
        result = await threat_intelligence.enrich_domain(result)
        result = replace(result, risk_assessment=RiskEngine.assess_domain(result))
    normalized_target = (
        result.ip_address
        if target_type == "ip"
        else result.refanged
        if target_type == "url"
        else result.domain
    )
    investigation_id = record_analysis(
        session,
        target=normalized_target,
        target_type=target_type,
        result=result,
        started_at=started_at,
    )
    return TargetAnalysisResponse(
        target_type=target_type,
        result=result,
        investigation_id=investigation_id,
    )
