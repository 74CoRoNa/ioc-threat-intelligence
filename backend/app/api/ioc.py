import asyncio
from dataclasses import replace
from time import perf_counter

from fastapi import APIRouter, Depends
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session

from app.api.dependencies import get_dns_service, get_threat_intelligence_service
from app.api.persistence import elapsed_ms, stored_intelligence
from app.core.database import get_db
from app.schemas.ioc import (
    BulkIOCAnalysisRequest,
    BulkIOCAnalysisResponse,
    ExtractionResponse,
    IOCAnalysisRequest,
    IOCAnalysisResponse,
    LogAnalysisRequest,
)
from app.services.dns_service import DNSService
from app.services.investigation_service import InvestigationService
from app.services.ioc_extractor import IOCExtractor
from app.services.ip_service import IPService
from app.services.risk_engine import RiskEngine
from app.services.threat_intelligence_service import ThreatIntelligenceService
from app.services.url_service import URLService
from app.utils.patterns import (
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
    refang,
    split_host_port,
)


router = APIRouter(prefix="/api/analyze", tags=["ioc"])


def _detect_ioc_type(value: str) -> str:
    normalized = refang(value.strip())
    for ioc_type, pattern in (
        ("sha256", SHA256_PATTERN),
        ("sha1", SHA1_PATTERN),
        ("md5", MD5_PATTERN),
    ):
        if pattern.fullmatch(normalized):
            return ioc_type
    return URLService.detect_target_type(normalized)


def _safe_type(value: str) -> str:
    try:
        return _detect_ioc_type(value)
    except Exception:
        return "unknown"


async def _analyze_one(
    request: IOCAnalysisRequest,
    dns_service: DNSService,
    threat_intelligence: ThreatIntelligenceService,
) -> IOCAnalysisResponse:
    submitted = refang(request.value.strip())
    value, observed_port = split_host_port(submitted)
    try:
        ioc_type = _detect_ioc_type(value)
        if ioc_type == "ip":
            analysis = await IPService.analyze_with_dns(value, dns_service)
            analysis = await threat_intelligence.enrich_ip(analysis, observed_port)
            analysis = replace(
                analysis,
                risk_assessment=RiskEngine.assess_ip(analysis),
            )
        elif ioc_type == "domain":
            analysis = await URLService(dns_service).analyze_domain(value)
            analysis = await threat_intelligence.enrich_domain(analysis)
            analysis = replace(
                analysis,
                risk_assessment=RiskEngine.assess_domain(analysis),
            )
        elif ioc_type == "url":
            analysis = await URLService(dns_service).analyze_url(value)
            analysis = await threat_intelligence.enrich_url(analysis)
            analysis = replace(
                analysis,
                risk_assessment=RiskEngine.assess_url(analysis),
            )
        else:
            providers = await threat_intelligence.lookup_hash(value)
            risk = RiskEngine.from_providers(providers, expected_sources=2)
            result = {
                "hash": value,
                "hash_type": ioc_type,
                "threat_intelligence": jsonable_encoder(providers),
                "risk_assessment": jsonable_encoder(risk),
            }
            return IOCAnalysisResponse(
                value=value,
                type=ioc_type,
                status="ok",
                result=result,
                score=risk.score,
                error=None,
            )
        encoded = jsonable_encoder(analysis)
        if observed_port is not None:
            encoded["observed_port"] = observed_port
        return IOCAnalysisResponse(
            value=value,
            type=ioc_type,
            status="ok",
            result=encoded,
            score=analysis.risk_assessment.score,
            error=None,
        )
    except Exception as error:
        return IOCAnalysisResponse(
            value=value,
            type=request.type or _safe_type(value),
            status="error",
            result=None,
            score=None,
            error=str(error) or "IOC analysis failed.",
        )


@router.post("/log", response_model=ExtractionResponse)
async def extract_log(
    request: LogAnalysisRequest,
    session: Session = Depends(get_db),
) -> ExtractionResponse:
    started_at = perf_counter()
    extraction = IOCExtractor().extract(request.text)
    investigation = InvestigationService(session).record(
        target="Pasted log",
        target_type="log",
        raw_result=extraction,
        duration_ms=elapsed_ms(started_at),
        iocs=[
            {"ioc_value": item.value, "ioc_type": item.type}
            for item in extraction.iocs
        ],
    )
    return ExtractionResponse(
        iocs=extraction.iocs,
        truncated=extraction.truncated,
        message=extraction.message,
        refanged=extraction.refanged,
        investigation_id=investigation.id,
    )


@router.post("/ioc/bulk", response_model=BulkIOCAnalysisResponse)
async def analyze_ioc_bulk(
    request: BulkIOCAnalysisRequest,
    dns_service: DNSService = Depends(get_dns_service),
    threat_intelligence: ThreatIntelligenceService = Depends(
        get_threat_intelligence_service
    ),
    session: Session = Depends(get_db),
) -> BulkIOCAnalysisResponse:
    started_at = perf_counter()
    semaphore = asyncio.Semaphore(5)

    async def bounded(item: IOCAnalysisRequest) -> IOCAnalysisResponse:
        async with semaphore:
            return await _analyze_one(item, dns_service, threat_intelligence)

    items = list(await asyncio.gather(*(bounded(item) for item in request.iocs)))
    investigation = InvestigationService(session).record(
        target=f"Bulk IOC analysis ({len(items)} indicators)",
        target_type="ioc_batch",
        raw_result={"items": jsonable_encoder(items)},
        duration_ms=elapsed_ms(started_at),
        iocs=[
            {"ioc_value": item.value, "ioc_type": item.type}
            for item in items
        ],
    )
    return BulkIOCAnalysisResponse(items=items, investigation_id=investigation.id)


@router.post("/ioc", response_model=IOCAnalysisResponse)
async def analyze_ioc(
    request: IOCAnalysisRequest,
    dns_service: DNSService = Depends(get_dns_service),
    threat_intelligence: ThreatIntelligenceService = Depends(
        get_threat_intelligence_service
    ),
    session: Session = Depends(get_db),
) -> IOCAnalysisResponse:
    started_at = perf_counter()
    item = await _analyze_one(request, dns_service, threat_intelligence)
    providers, risk = stored_intelligence(item.result)
    investigation = InvestigationService(session).record(
        target=item.value,
        target_type=item.type,
        raw_result=item,
        status="completed" if item.status == "ok" else "partial",
        duration_ms=elapsed_ms(started_at),
        iocs=[{"ioc_value": item.value, "ioc_type": item.type}],
        threat_results=providers,
        risk_assessment=risk,
    )
    result = item.model_dump()
    if result["result"] is not None:
        result["result"]["investigation_id"] = investigation.id
    return IOCAnalysisResponse.model_validate(result)
