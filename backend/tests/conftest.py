import os
from dataclasses import replace
import pytest

os.environ.update({"DB_PATH": ":memory:", "VIRUSTOTAL_API_KEY": "", "ABUSEIPDB_API_KEY": "", "THREATFOX_API_KEY": "", "URLHAUS_API_KEY": "", "AI_API_KEY": ""})

from app.api.dependencies import get_dns_service, get_threat_intelligence_service
from app.core.database import Base, engine, initialize_database
from app.main import app
from app.services.dns_service import DNSAnalysis, DNSRecordSet
from app.services.provider import ProviderResult


class FakeDNSService:
    async def resolve(self, domain: str) -> DNSAnalysis:
        return DNSAnalysis(target=domain, records={kind: DNSRecordSet(status="no_record") for kind in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")})
    async def reverse(self, ip: str) -> DNSRecordSet:
        return DNSRecordSet(status="ok", records=["dns.google"]) if ip == "8.8.8.8" else DNSRecordSet(status="no_record")


def unavailable(source: str) -> ProviderResult:
    return ProviderResult(source, "not_configured", message="API key not configured.")


class FakeThreatIntelligenceService:
    async def lookup_hash(self, value: str) -> dict[str, ProviderResult]:
        return {"virustotal": unavailable("virustotal"), "abuseipdb": ProviderResult("abuseipdb", "not_applicable", message="Not Applicable — AbuseIPDB is an IP reputation service."), "threatfox": unavailable("threatfox")}
    async def enrich_ip(self, analysis: object, port: int | None = None) -> object:
        return replace(analysis, enrichment="complete", threat_intelligence={name: unavailable(name) for name in ("virustotal", "abuseipdb", "threatfox")})
    async def enrich_domain(self, analysis: object) -> object:
        return replace(analysis, threat_intelligence={"virustotal": unavailable("virustotal"), "abuseipdb": ProviderResult("abuseipdb", "not_applicable", message="Not Applicable — AbuseIPDB is an IP reputation service."), "threatfox": unavailable("threatfox")})
    async def enrich_url(self, analysis: object) -> object:
        return await self.enrich_domain(analysis)


@pytest.fixture(autouse=True)
def dependencies() -> None:
    Base.metadata.drop_all(bind=engine); initialize_database()
    app.dependency_overrides[get_dns_service] = FakeDNSService
    app.dependency_overrides[get_threat_intelligence_service] = FakeThreatIntelligenceService
    yield
    app.dependency_overrides.clear()
