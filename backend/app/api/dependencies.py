from app.core.config import get_settings
from app.core.http_client import HTTPClient
from app.services.cache import TTLProviderCache
from app.services.dns_service import DNSService
from app.services.abuseipdb_service import AbuseIPDBService
from app.services.threat_intelligence_service import ThreatIntelligenceService
from app.services.threatfox_service import ThreatFoxService
from app.services.urlhaus_service import URLhausService
from app.services.virustotal_service import VirusTotalService


_http_client = HTTPClient()
_provider_cache = TTLProviderCache(get_settings().cache_ttl)


def get_dns_service() -> DNSService:
    """Provide an independently replaceable DNS service for API requests."""

    return DNSService()


def get_threat_intelligence_service() -> ThreatIntelligenceService:
    """Provide the shared cached vendor-integration orchestrator."""

    return ThreatIntelligenceService(
        VirusTotalService(_http_client),
        AbuseIPDBService(_http_client),
        ThreatFoxService(_http_client),
        URLhausService(_http_client),
        _provider_cache,
    )
