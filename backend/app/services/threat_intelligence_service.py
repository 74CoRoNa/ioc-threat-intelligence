import asyncio
from dataclasses import replace
from typing import Awaitable, Callable

from app.core.config import get_settings
from app.services.abuseipdb_service import AbuseIPDBService
from app.services.cache import TTLProviderCache
from app.services.ip_service import IPAnalysis
from app.services.provider import ProviderResult
from app.services.threatfox_service import ThreatFoxService
from app.services.urlhaus_service import URLhausService
from app.services.url_service import DomainAnalysis, URLAnalysis
from app.services.virustotal_service import VirusTotalService


class ThreatIntelligenceService:
    """Query the exact applicable providers concurrently and preserve failures."""

    def __init__(self, virustotal: VirusTotalService, abuseipdb: AbuseIPDBService, threatfox: ThreatFoxService, urlhaus: URLhausService, cache: TTLProviderCache) -> None:
        self.virustotal = virustotal
        self.abuseipdb = abuseipdb
        self.threatfox = threatfox
        self.urlhaus = urlhaus
        self.cache = cache

    async def enrich_ip(self, analysis: IPAnalysis, port: int | None = None) -> IPAnalysis:
        value = analysis.ip_address
        results = await asyncio.gather(
            self._cached(f"virustotal:ip:{value}", lambda: self.virustotal.lookup_ip(value)),
            self._cached(f"abuseipdb:ip:{value}", lambda: self.abuseipdb.lookup_ip(value)),
            self._cached(f"threatfox:ip:{value}:{port or ''}", lambda: self.threatfox.lookup_ip(value, port)),
            self._cached(f"urlhaus:host:{value}", lambda: self.urlhaus.lookup_host(value)),
        )
        return replace(analysis, enrichment="complete", threat_intelligence={item.source: item for item in results})

    async def enrich_domain(self, analysis: DomainAnalysis) -> DomainAnalysis:
        value = analysis.domain
        results = await asyncio.gather(
            self._cached(f"virustotal:domain:{value}", lambda: self.virustotal.lookup_domain(value)),
            self._cached(f"threatfox:ioc:{value}", lambda: self.threatfox.lookup_ioc(value)),
            self._cached(f"urlhaus:host:{value}", lambda: self.urlhaus.lookup_host(value)),
        )
        providers = {item.source: item for item in results}
        providers["abuseipdb"] = self.abuseipdb.not_applicable()
        return replace(analysis, threat_intelligence=providers)

    async def enrich_url(self, analysis: URLAnalysis) -> URLAnalysis:
        value = analysis.refanged
        results = await asyncio.gather(
            self._cached(f"virustotal:url:{value}", lambda: self.virustotal.lookup_url(value)),
            self._cached(f"threatfox:ioc:{value}", lambda: self.threatfox.lookup_ioc(value)),
            self._cached(f"urlhaus:url:{value}", lambda: self.urlhaus.lookup_url(value)),
        )
        providers = {item.source: item for item in results}
        providers["abuseipdb"] = self.abuseipdb.not_applicable()
        return replace(analysis, threat_intelligence=providers)

    async def lookup_hash(self, value: str) -> dict[str, ProviderResult]:
        results = await asyncio.gather(
            self._cached(f"virustotal:hash:{value}", lambda: self.virustotal.lookup_hash(value)),
            self._cached(f"threatfox:hash:{value}", lambda: self.threatfox.lookup_hash(value)),
            self._cached(f"urlhaus:hash:{value}", lambda: self.urlhaus.lookup_hash(value)),
        )
        providers = {item.source: item for item in results}
        providers["abuseipdb"] = self.abuseipdb.not_applicable()
        return providers

    async def _cached(self, key: str, loader: Callable[[], Awaitable[ProviderResult]]) -> ProviderResult:
        cached = await self.cache.get(key)
        if cached is not None:
            return cached
        try:
            async with asyncio.timeout(get_settings().analysis_timeout):
                result = await loader()
        except TimeoutError:
            result = ProviderResult(key.split(":", 1)[0], "timeout", message="Provider request exceeded the analysis time budget.")
        except Exception:
            result = ProviderResult(key.split(":", 1)[0], "error", message="Provider unavailable; remaining analysis continued.")
        await self.cache.set(key, result)
        return result
