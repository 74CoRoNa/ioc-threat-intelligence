import base64
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from app.core.config import get_settings
from app.core.http_client import HTTPClient
from app.services.provider import ProviderResult, not_configured


API_ROOT = "https://www.virustotal.com/api/v3"


class VirusTotalService:
    """Retrieve existing VirusTotal reports without submitting or scanning targets."""

    def __init__(self, client: HTTPClient, api_key: str | None = None) -> None:
        self.client = client
        self.api_key = api_key if api_key is not None else get_settings().virustotal_api_key

    async def lookup_ip(self, value: str) -> ProviderResult:
        return await self._lookup("ip_addresses", value, "ip-address")

    async def lookup_domain(self, value: str) -> ProviderResult:
        return await self._lookup("domains", value, "domain")

    async def lookup_url(self, value: str) -> ProviderResult:
        identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return await self._lookup("urls", identifier, "url")

    async def lookup_hash(self, value: str) -> ProviderResult:
        return await self._lookup("files", value, "file")

    async def _lookup(self, collection: str, identifier: str, gui_type: str) -> ProviderResult:
        if not self.api_key:
            return not_configured("virustotal")
        status, payload, message = await self.client.get_json(
            f"{API_ROOT}/{collection}/{quote(identifier, safe='')}",
            headers={"x-apikey": self.api_key},
        )
        if status != "ok" or payload is None:
            return ProviderResult("virustotal", status, message=message)
        attributes = payload.get("data", {}).get("attributes")
        if not isinstance(attributes, dict):
            return ProviderResult("virustotal", "error", message="VirusTotal returned an unexpected response.")
        stats = attributes.get("last_analysis_stats")
        data: dict[str, Any] = {}
        if isinstance(stats, dict):
            for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
                if key in stats:
                    data[key] = stats[key]
            data["total_engines"] = sum(value for value in stats.values() if isinstance(value, int))
        mapping = {
            "reputation": "reputation", "country": "country", "asn": "asn",
            "as_owner": "owner_isp", "network": "network", "registrar": "registrar",
            "title": "title", "last_final_url": "final_url", "size": "file_size",
            "type_description": "file_type", "meaningful_name": "file_name",
        }
        for source, target in mapping.items():
            if attributes.get(source) is not None:
                data[target] = attributes[source]
        timestamp = attributes.get("last_analysis_date")
        if isinstance(timestamp, (int, float)):
            data["last_analysis"] = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        return ProviderResult(
            "virustotal", "ok", data=data,
            external_url=f"https://www.virustotal.com/gui/{gui_type}/{quote(identifier, safe='')}",
        )
