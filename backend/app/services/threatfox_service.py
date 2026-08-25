from typing import Any, Callable

from app.core.config import get_settings
from app.core.http_client import HTTPClient
from app.services.provider import ProviderResult, not_configured


THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxService:
    """Search current malware-associated indicators in ThreatFox."""

    def __init__(self, http_client: HTTPClient, auth_key: str | None = None) -> None:
        self.http_client = http_client
        self.auth_key = auth_key if auth_key is not None else get_settings().threatfox_api_key

    async def lookup_ioc(self, value: str) -> ProviderResult:
        return await self._query(
            {"query": "search_ioc", "search_term": value, "exact_match": True},
            value,
        )

    async def lookup_ip(self, value: str, port: int | None = None) -> ProviderResult:
        """Search an IP address including its `ip:port` indicator records.

        ThreatFox files botnet C&C addresses under the `ip:port` IOC type, so an
        exact search for a bare address reports no result even when the address
        is listed. A known port is queried exactly first; otherwise the address
        is searched broadly and the records are narrowed back to this exact
        address so a substring of a longer address cannot match.
        """

        if port is not None:
            exact = await self._query(
                {
                    "query": "search_ioc",
                    "search_term": f"{value}:{port}",
                    "exact_match": True,
                },
                value,
            )
            if exact.status == "ok" and (exact.data or {}).get("listed"):
                return exact
        return await self._query(
            {"query": "search_ioc", "search_term": value, "exact_match": False},
            value,
            match=lambda indicator: indicator == value
            or indicator.startswith(f"{value}:"),
        )

    async def lookup_hash(self, value: str) -> ProviderResult:
        return await self._query({"query": "search_hash", "hash": value}, value)

    async def _query(
        self,
        request: dict[str, Any],
        value: str,
        match: Callable[[str], bool] | None = None,
    ) -> ProviderResult:
        if not self.auth_key:
            return not_configured("threatfox")
        status, payload, message = await self.http_client.post_json(
            THREATFOX_API_URL,
            headers={"Auth-Key": self.auth_key},
            json=request,
        )
        if status != "ok" or payload is None:
            return ProviderResult("threatfox", status, message=message)
        query_status = payload.get("query_status")
        if query_status in {"no_result", "no_results", "ioc_not_found", "hash_not_found"}:
            return ProviderResult(
                "threatfox",
                "ok",
                data={"listed": False, "match_count": 0},
                external_url="https://threatfox.abuse.ch/browse/",
            )
        if query_status != "ok":
            return ProviderResult(
                "threatfox",
                "error",
                message=f"ThreatFox query failed: {query_status or 'unexpected response'}.",
            )
        records = payload.get("data")
        if not isinstance(records, list):
            records = []
        if match is not None:
            records = [
                item
                for item in records
                if isinstance(item, dict) and match(str(item.get("ioc") or ""))
            ]
        if not records:
            return ProviderResult(
                "threatfox",
                "ok",
                data={"listed": False, "match_count": 0},
                external_url="https://threatfox.abuse.ch/browse/",
            )
        malware = sorted({str(item.get("malware_printable") or item.get("malware")) for item in records if isinstance(item, dict) and (item.get("malware_printable") or item.get("malware"))})
        aliases = sorted({str(item.get("malware_alias")) for item in records if isinstance(item, dict) and item.get("malware_alias")})
        threat_types = sorted({str(item.get("threat_type_desc") or item.get("threat_type")) for item in records if isinstance(item, dict) and (item.get("threat_type_desc") or item.get("threat_type"))})
        ioc_types = sorted({str(item.get("ioc_type")) for item in records if isinstance(item, dict) and item.get("ioc_type")})
        tags = sorted({str(tag) for item in records if isinstance(item, dict) for tag in (item.get("tags") or [])})
        reporters = sorted({str(item.get("reporter")) for item in records if isinstance(item, dict) and item.get("reporter")})
        first_seen = sorted(str(item.get("first_seen")) for item in records if isinstance(item, dict) and item.get("first_seen"))
        last_seen = sorted(str(item.get("last_seen")) for item in records if isinstance(item, dict) and item.get("last_seen"))
        confidence = [int(item.get("confidence_level", 0)) for item in records if isinstance(item, dict)]
        return ProviderResult(
            "threatfox",
            "ok",
            data={
                "listed": bool(records),
                "match_count": len(records),
                "indicators": sorted({str(item.get("ioc")) for item in records if isinstance(item, dict) and item.get("ioc")}),
                "malware_families": malware,
                "malware_aliases": aliases,
                "threat_types": threat_types,
                "ioc_types": ioc_types,
                "maximum_confidence": max(confidence, default=0),
                "first_seen": first_seen[0] if first_seen else None,
                "last_seen": last_seen[-1] if last_seen else None,
                "tags": tags,
                "reporters": reporters,
            },
            external_url="https://threatfox.abuse.ch/browse/",
        )
