from typing import Any

from app.core.config import get_settings
from app.core.http_client import HTTPClient
from app.services.provider import ProviderResult, not_configured


API_ROOT = "https://urlhaus-api.abuse.ch/v1"
NO_RESULT_STATUSES = {"no_results", "no_result"}
BROWSE_URL = "https://urlhaus.abuse.ch/browse/"


class URLhausService:
    """Search abuse.ch URLhaus for malware-distribution hosts, URLs, and payloads."""

    def __init__(self, http_client: HTTPClient, auth_key: str | None = None) -> None:
        self.http_client = http_client
        if auth_key is not None:
            self.auth_key = auth_key
        else:
            settings = get_settings()
            # URLhaus shares one abuse.ch Auth-Key with ThreatFox.
            self.auth_key = settings.urlhaus_api_key or settings.threatfox_api_key

    async def lookup_host(self, value: str) -> ProviderResult:
        """Look up a domain or IP address that may distribute malware."""

        return await self._query("host", {"host": value}, self._normalize_host)

    async def lookup_url(self, value: str) -> ProviderResult:
        return await self._query("url", {"url": value}, self._normalize_url)

    async def lookup_hash(self, value: str) -> ProviderResult:
        """Look up a payload by hash; URLhaus indexes MD5 and SHA-256 only."""

        length = len(value)
        if length == 32:
            payload = {"md5_hash": value}
        elif length == 64:
            payload = {"sha256_hash": value}
        else:
            return ProviderResult(
                "urlhaus",
                "not_applicable",
                message="Not Applicable — URLhaus indexes MD5 and SHA-256 payload hashes only.",
            )
        return await self._query("payload", payload, self._normalize_payload)

    async def _query(self, endpoint: str, data: dict[str, str], normalize) -> ProviderResult:
        if not self.auth_key:
            return not_configured("urlhaus")
        status, payload, message = await self.http_client.post_form_json(
            f"{API_ROOT}/{endpoint}/",
            headers={"Auth-Key": self.auth_key},
            data=data,
        )
        if status != "ok" or payload is None:
            return ProviderResult("urlhaus", status, message=message)
        query_status = payload.get("query_status")
        if query_status in NO_RESULT_STATUSES:
            return ProviderResult(
                "urlhaus",
                "ok",
                data={"listed": False, "url_count": 0},
                external_url=BROWSE_URL,
            )
        if query_status != "ok":
            return ProviderResult(
                "urlhaus",
                "error",
                message=f"URLhaus query failed: {query_status or 'unexpected response'}.",
            )
        data_out = normalize(payload)
        return ProviderResult(
            "urlhaus",
            "ok",
            data=data_out,
            external_url=payload.get("urlhaus_reference") or BROWSE_URL,
        )

    @staticmethod
    def _blacklists(payload: dict[str, Any]) -> list[str]:
        raw = payload.get("blacklists")
        if not isinstance(raw, dict):
            return []
        return sorted(
            name for name, state in raw.items()
            if isinstance(state, str) and state.lower() not in {"not listed", "not_listed"}
        )

    @classmethod
    def _normalize_host(cls, payload: dict[str, Any]) -> dict[str, Any]:
        urls = [item for item in (payload.get("urls") or []) if isinstance(item, dict)]
        online = [item for item in urls if str(item.get("url_status", "")).lower() == "online"]
        threats = sorted({str(item.get("threat")) for item in urls if item.get("threat")})
        tags = sorted({str(tag) for item in urls for tag in (item.get("tags") or [])})
        return {
            "listed": True,
            "url_count": cls._as_int(payload.get("url_count"), len(urls)),
            "online_url_count": len(online),
            "threat_types": threats,
            "first_seen": payload.get("firstseen"),
            "tags": tags,
            "blacklists": cls._blacklists(payload),
        }

    @classmethod
    def _normalize_url(cls, payload: dict[str, Any]) -> dict[str, Any]:
        payloads = [item for item in (payload.get("payloads") or []) if isinstance(item, dict)]
        signatures = sorted({str(item.get("signature")) for item in payloads if item.get("signature")})
        return {
            "listed": True,
            "url_count": 1,
            "url_status": payload.get("url_status"),
            "threat_types": [str(payload["threat"])] if payload.get("threat") else [],
            "first_seen": payload.get("date_added"),
            "last_online": payload.get("last_online"),
            "reporter": payload.get("reporter"),
            "tags": sorted({str(tag) for tag in (payload.get("tags") or [])}),
            "payload_count": len(payloads),
            "malware_signatures": signatures,
            "blacklists": cls._blacklists(payload),
        }

    @classmethod
    def _normalize_payload(cls, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "listed": True,
            "url_count": cls._as_int(payload.get("url_count"), 0),
            "file_type": payload.get("file_type"),
            "file_size": cls._as_int(payload.get("file_size"), 0) or None,
            "malware_signatures": [str(payload["signature"])] if payload.get("signature") else [],
            "first_seen": payload.get("firstseen"),
            "last_seen": payload.get("lastseen"),
        }

    @staticmethod
    def _as_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
