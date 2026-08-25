from typing import Any

from app.core.config import get_settings
from app.core.http_client import HTTPClient
from app.services.provider import ProviderResult, not_configured


CATEGORIES = {3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"}


class AbuseIPDBService:
    """Retrieve AbuseIPDB reputation only for IP address IOCs."""

    def __init__(self, client: HTTPClient, api_key: str | None = None) -> None:
        self.client = client
        self.api_key = api_key if api_key is not None else get_settings().abuseipdb_api_key

    async def lookup_ip(self, value: str) -> ProviderResult:
        if not self.api_key:
            return not_configured("abuseipdb")
        if self._is_abusech_key():
            return ProviderResult(
                "abuseipdb",
                "not_configured",
                message=(
                    "The configured key belongs to abuse.ch, which is a different "
                    "service from AbuseIPDB. Register at abuseipdb.com for a key, "
                    "or leave this blank."
                ),
            )
        status, payload, message = await self.client.get_json(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": "true"},
        )
        if status != "ok" or payload is None:
            return ProviderResult("abuseipdb", status, message=message)
        raw = payload.get("data")
        if not isinstance(raw, dict):
            return ProviderResult("abuseipdb", "error", message="AbuseIPDB returned an unexpected response.")
        mapping = {"abuseConfidenceScore": "abuse_confidence_score", "totalReports": "total_reports", "lastReportedAt": "last_report", "countryCode": "country", "isp": "isp", "domain": "domain", "usageType": "usage_type"}
        data: dict[str, Any] = {target: raw[source] for source, target in mapping.items() if raw.get(source) is not None}
        category_ids = {category for report in raw.get("reports", []) if isinstance(report, dict) for category in report.get("categories", []) if isinstance(category, int)}
        if category_ids:
            data["abuse_categories"] = [CATEGORIES.get(category, f"Category {category}") for category in sorted(category_ids)]
        return ProviderResult("abuseipdb", "ok", data=data, external_url=f"https://www.abuseipdb.com/check/{value}")

    def _is_abusech_key(self) -> bool:
        """Detect an abuse.ch Auth-Key pasted into the AbuseIPDB slot.

        The two services have similar names but no relationship, and AbuseIPDB
        answers such a key with HTTP 401. Reporting the mix-up directly is more
        useful to an analyst than a generic credential rejection.
        """

        settings = get_settings()
        abusech_keys = {
            key for key in (settings.threatfox_api_key, settings.urlhaus_api_key) if key
        }
        return self.api_key in abusech_keys

    @staticmethod
    def not_applicable() -> ProviderResult:
        return ProviderResult("abuseipdb", "not_applicable", message="Not Applicable — AbuseIPDB is an IP reputation service.")
