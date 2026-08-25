import httpx
import pytest
from app.core.http_client import HTTPClient
from app.services.abuseipdb_service import AbuseIPDBService
from app.services.threatfox_service import ThreatFoxService
from app.services.virustotal_service import VirusTotalService


@pytest.mark.asyncio
async def test_virustotal_normalizes_only_returned_fields() -> None:
    payload={"data":{"attributes":{"last_analysis_stats":{"malicious":3,"suspicious":1,"harmless":10,"undetected":6},"reputation":-4,"country":"GB"}}}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=payload))) as client:
        result=await VirusTotalService(HTTPClient(client),api_key="key").lookup_ip("1.1.1.1")
    assert result.status=="ok" and result.data["malicious"]==3 and result.data["total_engines"]==20
    assert "asn" not in result.data


@pytest.mark.asyncio
async def test_abuseipdb_normalizes_ip_report() -> None:
    payload={"data":{"abuseConfidenceScore":82,"totalReports":47,"countryCode":"US","isp":"Example","reports":[{"categories":[14,18]}]}}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=payload))) as client:
        result=await AbuseIPDBService(HTTPClient(client),api_key="key").lookup_ip("1.1.1.1")
    assert result.data["abuse_confidence_score"]==82
    assert result.data["abuse_categories"]==["Port Scan","Brute-Force"]


@pytest.mark.asyncio
async def test_threatfox_normalizes_real_fields() -> None:
    payload={"query_status":"ok","data":[{"ioc_type":"domain","malware_printable":"Test RAT","malware_alias":"Alias","threat_type_desc":"Botnet C2","confidence_level":90,"first_seen":"2026-01-01","last_seen":"2026-01-02","tags":["rat"],"reporter":"analyst"}]}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=payload))) as client:
        result=await ThreatFoxService(HTTPClient(client),auth_key="key").lookup_ioc("evil.test")
    assert result.data["listed"] is True and result.data["malware_families"]==["Test RAT"]


@pytest.mark.asyncio
async def test_missing_keys_never_call_network() -> None:
    transport=httpx.MockTransport(lambda _:(_ for _ in ()).throw(AssertionError("network called")))
    async with httpx.AsyncClient(transport=transport) as client:
        assert (await VirusTotalService(HTTPClient(client),api_key="").lookup_domain("example.com")).status=="not_configured"
        assert (await AbuseIPDBService(HTTPClient(client),api_key="").lookup_ip("1.1.1.1")).status=="not_configured"
        assert (await ThreatFoxService(HTTPClient(client),auth_key="").lookup_ioc("example.com")).status=="not_configured"


@pytest.mark.asyncio
async def test_threatfox_ip_lookup_finds_ip_port_records() -> None:
    """A bare address must still match the `ip:port` records ThreatFox files C&Cs under."""

    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        body = _json.loads(request.content)
        seen.append(body)
        if body.get("exact_match") is True and body.get("search_term") == "45.140.14.113":
            return httpx.Response(200, json={"query_status": "no_result"})
        return httpx.Response(200, json={"query_status": "ok", "data": [
            {"ioc": "45.140.14.113:443", "ioc_type": "ip:port", "malware_printable": "SectopRAT", "threat_type_desc": "Botnet C&C", "confidence_level": 100},
        ]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await ThreatFoxService(HTTPClient(client), auth_key="key").lookup_ip("45.140.14.113")

    assert result.data["listed"] is True
    assert result.data["indicators"] == ["45.140.14.113:443"]
    assert result.data["malware_families"] == ["SectopRAT"]
    assert seen[-1]["exact_match"] is False


@pytest.mark.asyncio
async def test_threatfox_ip_lookup_rejects_substring_addresses() -> None:
    """A broad search must not report a longer address that merely contains the query."""

    payload = {"query_status": "ok", "data": [
        {"ioc": "145.140.14.113:443", "ioc_type": "ip:port", "malware_printable": "Other"},
        {"ioc": "45.140.14.1130", "ioc_type": "ip:port", "malware_printable": "Other"},
    ]}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as client:
        result = await ThreatFoxService(HTTPClient(client), auth_key="key").lookup_ip("45.140.14.113")

    assert result.data["listed"] is False
    assert result.data["match_count"] == 0


@pytest.mark.asyncio
async def test_threatfox_known_port_is_queried_exactly_first() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"query_status": "ok", "data": [
        {"ioc": "45.140.14.113:443", "ioc_type": "ip:port", "malware_printable": "SectopRAT"},
    ]}))) as client:
        result = await ThreatFoxService(HTTPClient(client), auth_key="key").lookup_ip("45.140.14.113", 443)

    assert result.data["listed"] is True and result.data["match_count"] == 1


@pytest.mark.asyncio
async def test_urlhaus_normalizes_listed_host() -> None:
    from app.services.urlhaus_service import URLhausService

    payload = {"query_status": "ok", "urlhaus_reference": "https://urlhaus.abuse.ch/host/1.2.3.4/",
               "firstseen": "2026-08-16 10:55:05 UTC", "url_count": "3",
               "blacklists": {"spamhaus_dbl": "not listed", "surbl": "listed"},
               "urls": [
                   {"url_status": "online", "threat": "malware_download", "tags": ["elf", "Mozi"]},
                   {"url_status": "offline", "threat": "malware_download", "tags": ["elf"]},
               ]}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as client:
        result = await URLhausService(HTTPClient(client), auth_key="key").lookup_host("1.2.3.4")

    assert result.status == "ok" and result.data["listed"] is True
    assert result.data["url_count"] == 3 and result.data["online_url_count"] == 1
    assert result.data["threat_types"] == ["malware_download"]
    assert result.data["tags"] == ["Mozi", "elf"]
    assert result.data["blacklists"] == ["surbl"]
    assert result.external_url == "https://urlhaus.abuse.ch/host/1.2.3.4/"


@pytest.mark.asyncio
async def test_urlhaus_no_results_is_not_a_safety_claim() -> None:
    from app.services.urlhaus_service import URLhausService

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"query_status": "no_results"}))) as client:
        result = await URLhausService(HTTPClient(client), auth_key="key").lookup_host("example.com")

    assert result.status == "ok" and result.data == {"listed": False, "url_count": 0}


@pytest.mark.asyncio
async def test_urlhaus_rejects_unsupported_hash_length() -> None:
    from app.services.urlhaus_service import URLhausService

    transport = httpx.MockTransport(lambda _: (_ for _ in ()).throw(AssertionError("network called")))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await URLhausService(HTTPClient(client), auth_key="key").lookup_hash("a" * 40)

    assert result.status == "not_applicable"


@pytest.mark.asyncio
async def test_abuseipdb_reports_abusech_key_mixup_without_calling_network(monkeypatch) -> None:
    from app.core.config import Settings, get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("THREATFOX_API_KEY", "abusech-shared-key")
    get_settings.cache_clear()
    try:
        transport = httpx.MockTransport(lambda _: (_ for _ in ()).throw(AssertionError("network called")))
        async with httpx.AsyncClient(transport=transport) as client:
            result = await AbuseIPDBService(HTTPClient(client), api_key="abusech-shared-key").lookup_ip("1.1.1.1")
        assert result.status == "not_configured"
        assert "abuse.ch" in result.message and "abuseipdb.com" in result.message
    finally:
        get_settings.cache_clear()
