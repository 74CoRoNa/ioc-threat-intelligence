from typing import Any

import pytest

from app.core.exceptions import ValidationError
from app.services.dns_service import DNSAnalysis
from app.services.url_service import URLService
from app.utils.patterns import refang


class StubDNSService:
    def __init__(self) -> None:
        self.resolved: list[str] = []

    async def resolve(self, domain: str) -> DNSAnalysis:
        self.resolved.append(domain)
        return DNSAnalysis(target=domain, records={})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("hxxp://evil[.]example", "http://evil.example"),
        ("hxxps[:]//evil(.)example", "https://evil.example"),
        ("visit test{.}example", "visit test.example"),
        ("HXXPS://EXAMPLE[.]COM", "https://EXAMPLE.COM"),
    ],
)
def test_refang(value: str, expected: str) -> None:
    assert refang(value) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url", "attribute", "expected"),
    [
        ("http://example.com", "port", 80),
        ("https://example.com", "port", 443),
        ("https://example.com:8443/a", "explicit_port", True),
        ("https://user:pass@example.com/login", "userinfo", "user:pass"),
        ("https://192.0.2.4/login", "host_is_ip", True),
        ("https://[2001:db8::1]/", "host_is_ip", True),
        ("hxxps://evil[.]example/login", "refanged", "https://evil.example/login"),
        ("https://münich.example", "host", "xn--mnich-kva.example"),
        ("https://a.example.com", "subdomain", "a"),
        ("https://a.example.co.uk", "registered_domain", "example.co.uk"),
        ("https://example.com/a/b", "path", "/a/b"),
        ("https://example.com", "path", "/"),
        ("https://example.com/a#section", "fragment", "section"),
        ("HTTPS://EXAMPLE.COM/A", "scheme", "https"),
        ("https://example.com./", "host", "example.com"),
        ("https://example.com/%2Fadmin", "path", "/%2Fadmin"),
        ("http://example.com:80", "explicit_port", True),
        ("https://example.xyz", "registered_domain", "example.xyz"),
        ("https://a.b.c.d.example.com", "subdomain", "a.b.c.d"),
        ("https://xn--mnich-kva.example", "host", "xn--mnich-kva.example"),
    ],
)
async def test_url_parsing_table(
    url: str,
    attribute: str,
    expected: Any,
) -> None:
    result = await URLService(StubDNSService()).analyze_url(url)

    assert getattr(result, attribute) == expected
    assert result.tls is None
    assert result.redirect_chain is None
    assert result.disabled_features == {
        "tls": "disabled_in_v1",
        "redirect_chain": "disabled_in_v1",
    }


@pytest.mark.asyncio
async def test_query_parameters_preserve_duplicates_and_blank_values() -> None:
    result = await URLService(StubDNSService()).analyze_url(
        "https://example.com/?tag=one&tag=two&empty="
    )

    assert result.query_parameters == [
        {"name": "tag", "value": "one"},
        {"name": "tag", "value": "two"},
        {"name": "empty", "value": ""},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url", "expected_flag"),
    [
        ("https://192.0.2.4", "ip_as_host"),
        ("https://example.com:8443", "non_standard_port"),
        ("https://user@example.com", "userinfo"),
        ("https://a.b.c.d.example.com", "deep_subdomain"),
        ("https://xn--mnich-kva.example", "punycode"),
        ("https://example.xyz", "risky_tld"),
    ],
)
async def test_suspicious_url_flags(url: str, expected_flag: str) -> None:
    result = await URLService(StubDNSService()).analyze_url(url)

    assert expected_flag in {flag.code for flag in result.flags}


@pytest.mark.asyncio
async def test_ip_host_skips_dns_resolution() -> None:
    dns_service = StubDNSService()

    result = await URLService(dns_service).analyze_url("https://192.0.2.5/path")

    assert result.dns is None
    assert dns_service.resolved == []


@pytest.mark.asyncio
async def test_domain_normalization_and_dns() -> None:
    dns_service = StubDNSService()

    result = await URLService(dns_service).analyze_domain("MÜNICH[.]EXAMPLE.")

    assert result.domain == "xn--mnich-kva.example"
    assert result.unicode_domain == "münich.example"
    assert result.punycode is True
    assert dns_service.resolved == ["xn--mnich-kva.example"]


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("8.8.8.8", "ip"),
        ("example.com", "domain"),
        ("https://example.com/path", "url"),
        ("hxxps://example[.]com", "url"),
    ],
)
def test_target_type_detection(target: str, expected: str) -> None:
    assert URLService.detect_target_type(target) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    ["", "example.com/path", "ftp://example.com/file", "https://example.com:99999"],
)
async def test_invalid_urls(url: str) -> None:
    with pytest.raises(ValidationError):
        await URLService(StubDNSService()).analyze_url(url)

