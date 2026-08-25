from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from app.services.dns_service import DNSService


class FakeResolver:
    def __init__(self, answers: dict[str, object]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str, float]] = []

    async def resolve(
        self,
        target: str,
        record_type: str,
        *,
        lifetime: float,
        raise_on_no_answer: bool,
    ) -> object:
        self.calls.append((target, record_type, lifetime))
        result = self.answers.get(record_type, dns.resolver.NoAnswer())
        if isinstance(result, Exception):
            raise result
        return result


@pytest.mark.asyncio
async def test_resolve_formats_supported_record_types() -> None:
    resolver = FakeResolver(
        {
            "A": [SimpleNamespace(address="93.184.216.34")],
            "AAAA": [SimpleNamespace(address="2606:2800:220:1:248:1893:25c8:1946")],
            "MX": [SimpleNamespace(preference=10, exchange="mail.example.com.")],
            "NS": [SimpleNamespace(target="ns1.example.com.")],
            "TXT": [SimpleNamespace(strings=(b"v=spf1 ", b"-all"))],
            "CNAME": [SimpleNamespace(target="canonical.example.com.")],
            "SOA": [
                SimpleNamespace(
                    mname="ns1.example.com.",
                    rname="hostmaster.example.com.",
                    serial=2026081901,
                    refresh=3600,
                    retry=600,
                    expire=86400,
                    minimum=300,
                )
            ],
        }
    )

    result = await DNSService(resolver=resolver, timeout=1.5).resolve("Example.COM.")

    assert result.target == "example.com"
    assert result.records["A"].records == ["93.184.216.34"]
    assert result.records["MX"].records == [
        {"priority": 10, "exchange": "mail.example.com"}
    ]
    assert result.records["TXT"].records == ["v=spf1 -all"]
    assert result.records["SOA"].records[0]["serial"] == 2026081901
    assert len(resolver.calls) == 7
    assert all(call[2] == 1.5 for call in resolver.calls)


@pytest.mark.asyncio
async def test_one_record_timeout_does_not_hide_successful_records() -> None:
    resolver = FakeResolver(
        {
            "A": [SimpleNamespace(address="192.0.2.10")],
            "MX": dns.exception.Timeout(),
        }
    )

    result = await DNSService(resolver=resolver).resolve("example.com")

    assert result.records["A"].status == "ok"
    assert result.records["A"].records == ["192.0.2.10"]
    assert result.records["MX"].status == "timeout"
    assert result.records["NS"].status == "no_record"


@pytest.mark.asyncio
async def test_nxdomain_is_an_explicit_no_record_status() -> None:
    resolver = FakeResolver(
        {record_type: dns.resolver.NXDOMAIN() for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")}
    )

    result = await DNSService(resolver=resolver).resolve("missing.example")

    assert all(record.status == "no_record" for record in result.records.values())


@pytest.mark.asyncio
async def test_reverse_dns_present_and_absent() -> None:
    present = DNSService(
        resolver=FakeResolver({"PTR": [SimpleNamespace(target="dns.google.")]})
    )
    absent = DNSService(resolver=FakeResolver({"PTR": dns.resolver.NoAnswer()}))

    present_result = await present.reverse("8.8.8.8")
    absent_result = await absent.reverse("192.0.2.1")

    assert present_result.status == "ok"
    assert present_result.records == ["dns.google"]
    assert absent_result.status == "no_record"

