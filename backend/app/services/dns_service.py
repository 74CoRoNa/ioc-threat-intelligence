import asyncio
from dataclasses import dataclass, field
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.reversename
import dns.resolver

from app.core.config import get_settings
from app.core.exceptions import ValidationError


DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


@dataclass(frozen=True, slots=True)
class DNSRecordSet:
    status: str
    records: list[str | dict[str, Any]] = field(default_factory=list)
    message: str | None = None


@dataclass(frozen=True, slots=True)
class DNSAnalysis:
    target: str
    records: dict[str, DNSRecordSet]


class DNSService:
    """Resolve DNS record types independently with fail-soft status reporting."""

    def __init__(
        self,
        resolver: Any | None = None,
        timeout: float | None = None,
    ) -> None:
        settings = get_settings()
        self.resolver = resolver or dns.asyncresolver.Resolver()
        self.timeout = timeout or settings.dns_timeout

    async def resolve(self, domain: str) -> DNSAnalysis:
        normalized = self._normalize_domain(domain)
        lookups = await asyncio.gather(
            *(self._resolve_type(normalized, record_type) for record_type in DNS_RECORD_TYPES)
        )
        return DNSAnalysis(
            target=normalized,
            records=dict(zip(DNS_RECORD_TYPES, lookups, strict=True)),
        )

    async def reverse(self, ip: str) -> DNSRecordSet:
        try:
            reverse_name = dns.reversename.from_address(ip)
        except ValueError as error:
            raise ValidationError("Enter a valid IP address for reverse DNS.") from error
        return await self._resolve_type(str(reverse_name), "PTR")

    async def _resolve_type(self, target: str, record_type: str) -> DNSRecordSet:
        try:
            answer = await self.resolver.resolve(
                target,
                record_type,
                lifetime=self.timeout,
                raise_on_no_answer=True,
            )
            return DNSRecordSet(
                status="ok",
                records=[self._format_record(record_type, record) for record in answer],
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return DNSRecordSet(
                status="no_record",
                message=f"No {record_type} record available.",
            )
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            return DNSRecordSet(
                status="timeout",
                message=f"The {record_type} lookup timed out.",
            )
        except dns.exception.DNSException:
            return DNSRecordSet(
                status="error",
                message=f"The {record_type} lookup failed.",
            )
        except Exception:
            return DNSRecordSet(
                status="error",
                message=f"The {record_type} lookup failed.",
            )

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        normalized = domain.strip().rstrip(".").lower()
        if not normalized or len(normalized) > 253:
            raise ValidationError("Enter a valid domain name.")
        try:
            ascii_domain = normalized.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValidationError("Enter a valid domain name.") from error
        labels = ascii_domain.split(".")
        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise ValidationError("Enter a valid domain name.")
        return ascii_domain

    @staticmethod
    def _format_record(record_type: str, record: Any) -> str | dict[str, Any]:
        if record_type in {"A", "AAAA"}:
            return str(getattr(record, "address", record))
        if record_type in {"NS", "CNAME", "PTR"}:
            return str(getattr(record, "target", record)).rstrip(".")
        if record_type == "MX":
            return {
                "priority": int(record.preference),
                "exchange": str(record.exchange).rstrip("."),
            }
        if record_type == "TXT":
            strings = getattr(record, "strings", None)
            if strings is not None:
                return "".join(
                    item.decode("utf-8", errors="replace")
                    if isinstance(item, bytes)
                    else str(item)
                    for item in strings
                )
            return str(record).strip('"')
        if record_type == "SOA":
            return {
                "mname": str(record.mname).rstrip("."),
                "rname": str(record.rname).rstrip("."),
                "serial": int(record.serial),
                "refresh": int(record.refresh),
                "retry": int(record.retry),
                "expire": int(record.expire),
                "minimum": int(record.minimum),
            }
        return str(record).rstrip(".")

