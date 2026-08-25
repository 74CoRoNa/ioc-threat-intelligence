import ipaddress
from dataclasses import dataclass, replace
from typing import Any

from app.services.dns_service import DNSService
from app.services.subnet_service import SubnetResult, SubnetService
from app.utils.validators import normalize_target, parse_interface


CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


@dataclass(frozen=True, slots=True)
class IPClassification:
    public: bool
    private: bool
    loopback: bool
    link_local: bool
    multicast: bool
    reserved: bool
    unspecified: bool
    cgnat: bool
    documentation: bool


@dataclass(frozen=True, slots=True)
class LegacyClass:
    value: str | None
    legacy_only: bool
    note: str


@dataclass(frozen=True, slots=True)
class IPAnalysis:
    input: str
    ip_address: str
    version: int
    classification: IPClassification
    legacy_class: LegacyClass | None
    network: SubnetResult
    reverse_dns: str | None
    country: str | None
    asn: str | None
    isp: str | None
    enrichment: str
    threat_intelligence: dict[str, Any] | None = None
    risk_assessment: Any | None = None


class IPService:
    """Analyze address classification and delegate CIDR math to SubnetService."""

    @staticmethod
    def analyze(value: str) -> IPAnalysis:
        normalized = normalize_target(value)
        interface = parse_interface(normalized)
        address = interface.ip

        classification = IPClassification(
            public=address.is_global,
            private=address.is_private,
            loopback=address.is_loopback,
            link_local=address.is_link_local,
            multicast=address.is_multicast,
            reserved=address.is_reserved,
            unspecified=address.is_unspecified,
            cgnat=IPService._is_cgnat(address),
            documentation=IPService._is_documentation(address),
        )

        return IPAnalysis(
            input=normalized,
            ip_address=str(address),
            version=address.version,
            classification=classification,
            legacy_class=IPService._legacy_class(address),
            network=SubnetService.calculate(normalized),
            reverse_dns=None,
            country=None,
            asn=None,
            isp=None,
            enrichment="pending",
            threat_intelligence={},
            risk_assessment=None,
        )

    @staticmethod
    async def analyze_with_dns(
        value: str,
        dns_service: DNSService,
    ) -> IPAnalysis:
        """Add fail-soft PTR data while preserving the offline core analysis."""

        analysis = IPService.analyze(value)
        ptr_result = await dns_service.reverse(analysis.ip_address)
        reverse_dns = (
            str(ptr_result.records[0])
            if ptr_result.status == "ok" and ptr_result.records
            else None
        )
        return replace(
            analysis,
            reverse_dns=reverse_dns,
            enrichment="dns_complete",
        )

    @staticmethod
    def _is_cgnat(
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        return isinstance(address, ipaddress.IPv4Address) and address in CGNAT_NETWORK

    @staticmethod
    def _is_documentation(
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        return any(
            address.version == network.version and address in network
            for network in DOCUMENTATION_NETWORKS
        )

    @staticmethod
    def _legacy_class(
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> LegacyClass | None:
        if not isinstance(address, ipaddress.IPv4Address):
            return None

        first_octet = int(str(address).split(".", maxsplit=1)[0])
        if first_octet <= 127:
            value = "A"
        elif first_octet <= 191:
            value = "B"
        elif first_octet <= 223:
            value = "C"
        else:
            value = None

        return LegacyClass(
            value=value,
            legacy_only=True,
            note="Legacy class information is descriptive only; CIDR drives all network calculations.",
        )
