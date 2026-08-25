import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.core.exceptions import ValidationError
from app.services.dns_service import DNSAnalysis, DNSService
from app.utils.patterns import refang


HTTP_SCHEMES = {"http", "https"}
COMMON_MULTI_LABEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "co.jp",
    "com.br",
}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "gq", "tk"}
MAX_URL_LENGTH = 4096


@dataclass(frozen=True, slots=True)
class URLFlag:
    code: str
    description: str


@dataclass(frozen=True, slots=True)
class URLAnalysis:
    input: str
    refanged: str
    scheme: str
    host: str
    port: int
    explicit_port: bool
    path: str
    query_parameters: list[dict[str, str]]
    fragment: str
    userinfo: str | None
    registered_domain: str | None
    subdomain: str | None
    host_is_ip: bool
    https: bool
    flags: list[URLFlag]
    dns: DNSAnalysis | None
    tls: None = None
    redirect_chain: None = None
    disabled_features: dict[str, str] = field(
        default_factory=lambda: {
            "tls": "disabled_in_v1",
            "redirect_chain": "disabled_in_v1",
        }
    )
    threat_intelligence: dict[str, Any] = field(default_factory=dict)
    risk_assessment: Any | None = None


@dataclass(frozen=True, slots=True)
class DomainAnalysis:
    input: str
    domain: str
    unicode_domain: str
    registered_domain: str
    subdomain: str | None
    punycode: bool
    dns: DNSAnalysis
    threat_intelligence: dict[str, Any] = field(default_factory=dict)
    risk_assessment: Any | None = None


class URLService:
    """Parse domains and URLs without fetching user-controlled web content."""

    def __init__(self, dns_service: DNSService | None = None) -> None:
        self.dns_service = dns_service or DNSService()

    async def analyze_domain(self, value: str) -> DomainAnalysis:
        raw_domain = refang(value.strip()).rstrip(".")
        ascii_domain = DNSService._normalize_domain(raw_domain)
        registered, subdomain = self._split_registered_domain(ascii_domain)
        try:
            unicode_domain = ascii_domain.encode("ascii").decode("idna")
        except UnicodeError:
            unicode_domain = raw_domain
        dns_result = await self.dns_service.resolve(ascii_domain)
        return DomainAnalysis(
            input=value.strip(),
            domain=ascii_domain,
            unicode_domain=unicode_domain,
            registered_domain=registered,
            subdomain=subdomain,
            punycode="xn--" in ascii_domain,
            dns=dns_result,
        )

    async def analyze_url(self, value: str) -> URLAnalysis:
        raw_value = value.strip()
        if not raw_value or len(raw_value) > MAX_URL_LENGTH:
            raise ValidationError(
                f"Enter a URL no longer than {MAX_URL_LENGTH} characters."
            )
        restored = refang(raw_value)
        parsed = urlparse(restored)
        if parsed.scheme.lower() not in HTTP_SCHEMES or not parsed.netloc:
            raise ValidationError("Enter a complete HTTP or HTTPS URL.")

        try:
            parsed_port = parsed.port
        except ValueError as error:
            raise ValidationError("The URL contains an invalid port.") from error

        raw_host = parsed.hostname
        if not raw_host:
            raise ValidationError("The URL must contain a host.")
        try:
            host = raw_host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as error:
            raise ValidationError("The URL contains an invalid host.") from error

        host_is_ip = self._is_ip(host)
        if not host_is_ip:
            host = DNSService._normalize_domain(host)
        scheme = parsed.scheme.lower()
        default_port = 443 if scheme == "https" else 80
        port = parsed_port or default_port
        explicit_port = parsed_port is not None
        registered, subdomain = (
            (None, None)
            if host_is_ip
            else self._split_registered_domain(host)
        )
        userinfo = self._userinfo(parsed.username, parsed.password)
        flags = self._flags(
            original=restored,
            host=host,
            host_is_ip=host_is_ip,
            port=port,
            default_port=default_port,
            explicit_port=explicit_port,
            subdomain=subdomain,
            userinfo=userinfo,
        )
        dns_result = None if host_is_ip else await self.dns_service.resolve(host)

        return URLAnalysis(
            input=raw_value,
            refanged=restored,
            scheme=scheme,
            host=host,
            port=port,
            explicit_port=explicit_port,
            path=parsed.path or "/",
            query_parameters=[
                {"name": name, "value": query_value}
                for name, query_value in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            fragment=parsed.fragment,
            userinfo=userinfo,
            registered_domain=registered,
            subdomain=subdomain,
            host_is_ip=host_is_ip,
            https=scheme == "https",
            flags=flags,
            dns=dns_result,
        )

    @staticmethod
    def detect_target_type(value: str) -> str:
        restored = refang(value.strip())
        try:
            ipaddress.ip_address(restored)
            return "ip"
        except ValueError:
            pass
        parsed = urlparse(restored)
        if parsed.scheme.lower() in HTTP_SCHEMES and parsed.netloc:
            return "url"
        DNSService._normalize_domain(restored)
        return "domain"

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _split_registered_domain(host: str) -> tuple[str, str | None]:
        labels = host.split(".")
        suffix_length = 2 if ".".join(labels[-2:]) in COMMON_MULTI_LABEL_SUFFIXES else 1
        registered_start = len(labels) - suffix_length - 1
        registered = ".".join(labels[registered_start:])
        subdomain = ".".join(labels[:registered_start]) or None
        return registered, subdomain

    @staticmethod
    def _userinfo(username: str | None, password: str | None) -> str | None:
        if username is None:
            return None
        return f"{username}:{password}" if password is not None else username

    @staticmethod
    def _flags(
        *,
        original: str,
        host: str,
        host_is_ip: bool,
        port: int,
        default_port: int,
        explicit_port: bool,
        subdomain: str | None,
        userinfo: str | None,
    ) -> list[URLFlag]:
        flags: list[URLFlag] = []
        if host_is_ip:
            flags.append(URLFlag("ip_as_host", "The URL uses an IP address as its host."))
        if explicit_port and port != default_port:
            flags.append(URLFlag("non_standard_port", f"The URL uses non-standard port {port}."))
        if userinfo is not None:
            flags.append(URLFlag("userinfo", "The URL authority contains user information."))
        if subdomain and len(subdomain.split(".")) > 3:
            flags.append(URLFlag("deep_subdomain", "The host has unusually deep subdomain nesting."))
        if "xn--" in host:
            flags.append(URLFlag("punycode", "The host contains an internationalized punycode label."))
        if host.split(".")[-1] in RISKY_TLDS:
            flags.append(URLFlag("risky_tld", "The host uses a TLD frequently seen in abusive campaigns."))
        if len(original) > 2048:
            flags.append(URLFlag("long_url", "The URL is unusually long."))
        return flags
