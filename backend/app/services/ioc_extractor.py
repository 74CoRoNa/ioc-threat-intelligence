import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.core.exceptions import ValidationError
from app.utils.patterns import (
    DOMAIN_PATTERN,
    IPV4_PATTERN,
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
    URL_PATTERN,
    refang,
)


EMAIL_PATTERN = re.compile(
    r"(?i)(?<![\w.+-])[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w.-])"
)
IPV6_CANDIDATE_PATTERN = re.compile(r"(?<![\w:])[0-9a-fA-F:]{3,}(?![\w:])")
COMMON_BENIGN_DOMAINS = {
    "microsoft.com",
    "google.com",
    "windows.com",
    "apple.com",
    "cloudflare.com",
}
DEFAULT_MAX_INPUT = 200_000
DEFAULT_MAX_IOCS = 500


@dataclass(frozen=True, slots=True)
class ExtractedIOC:
    value: str
    type: str
    count: int
    private_or_local: bool
    common_benign: bool


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    iocs: list[ExtractedIOC]
    truncated: bool
    message: str | None
    refanged: bool


class IOCExtractor:
    """Extract common indicators while preserving their first-seen order."""

    def __init__(
        self,
        max_input: int = DEFAULT_MAX_INPUT,
        max_iocs: int = DEFAULT_MAX_IOCS,
    ) -> None:
        self.max_input = max_input
        self.max_iocs = max_iocs

    def extract(self, text: str) -> ExtractionResult:
        if not text.strip():
            raise ValidationError("Paste log text containing indicators to extract.")
        if len(text) > self.max_input:
            raise ValidationError(
                f"Log input must not exceed {self.max_input:,} characters."
            )
        restored = refang(text)
        candidates: list[tuple[int, int, str, str]] = []
        protected_spans: list[tuple[int, int]] = []

        for match in URL_PATTERN.finditer(restored):
            value = match.group().rstrip(".,;:!?)\"]}'")
            end = match.start() + len(value)
            candidates.append((match.start(), end, "url", value))
            protected_spans.append((match.start(), end))
        for match in EMAIL_PATTERN.finditer(restored):
            candidates.append((match.start(), match.end(), "email", match.group().lower()))
            protected_spans.append((match.start(), match.end()))

        hash_patterns = (
            ("sha256", SHA256_PATTERN),
            ("sha1", SHA1_PATTERN),
            ("md5", MD5_PATTERN),
        )
        hash_spans: list[tuple[int, int]] = []
        for ioc_type, pattern in hash_patterns:
            for match in pattern.finditer(restored):
                if self._overlaps(match.span(), hash_spans):
                    continue
                candidates.append((match.start(), match.end(), ioc_type, match.group().lower()))
                hash_spans.append(match.span())

        for match in IPV4_PATTERN.finditer(restored):
            if self._overlaps(match.span(), protected_spans):
                continue
            prefix = restored[max(0, match.start() - 10):match.start()].lower()
            if re.search(r"(?:version|\bv)\s*$", prefix):
                continue
            candidates.append((match.start(), match.end(), "ipv4", match.group()))

        for match in IPV6_CANDIDATE_PATTERN.finditer(restored):
            if ":" not in match.group() or self._overlaps(match.span(), protected_spans):
                continue
            try:
                address = ipaddress.IPv6Address(match.group())
            except ValueError:
                continue
            candidates.append((match.start(), match.end(), "ipv6", str(address)))

        for match in DOMAIN_PATTERN.finditer(restored):
            if self._overlaps(match.span(), protected_spans + hash_spans):
                continue
            candidates.append((match.start(), match.end(), "domain", match.group().lower()))

        candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))
        ordered: list[ExtractedIOC] = []
        positions: dict[tuple[str, str], int] = {}
        for _, _, ioc_type, value in candidates:
            normalized = self._normalize(value, ioc_type)
            key = (ioc_type, normalized)
            if key in positions:
                index = positions[key]
                existing = ordered[index]
                ordered[index] = ExtractedIOC(
                    value=existing.value,
                    type=existing.type,
                    count=existing.count + 1,
                    private_or_local=existing.private_or_local,
                    common_benign=existing.common_benign,
                )
                continue
            positions[key] = len(ordered)
            ordered.append(self._build_ioc(normalized, ioc_type))

        truncated = len(ordered) > self.max_iocs
        if truncated:
            ordered = ordered[: self.max_iocs]
        return ExtractionResult(
            iocs=ordered,
            truncated=truncated,
            message=(
                f"Results were limited to the first {self.max_iocs} unique indicators."
                if truncated
                else None
            ),
            refanged=restored != text,
        )

    @staticmethod
    def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
        return any(span[0] < end and span[1] > start for start, end in spans)

    @staticmethod
    def _normalize(value: str, ioc_type: str) -> str:
        if ioc_type == "url":
            parsed = urlparse(value)
            return parsed._replace(netloc=parsed.netloc.lower()).geturl()
        return value.lower()

    @staticmethod
    def _build_ioc(value: str, ioc_type: str) -> ExtractedIOC:
        private_or_local = False
        if ioc_type in {"ipv4", "ipv6"}:
            address = ipaddress.ip_address(value)
            private_or_local = (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
            )
        domain = value
        if ioc_type == "url":
            domain = urlparse(value).hostname or value
        if ioc_type == "email":
            domain = value.rsplit("@", maxsplit=1)[-1]
        common_benign = any(
            domain == benign or domain.endswith(f".{benign}")
            for benign in COMMON_BENIGN_DOMAINS
        )
        return ExtractedIOC(value, ioc_type, 1, private_or_local, common_benign)

