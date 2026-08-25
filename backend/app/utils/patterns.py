import ipaddress
import re


IPV4_PATTERN = re.compile(
    r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"
)
IPV6_PATTERN = re.compile(
    r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"
)
DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])"
)
URL_PATTERN = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"']+")
MD5_PATTERN = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])")
SHA1_PATTERN = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])")
SHA256_PATTERN = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])")

_DEFANGED_DOT_PATTERN = re.compile(r"\[\.\]|\(\.\)|\{\.\}")
_DEFANGED_COLON_PATTERN = re.compile(r"\[:\]|\(:\)|\{:}")
_DEFANGED_SCHEME_PATTERN = re.compile(r"(?i)\bhxxp(s?)\b")


def refang(value: str) -> str:
    """Convert common defensive IOC notation back to a parseable value."""

    restored = _DEFANGED_DOT_PATTERN.sub(".", value)
    restored = _DEFANGED_COLON_PATTERN.sub(":", restored)
    return _DEFANGED_SCHEME_PATTERN.sub(
        lambda match: "https" if match.group(1) else "http",
        restored,
    )



_BRACKETED_HOST_PORT_PATTERN = re.compile(r"^\[(?P<host>[0-9A-Fa-f:.]+)\]:(?P<port>\d{1,5})$")
_IPV4_HOST_PORT_PATTERN = re.compile(r"^(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,5})$")


def split_host_port(value: str) -> tuple[str, int | None]:
    """Separate a trailing transport port from an IP address literal.

    Firewall, proxy, and netflow records commonly present an endpoint as
    `address:port`. Only literal IP addresses are split, so an IPv6 address
    and a domain carrying a colon are both returned unchanged.
    """

    candidate = value.strip()
    for pattern in (_BRACKETED_HOST_PORT_PATTERN, _IPV4_HOST_PORT_PATTERN):
        match = pattern.fullmatch(candidate)
        if match is None:
            continue
        port = int(match.group("port"))
        if not 0 < port <= 65_535:
            continue
        try:
            ipaddress.ip_address(match.group("host"))
        except ValueError:
            continue
        return match.group("host"), port
    return candidate, None
