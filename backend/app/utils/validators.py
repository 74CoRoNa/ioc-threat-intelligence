import ipaddress

from app.core.exceptions import ValidationError


MAX_TARGET_LENGTH = 256


def normalize_target(value: str) -> str:
    """Normalize and bound a user-supplied analysis target."""

    normalized = value.strip().lower()
    if not normalized:
        raise ValidationError("An IP address or network is required.")
    if len(normalized) > MAX_TARGET_LENGTH:
        raise ValidationError(
            f"The target must not exceed {MAX_TARGET_LENGTH} characters."
        )
    return normalized


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse one IPv4 or IPv6 address and return a clear application error."""

    normalized = normalize_target(value)
    try:
        return ipaddress.ip_address(normalized)
    except ValueError as error:
        raise ValidationError(
            "Enter a valid IPv4 or IPv6 address.",
            details={"target": normalized},
        ) from error


def parse_interface(
    value: str,
) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface:
    """Parse an IP with an optional prefix, defaulting to a host prefix."""

    normalized = normalize_target(value)
    try:
        return ipaddress.ip_interface(normalized)
    except ValueError as error:
        raise ValidationError(
            "Enter a valid IP address with an optional CIDR prefix.",
            details={"target": normalized},
        ) from error


def parse_network(
    value: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a network without requiring the supplied IP to be its network ID."""

    return parse_interface(value).network

