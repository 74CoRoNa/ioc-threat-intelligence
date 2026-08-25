import pytest

from app.core.exceptions import ValidationError
from app.services.subnet_service import SubnetService


@pytest.mark.parametrize(
    (
        "prefix",
        "network",
        "first_host",
        "last_host",
        "broadcast",
        "total",
        "usable",
    ),
    [
        (8, "192.0.0.0", "192.0.0.1", "192.255.255.254", "192.255.255.255", 16_777_216, 16_777_214),
        (16, "192.168.0.0", "192.168.0.1", "192.168.255.254", "192.168.255.255", 65_536, 65_534),
        (24, "192.168.10.0", "192.168.10.1", "192.168.10.254", "192.168.10.255", 256, 254),
        (25, "192.168.10.0", "192.168.10.1", "192.168.10.126", "192.168.10.127", 128, 126),
        (26, "192.168.10.0", "192.168.10.1", "192.168.10.62", "192.168.10.63", 64, 62),
        (27, "192.168.10.0", "192.168.10.1", "192.168.10.30", "192.168.10.31", 32, 30),
        (28, "192.168.10.16", "192.168.10.17", "192.168.10.30", "192.168.10.31", 16, 14),
        (29, "192.168.10.24", "192.168.10.25", "192.168.10.30", "192.168.10.31", 8, 6),
        (30, "192.168.10.24", "192.168.10.25", "192.168.10.26", "192.168.10.27", 4, 2),
        (31, "192.168.10.24", "192.168.10.24", "192.168.10.25", None, 2, 2),
        (32, "192.168.10.25", "192.168.10.25", "192.168.10.25", None, 1, 1),
    ],
)
def test_ipv4_prefix_boundaries(
    prefix: int,
    network: str,
    first_host: str,
    last_host: str,
    broadcast: str | None,
    total: int,
    usable: int,
) -> None:
    result = SubnetService.calculate(f"192.168.10.25/{prefix}")

    assert result.network == network
    assert result.first_host == first_host
    assert result.last_host == last_host
    assert result.broadcast == broadcast
    assert result.total_addresses == total
    assert result.usable_hosts == usable


@pytest.mark.parametrize(
    ("target", "mask", "wildcard"),
    [
        ("10.20.30.40/8", "255.0.0.0", "0.255.255.255"),
        ("172.20.30.40/16", "255.255.0.0", "0.0.255.255"),
        ("192.168.1.99/26", "255.255.255.192", "0.0.0.63"),
    ],
)
def test_masks_against_known_values(
    target: str,
    mask: str,
    wildcard: str,
) -> None:
    result = SubnetService.calculate(target)

    assert result.subnet_mask == mask
    assert result.wildcard_mask == wildcard


def test_bare_ipv4_assumes_host_prefix() -> None:
    result = SubnetService.calculate("8.8.8.8")

    assert result.cidr == "8.8.8.8/32"
    assert result.assumed_prefix is True


def test_ipv6_has_no_fabricated_broadcast_or_wildcard() -> None:
    result = SubnetService.calculate("2001:db8::1/126")

    assert result.version == 6
    assert result.network == "2001:db8::"
    assert result.first_host == "2001:db8::"
    assert result.last_host == "2001:db8::3"
    assert result.total_addresses == 4
    assert result.usable_hosts == 4
    assert result.broadcast is None
    assert result.wildcard_mask is None


@pytest.mark.parametrize(
    "target",
    ["999.1.1.1", "192.168.1.0/33", "abc", "", "   "],
)
def test_invalid_network_input(target: str) -> None:
    with pytest.raises(ValidationError):
        SubnetService.calculate(target)

