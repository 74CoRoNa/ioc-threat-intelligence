import pytest

from app.core.exceptions import ValidationError
from app.services.ip_service import IPService


@pytest.mark.parametrize(
    ("target", "private", "public", "flag"),
    [
        ("10.1.2.3", True, False, None),
        ("172.16.0.1", True, False, None),
        ("172.31.255.254", True, False, None),
        ("192.168.1.1", True, False, None),
        ("127.0.0.1", True, False, "loopback"),
        ("169.254.1.1", True, False, "link_local"),
        ("8.8.8.8", False, True, None),
    ],
)
def test_private_public_and_special_classification(
    target: str,
    private: bool,
    public: bool,
    flag: str | None,
) -> None:
    result = IPService.analyze(target)

    assert result.classification.private is private
    assert result.classification.public is public
    if flag:
        assert getattr(result.classification, flag) is True


def test_cgnat_and_documentation_ranges_are_explicit() -> None:
    cgnat = IPService.analyze("100.64.12.1")
    documentation = IPService.analyze("203.0.113.10")

    assert cgnat.classification.cgnat is True
    assert cgnat.classification.public is False
    assert documentation.classification.documentation is True


@pytest.mark.parametrize(
    ("target", "expected_class"),
    [
        ("10.0.0.1", "A"),
        ("172.16.0.1", "B"),
        ("192.168.0.1", "C"),
        ("240.0.0.1", None),
    ],
)
def test_legacy_class_is_descriptive_only(
    target: str,
    expected_class: str | None,
) -> None:
    result = IPService.analyze(target)

    assert result.legacy_class is not None
    assert result.legacy_class.value == expected_class
    assert result.legacy_class.legacy_only is True
    assert result.network.cidr.endswith("/32")


@pytest.mark.parametrize(
    ("target", "flag"),
    [
        ("2001:db8::1/32", "documentation"),
        ("::1", "loopback"),
        ("fe80::1/10", "link_local"),
    ],
)
def test_ipv6_classification(target: str, flag: str) -> None:
    result = IPService.analyze(target)

    assert result.version == 6
    assert result.legacy_class is None
    assert getattr(result.classification, flag) is True
    assert result.network.broadcast is None


def test_supplied_prefix_drives_network_math() -> None:
    result = IPService.analyze("192.168.10.25/24")

    assert result.ip_address == "192.168.10.25"
    assert result.network.network == "192.168.10.0"
    assert result.network.broadcast == "192.168.10.255"


@pytest.mark.parametrize("target", ["999.1.1.1", "abc", ""])
def test_invalid_ip_input(target: str) -> None:
    with pytest.raises(ValidationError):
        IPService.analyze(target)

