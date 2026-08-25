import pytest

from app.core.exceptions import ValidationError
from app.services.ioc_extractor import IOCExtractor


SAMPLE_LOG = """
2026-08-19 Failed login from 185.220.101.4
Connection to hxxps://evil[.]example/login from 2001:db8::5
Hash: d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2
SHA1: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Contact analyst@example.org and check update.microsoft.com
Repeated source 185.220.101.4
Internal peer 10.0.0.5
"""


def test_realistic_log_extracts_ordered_deduplicated_iocs() -> None:
    result = IOCExtractor().extract(SAMPLE_LOG)

    assert [(item.type, item.value, item.count) for item in result.iocs] == [
        ("ipv4", "185.220.101.4", 2),
        ("url", "https://evil.example/login", 1),
        ("ipv6", "2001:db8::5", 1),
        ("md5", "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2", 1),
        ("sha1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
        ("sha256", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
        ("email", "analyst@example.org", 1),
        ("domain", "update.microsoft.com", 1),
        ("ipv4", "10.0.0.5", 1),
    ]
    assert result.refanged is True
    assert result.iocs[-1].private_or_local is True
    assert result.iocs[-2].common_benign is True


def test_url_does_not_also_emit_its_bare_domain() -> None:
    result = IOCExtractor().extract("Observed https://evil.example/path")

    assert [(item.type, item.value) for item in result.iocs] == [
        ("url", "https://evil.example/path")
    ]


def test_hash_lengths_do_not_overlap() -> None:
    result = IOCExtractor().extract(
        "a" * 32 + " " + "b" * 40 + " " + "c" * 64
    )

    assert [item.type for item in result.iocs] == ["md5", "sha1", "sha256"]


def test_version_number_false_positive_is_excluded() -> None:
    result = IOCExtractor().extract("Version 1.2.3.4 connected to 8.8.8.8")

    assert [item.value for item in result.iocs] == ["8.8.8.8"]


def test_result_limit_is_explicit() -> None:
    result = IOCExtractor(max_iocs=2).extract(
        "one.example two.example three.example"
    )

    assert len(result.iocs) == 2
    assert result.truncated is True
    assert result.message is not None


def test_input_size_and_empty_input_are_rejected() -> None:
    extractor = IOCExtractor(max_input=10)

    with pytest.raises(ValidationError):
        extractor.extract("")
    with pytest.raises(ValidationError):
        extractor.extract("x" * 11)

