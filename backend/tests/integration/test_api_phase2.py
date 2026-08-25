from fastapi.testclient import TestClient

from app.main import app


def test_domain_endpoint_returns_per_record_statuses() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/domain",
            json={"target": "Example.COM"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == "example.com"
    assert set(body["dns"]["records"]) == {
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
        "SOA",
    }
    assert all(
        record_set["status"] == "no_record"
        for record_set in body["dns"]["records"].values()
    )


def test_url_endpoint_does_not_fetch_target() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/url",
            json={"url": "https://user@example.xyz:8443/login?a=1"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["host"] == "example.xyz"
    assert body["port"] == 8443
    assert {flag["code"] for flag in body["flags"]} == {
        "non_standard_port",
        "userinfo",
        "risky_tld",
    }
    assert body["tls"] is None
    assert body["redirect_chain"] is None
    assert body["disabled_features"]["tls"] == "disabled_in_v1"


def test_shared_target_endpoint_routes_all_supported_types() -> None:
    cases = [
        ("example.com", "domain"),
        ("hxxps://example[.]com/path", "url"),
    ]

    with TestClient(app) as client:
        for target, expected_type in cases:
            response = client.post("/api/analyze/target", json={"target": target})
            assert response.status_code == 200
            assert response.json()["target_type"] == expected_type


def test_invalid_domain_uses_shared_error_envelope() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/domain",
            json={"target": "not a domain"},
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_shared_target_endpoint_rejects_direct_ip_inquiries() -> None:
    with TestClient(app) as client:
        response = client.post("/api/analyze/target", json={"target": "8.8.8.8"})

    assert response.status_code == 422
    assert "disabled" in response.json()["error"]["message"].lower()
