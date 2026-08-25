import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def test_standalone_ip_inquiry_is_removed(client: TestClient) -> None:
    response = client.post("/api/analyze/ip", json={"ip": "8.8.8.8/24"})

    assert response.status_code in {404, 405}


def test_subnet_calculation_response_shape(client: TestClient) -> None:
    response = client.post(
        "/api/subnet/calculate",
        json={"ip_cidr": "192.168.10.25/28"},
    )

    assert response.status_code == 200
    body = response.json()
    investigation_id = body.pop("investigation_id")
    assert investigation_id > 0
    assert body == {
        "input": "192.168.10.25/28",
        "ip_address": "192.168.10.25",
        "version": 4,
        "cidr": "192.168.10.16/28",
        "prefix_length": 28,
        "network": "192.168.10.16",
        "subnet_mask": "255.255.255.240",
        "wildcard_mask": "0.0.0.15",
        "first_host": "192.168.10.17",
        "last_host": "192.168.10.30",
        "broadcast": "192.168.10.31",
        "total_addresses": 16,
        "usable_hosts": 14,
        "assumed_prefix": False,
    }


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/subnet/calculate", {"ip_cidr": "192.168.1.1/99"}),
        ("/api/subnet/calculate", {}),
    ],
)
def test_bad_input_uses_error_envelope(
    client: TestClient,
    path: str,
    payload: dict[str, str],
) -> None:
    response = client.post(path, json=payload)

    assert response.status_code == 422
    body = response.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["message"]
    assert "details" in body["error"]
