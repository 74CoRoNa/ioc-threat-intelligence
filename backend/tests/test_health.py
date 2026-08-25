from fastapi.testclient import TestClient
import pytest

from app.main import app


def test_health_reports_unconfigured_integrations() -> None:
    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": "0.1.0",
        "integrations": {
            "virustotal": False,
            "abuseipdb": False,
            "threatfox": False,
            "urlhaus": False,
            "ai_analyst": False,
        },
    }


def test_frontend_is_served() -> None:
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "IOC Threat Intelligence" in response.text


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/domain.html",
        "/ioc.html",
        "/history.html",
        "/dashboard.html",
        "/report.html",
    ],
)
def test_all_frontend_pages_are_served(path: str) -> None:
    with TestClient(app) as client:
        response = client.get(path)

    assert response.status_code == 200
    assert "html" in response.headers["content-type"]
