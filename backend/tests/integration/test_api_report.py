from fastapi.testclient import TestClient

from app.main import app
from app.services.report_service import DISCLAIMER


def test_report_contains_required_sections_and_disclaimer() -> None:
    with TestClient(app) as client:
        analysis = client.post("/api/analyze/domain", json={"target": "example.com"}).json()
        report = client.get(
            f"/api/investigations/{analysis['investigation_id']}/report"
        )

    assert report.status_code == 200
    body = report.json()
    assert body["target"] == "example.com"
    assert body["risk"]["score"] == analysis["risk_assessment"]["score"]
    assert body["recommendations"]
    assert body["sources_unavailable"]
    assert body["disclaimer"] == DISCLAIMER


def test_markdown_and_html_formats_are_readable_and_complete() -> None:
    with TestClient(app) as client:
        analysis = client.post(
            "/api/subnet/calculate", json={"ip_cidr": "192.168.1.10/24"}
        ).json()
        identifier = analysis["investigation_id"]
        markdown = client.get(f"/api/investigations/{identifier}/report?format=md")
        html = client.get(f"/api/investigations/{identifier}/report?format=html")

    assert markdown.status_code == 200
    assert "## Defensive Recommendations" in markdown.text
    assert "not a SIEM" in markdown.text
    assert html.status_code == 200
    assert "@media print" in html.text
    assert "not a SIEM" in html.text


def test_invalid_report_format_uses_validation_envelope() -> None:
    with TestClient(app) as client:
        response = client.get("/api/investigations/1/report?format=pdf")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
