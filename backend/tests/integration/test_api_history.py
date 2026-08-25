from fastapi.testclient import TestClient

from app.main import app


def test_analyze_list_reopen_and_delete_round_trip() -> None:
    with TestClient(app) as client:
        analysis = client.post(
            "/api/subnet/calculate",
            json={"ip_cidr": "192.168.50.25/24"},
        )
        assert analysis.status_code == 200
        investigation_id = analysis.json()["investigation_id"]

        history = client.get("/api/investigations")
        assert history.status_code == 200
        history_body = history.json()
        assert history_body["total"] == 1
        assert history_body["items"][0]["id"] == investigation_id
        assert history_body["items"][0]["target_type"] == "subnet"

        detail = client.get(f"/api/investigations/{investigation_id}")
        assert detail.status_code == 200
        assert detail.json()["raw_result"]["network"] == "192.168.50.0"

        deleted = client.delete(f"/api/investigations/{investigation_id}")
        assert deleted.status_code == 200
        assert deleted.json() == {
            "deleted": True,
            "investigation_id": investigation_id,
        }
        assert client.get(f"/api/investigations/{investigation_id}").status_code == 404


def test_history_query_validation_uses_error_envelope() -> None:
    with TestClient(app) as client:
        response = client.get("/api/investigations?page=0&page_size=500")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_provider_statuses_are_persisted_even_when_unavailable() -> None:
    with TestClient(app) as client:
        analysis = client.post("/api/analyze/domain", json={"target": "example.com"})
        investigation_id = analysis.json()["investigation_id"]
        detail = client.get(f"/api/investigations/{investigation_id}").json()

    statuses = {item["source"]: item["status"] for item in detail["threat_results"]}
    assert statuses == {
        "virustotal": "not_configured",
        "abuseipdb": "not_applicable",
        "threatfox": "not_configured",
    }
