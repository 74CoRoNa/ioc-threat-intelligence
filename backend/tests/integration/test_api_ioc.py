from fastapi.testclient import TestClient

from app.main import app


def test_log_extraction_is_persisted_as_one_parent() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/log",
            json={"text": "Source 8.8.8.8 called hxxps://evil[.]example/path"},
        )
        assert response.status_code == 200
        body = response.json()
        detail = client.get(
            f"/api/investigations/{body['investigation_id']}"
        ).json()

    assert [item["type"] for item in body["iocs"]] == ["ipv4", "url"]
    assert len(detail["iocs"]) == 2
    assert detail["target_type"] == "log"


def test_bulk_analysis_isolates_invalid_ioc_failure() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/ioc/bulk",
            json={
                "iocs": [
                    {"value": "8.8.8.8"},
                    {"value": "not a valid indicator"},
                    {"value": "a" * 64},
                ]
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert [item["status"] for item in body["items"]] == ["ok", "error", "ok"]
    assert body["items"][0]["score"] is not None
    assert body["items"][1]["error"]
    assert body["investigation_id"] > 0


def test_hash_is_recognized_without_configured_vendor() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/ioc",
            json={"value": "b" * 64},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "sha256"
    assert body["status"] == "ok"
    providers = body["result"]["threat_intelligence"]
    assert providers["virustotal"]["status"] == "not_configured"
    assert providers["abuseipdb"]["status"] == "not_applicable"
    assert providers["threatfox"]["status"] == "not_configured"
