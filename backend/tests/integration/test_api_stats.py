from fastapi.testclient import TestClient

from app.main import app


def test_empty_dashboard_returns_zeros_and_empty_lists() -> None:
    with TestClient(app) as client:
        summary = client.get("/api/stats/summary").json()
        recent = client.get("/api/stats/recent").json()
        top = client.get("/api/stats/top-iocs").json()
        distribution = client.get("/api/stats/distribution").json()

    assert summary == {
        "total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
        "today": 0, "last_seven_days": 0,
    }
    assert recent == []
    assert top == []
    assert distribution["risk_buckets"] == {
        "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0,
    }
    assert len(distribution["time_series"]) == 7


def test_dashboard_aggregates_seeded_api_activity() -> None:
    with TestClient(app) as client:
        client.post("/api/analyze/domain", json={"target": "first.example"})
        client.post("/api/analyze/domain", json={"target": "example.com"})
        client.post("/api/analyze/log", json={"text": "Seen 8.8.8.8 twice 8.8.8.8"})
        summary = client.get("/api/stats/summary").json()
        recent = client.get("/api/stats/recent").json()
        top = client.get("/api/stats/top-iocs").json()

    assert summary["total"] == 3
    assert summary["low"] == 2
    assert summary["today"] == 3
    assert len(recent) == 3
    assert top[0]["value"] == "8.8.8.8"
    assert top[0]["occurrences"] == 1
