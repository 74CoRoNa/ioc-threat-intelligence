import sys
from pathlib import Path

from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.main import app


def main() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/ioc",
            json={"value": "44d88612fea8a8f36de82e1278abb02f"},
        )
        response.raise_for_status()
        body = response.json()
    result = body["result"]
    risk = result["risk_assessment"]
    print(f"IOC_TYPE={body['type']}")
    for name in ("virustotal", "abuseipdb", "threatfox"):
        print(f"{name.upper()}_STATUS={result['threat_intelligence'][name]['status']}")
    print(f"RISK_SCORE={risk['score']}")
    print(f"SEVERITY={risk['severity']}")
    print(f"VERDICT={risk['verdict']}")
    print(f"INVESTIGATION_ID={result['investigation_id']}")


if __name__ == "__main__":
    main()
