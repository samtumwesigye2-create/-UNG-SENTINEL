from fastapi.testclient import TestClient
from app import app

def test_health_and_system():
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    data = client.get("/v1/system").json()
    assert data["system_id"] == "UNG-SENTINEL"

def test_protected_routes_reject_missing_token():
    client = TestClient(app)
    assert client.get("/v1/operations/events").status_code == 401
