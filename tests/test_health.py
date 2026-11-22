from conftest import load_service_client


def test_api_health():
    client = load_service_client("api")
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "hospital-privacy-api"


def test_api_root():
    client = load_service_client("api")
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert "modules" in data
    assert set(data["modules"].keys()) == {"A", "B", "C"}


def test_siem_health():
    client = load_service_client("siem")
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "siem-collector"
