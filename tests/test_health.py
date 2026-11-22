import importlib.util
from pathlib import Path
import sys

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


def _load_app(service_dir: str):
    service_path = str(ROOT / "services" / service_dir)
    if service_path not in sys.path:
        sys.path.insert(0, service_path)
    # Limpiar posibles colisiones de módulo 'app' entre servicios
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            del sys.modules[mod]
    spec = importlib.util.spec_from_file_location(
        f"{service_dir}_app_main", ROOT / "services" / service_dir / "app" / "main.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def test_api_health():
    client = TestClient(_load_app("api"))
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "hospital-privacy-api"


def test_api_root():
    client = TestClient(_load_app("api"))
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert "modules" in data
    assert set(data["modules"].keys()) == {"A", "B", "C"}


def test_siem_health():
    client = TestClient(_load_app("siem"))
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "siem-collector"
